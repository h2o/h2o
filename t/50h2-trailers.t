use strict;
use warnings;
use utf8;
use File::Temp qw(tempfile);
use Path::Tiny;
use Time::HiRes qw(sleep);
use Test::More;
use t::Util;

sub debug_display {
    my ($kind, $err, $out) = @_;
    if ($err) {
        diag "--- $kind stderr:";
        diag $err;
    }
    diag "--- $kind stdout:";
    diag $out;
}

sub spawn_h2get_backend {
    my ($backend_port) = empty_ports(1, { host => '0.0.0.0' });
    my $backend = spawn_forked(sub {
        my $code = <<"EOC";
        BINARY_DIR = '@{[ bindir() ]}';
        @{[ path(ASSETS_DIR, 'h2get-server.rb')->slurp ]}

        data_received = false
        run_server(listen: ARGV[0]) do |f, conn|
          p ['backend', f.stream_id, f.type, f.flags]
          if f.type == 'HEADERS'
            if data_received
              # trailers
              puts "BACKEND RECEIVED TRAILERS FROM CLIENT"
              puts f.to_s
            else
              # headers
              res = { ":status" => "200", "content-length" => "5" }
              conn.send_headers(res, f.stream_id, END_HEADERS)
              conn.send_data(f.stream_id, 0, "hello")
              conn.send_headers({ "x-backend-trailer" => "bar" }, f.stream_id, END_HEADERS | END_STREAM)
            end
          elsif f.type == 'DATA'
            data_received = true
          end
        end
EOC
        my ($scriptfh, $scriptfn) = tempfile(UNLINK => 1);
        print $scriptfh $code;
        close($scriptfh);
        exec(bindir() . '/h2get_bin/h2get', $scriptfn, "127.0.0.1:$backend_port");
    }, +{ on_exit => sub {
        my ($out, $err) = @_;
        debug_display('backend', $err, $out);
        # TODO: check if request trailers to be forwarded
        # like $out, qr/BACKEND RECEIVED TRAILERS FROM CLIENT/;
    } });

    $backend->{tls_port} = $backend_port;
    return $backend;
}

my $h2get_client_script = <<"EOS";
    req = { ":method" => "POST", ":authority" => authority, ":scheme" => "https", ":path" => "/", "content-length" => "10" }
    h2g.send_headers(req, 1, END_HEADERS)
    h2g.send_data(1, 0, "a" * 10)
    h2g.send_headers({ "x-client-trailer" => "foo" }, 1, END_STREAM | END_HEADERS)

    data_received = false
    while f = h2g.read(1000) do
      p ['client', f.stream_id, f.type, f.flags]
      if f.type == "DATA"
        data_received = true
        if f.len > 0
          h2g.send_window_update(0, f.len)
          h2g.send_window_update(f.stream_id, f.len)
        end
      elsif f.type == "HEADERS"
        if data_received
          # trailers
          puts "CLIENT RECEIVED TRAILERS FROM BACKEND"
          puts f.to_s
        end
      end
    end
EOS

subtest 'connect directly to backend' => sub {
    my $backend = spawn_h2get_backend();
    sleep 0.5;
    my ($err, $out) = run_with_h2get_simple($backend, $h2get_client_script);
    debug_display('client', $err, $out);
    like $out, qr/CLIENT RECEIVED TRAILERS FROM BACKEND/;
};

subtest 'normal h2o exists between client and backend' => sub {
    my $backend = spawn_h2get_backend();
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.ssl.verify-peer: OFF
        proxy.reverse.url: https://127.0.0.1:$backend->{tls_port}
EOT
    sleep 0.5;
    my ($err, $out) = run_with_h2get_simple($server, $h2get_client_script);
    debug_display('client', $err, $out);
    like $out, qr/CLIENT RECEIVED TRAILERS FROM BACKEND/;
};

subtest 'nghttp2 client and backend' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    plan skip_all => 'nghttpd not found'
        unless prog_exists('nghttpd');

    my ($backend_port) = empty_ports(1, { host => '0.0.0.0' });
    my $backend = spawn_forked(sub {
        exec('nghttpd', '-v', '--htdocs', DOC_ROOT,
             '--trailer', 'x-backend-trailer: bar',
             $backend_port, 'examples/h2o/server.key', 'examples/h2o/server.crt');
    });
    $backend->{tls_port} = $backend_port;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.ssl.verify-peer: OFF
        proxy.reverse.url: https://127.0.0.1:$backend->{tls_port}
EOT
    my $client_command = "/bin/echo -n 'aaaaaaaaaa' | " .
                         "nghttp -vn -H ':method: POST' --data '-' --trailer 'x-client-trailer: foo' " .
                         "'https://127.0.0.1:$server->{tls_port}/index.txt'";
    my $client_log = `$client_command`;
    like $client_log, qr/x-backend-trailer: bar/;

    $backend->{kill}->();
    my $backend_log = readline($backend->{stdout});
    # TODO: check if request trailers to be forwarded
    # like $backend_log, qr/x-client-trailer: foo/;
};

done_testing;

