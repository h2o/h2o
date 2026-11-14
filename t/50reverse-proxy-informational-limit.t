use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

# The HTTP clients accept up to 10 informational responses for each request; when more are received, the request fails.

# HTTP/1.1 upstream that sends as many 103 responses as specified by the path, followed by a 200 response
my $h1_port = empty_port();
my $h1_upstream = do {
    my $listen = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $h1_port,
        Proto     => 'tcp',
        Listen    => 5,
        Reuse     => 1,
    ) or die "failed to listen to 127.0.0.1:$h1_port:$!";
    my $upstream = spawn_forked(sub {
        while (my $sock = $listen->accept) {
            my $req = '';
            while ($req !~ /\r\n\r\n/) {
                $sock->sysread($req, 4096, length $req) or last;
            }
            my ($num_informational) = $req =~ m{^GET /(\d+)};
            $sock->syswrite(join "", ("HTTP/1.1 103 Early Hints\r\nlink: </index.js>; rel=preload\r\n\r\n") x $num_informational,
                "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello");
            close $sock;
        }
    });
    close $listen;
    $upstream;
};

subtest 'http1' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$h1_port
EOT
    test_limit("http://127.0.0.1:$server->{port}", 0);
};

subtest 'http2' => sub {
    plan skip_all => "h2get not found"
        unless h2get_exists();
    for my $num_informational (10, 11) {
        subtest "$num_informational informational responses" => sub {
            my $h2g = spawn_h2get_backend(<< "EOC");
    if f.type == 'HEADERS' and (f.flags & END_STREAM) == END_STREAM then
        $num_informational.times do
            conn.send_headers({":status" => "103", "link" => "</index.js>; rel=preload"}, f.stream_id, END_HEADERS)
        end
        conn.send_headers({":status" => "200", "content-length" => "5"}, f.stream_id, END_HEADERS)
        conn.send_data(f.stream_id, END_STREAM, "hello")
    end
EOC
            my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$h2g->{tls_port}
        proxy.ssl.verify-peer: OFF
        proxy.http2.ratio: 100
EOT
            check_resp("http://127.0.0.1:$server->{port}/", $num_informational);
            $h2g->{kill}->();
        };
    }
};

subtest 'http3' => sub {
    # The HTTP/3 upstream is an h2o that sends one 103 of its own (`header.add` with `when: early`) and forwards the 103s it
    # receives from the HTTP/1.1 upstream.
    my $quic_port = empty_port({ host => "127.0.0.1", proto => "udp" });
    my $backend = spawn_h2o_raw(<< "EOT", [{host => "127.0.0.1", port => $quic_port, proto => "udp"}]);
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        header.add:
          header: "link: </index.css>; rel=preload"
          when: early
        proxy.reverse.url: http://127.0.0.1:$h1_port
EOT
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$quic_port
        proxy.ssl.verify-peer: OFF
        proxy.http3.ratio: 100
EOT
    test_limit("http://127.0.0.1:$server->{port}", 1);
};

done_testing;

sub test_limit {
    my ($base_url, $num_added) = @_;
    for my $num_informational (10, 11) {
        subtest "$num_informational informational responses" => sub {
            check_resp("$base_url/@{[$num_informational - $num_added]}", $num_informational);
        };
    }
}

sub check_resp {
    my ($url, $num_informational) = @_;
    my $resp = `curl --silent --include -m 5 $url 2>&1`;
    if ($num_informational <= 10) {
        like $resp, qr{^HTTP/1\.1 200 .*\r\n\r\nhello$}s, "success";
    } else {
        like $resp, qr{^HTTP/1\.1 502 .*\r\n\r\ntoo many informational responses$}s, "failure";
    }
}
