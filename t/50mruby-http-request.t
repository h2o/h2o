use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(empty_port check_port);
use Test::More;
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_hostport = "127.0.0.1:@{[empty_port()]}";

sub create_upstream {
    my @args = (
        qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen),
        $upstream_hostport,
        ASSETS_DIR . "/upstream.psgi",
    );
    spawn_server(
        argv     => \@args,
        is_ready =>  sub {
            $upstream_hostport =~ /:([0-9]+)$/s
                or die "failed to extract port number";
            check_port($1);
        },
    );
};

my $server = spawn_h2o(sub {
    my ($port, $tls_port) = @_;
    return << "EOT";
proxy.timeout.io: 1000
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            http_request("http://$upstream_hostport#{env["PATH_INFO"]}#{env["QUERY_STRING"]}", {
              method: env["REQUEST_METHOD"],
              body: env["rack.input"],
            }).join
          end
      /as_str:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, [http_request("http://$upstream_hostport/index.txt").join[2].as_str]]
          end
EOT
});

sub doit {
    my ($proto, $port) = @_;
    my $curl_cmd = 'curl --insecure --silent --dump-header /dev/stderr';
    subtest "connection-error" => sub {
        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/index.txt");
        like $headers, qr{HTTP/1\.1 500 }is;
    };
    my $upstream = create_upstream();
    subtest "get" => sub {
        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/index.txt");
        like $headers, qr{HTTP/1\.1 200 }is;
        is $body, "hello\n";
    };
    subtest "post" => sub {
        my ($headers, $body) = run_prog("$curl_cmd --data 'hello world' $proto://127.0.0.1:$port/echo");
        like $headers, qr{HTTP/1\.1 200 }is;
        is $body, 'hello world';
    };
    subtest "slow-chunked" => sub {
        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/streaming-body");
        like $headers, qr{HTTP/1\.1 200 }is;
        is $body, (join "", 1..30);
    };
    subtest "as_str" => sub {
        my ($headers, $body) = run_prog("$curl_cmd $proto://127.0.0.1:$port/as_str/");
        like $headers, qr{HTTP/1\.1 200 }is;
        is $body, "hello\n";
    };
}

subtest "http/1" => sub {
    doit("http", $server->{port});
};

subtest "https/1" => sub {
    doit("https", $server->{tls_port});
};

subtest "http2" => sub {
    plan skip_all => "curl does not support HTTP/2"
        unless curl_supports_http2();
    doit("https", $server->{tls_port}, "--http2");
};

done_testing();
