use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port);
use Test::More;
use Time::HiRes qw(time);
use t::Util;

# Tests `proxy.timeout.first_byte` and `proxy.timeout.io` of the HTTP/3 client. The upstream is h2o serving HTTP/3, which forwards
# the requests to a HTTP/1 backend that stalls in the way specified by the path.

my $backend_port = empty_port();
my $listen = IO::Socket::INET->new(
    LocalHost => "127.0.0.1",
    LocalPort => $backend_port,
    Proto     => "tcp",
    Listen    => 10,
    Reuse     => 1,
) or die "failed to listen to 127.0.0.1:$backend_port:$!";
my $backend = spawn_forked(sub {
    while (my $sock = $listen->accept) {
        next if fork;
        my $req = "";
        while ($req !~ /\r\n\r\n/) {
            $sock->sysread($req, 4096, length $req) or exit 0;
        }
        if ($req =~ m{^\S+ /delay-head }) {
            sleep 2;
            $sock->syswrite("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello");
            exit 0;
        } elsif ($req =~ m{^GET /stall-body }) {
            $sock->syswrite("HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhello");
        }
        # stall
        while ($sock->sysread(my $buf, 4096)) {}
        exit 0;
    }
});
close $listen;

my $upstream_port = empty_port({ host => "127.0.0.1", proto => "udp" });
my $upstream = spawn_h2o_raw(<< "EOT", [{host => "127.0.0.1", port => $upstream_port, proto => "udp"}]);
listen:
  type: quic
  host: 127.0.0.1
  port: $upstream_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$backend_port
EOT

subtest "first byte timeout" => sub {
    my ($resp, $elapsed) = doit("/stall-head", "proxy.timeout.first_byte: 1000");
    like $resp, qr{^HTTP/[0-9.]+ 50[24]}s, "error response";
    cmp_ok $elapsed, "<", 3, "timed out promptly";
};

subtest "first byte timeout longer than I/O timeout" => sub {
    my ($resp, $elapsed) = doit("/delay-head", "proxy.timeout.io: 1000\n        proxy.timeout.first_byte: 4000");
    like $resp, qr{HTTP/[0-9.]+ 200.*\r\n\r\nhello$}s, "response is received";
};

subtest "first byte timeout longer than I/O timeout, request body ending with an empty chunk" => sub {
    # the request body is streamed, its end being signalled by a FIN that does not carry data
    my ($resp, $elapsed) = doit("/delay-head", "proxy.timeout.io: 1000\n        proxy.timeout.first_byte: 4000",
        "(echo hello; sleep 0.5) | curl -T -");
    like $resp, qr{HTTP/[0-9.]+ 200.*\r\n\r\nhello$}s, "response is received";
};

subtest "I/O timeout" => sub {
    my ($resp, $elapsed) = doit("/stall-body", "proxy.timeout.io: 1000");
    like $resp, qr{^HTTP/[0-9.]+ 200.*\r\n\r\nhello$}ms, "response headers and partial body are received";
    unlike $resp, qr/Operation timed out/, "timed out by h2o";
    cmp_ok $elapsed, "<", 3, "timed out promptly";
};

done_testing;

sub doit {
    my ($path, $proxy_conf, $curl) = @_;
    $curl ||= "curl";
    my $server = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.http3.ratio: 100
        $proxy_conf
EOT
    my $start_at = time;
    my $resp = `$curl --silent --show-error --max-time 10 --include http://127.0.0.1:$server->{port}$path 2>&1`;
    my $elapsed = time - $start_at;
    return ($resp, $elapsed);
}
