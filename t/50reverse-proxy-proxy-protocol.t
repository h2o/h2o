use strict;
use warnings;
use IO::Socket::INET;
use Test::TCP;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Scope::Guard qw(guard);
use t::Util;

my $upstream_port = empty_port();

my $listen = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $upstream_port,
    Listen => 5,
) or die "failed to listen to 127.0.0.1:$upstream_port:$!";

my $upstream_guard = do {
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        # server process
        while (1) {
            if (my $conn = $listen->accept) {
                sysread $conn, my $buf, 4096;
print STDERR "**** $buf";
                syswrite $conn, "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n$buf";
print STDERR "**** yeoh";
                $conn->close;
            }
        }
    }
    guard {
        kill 'TERM', $pid;
    };
};

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port/
        proxy.proxy-protocol: ON
        proxy.timeout.keepalive: 0
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl_cmd) = @_;
    my $resp = `$curl_cmd --silent $proto://127.0.0.1:$port/hello`;
    like $resp, qr{^PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 [0-9]{1,5} $port\r\nGET /hello HTTP/1\.}is;
});

done_testing;
