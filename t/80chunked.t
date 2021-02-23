use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

subtest "reverse-proxy" => sub {
    # spawn upstream psgi
    plan skip_all => 'Starlet not found'
        unless system 'perl -MStarlet /dev/null > /dev/null 2>&1' == 0;
    my $upstream_port = empty_port();
    my $upstream = spawn_server(
        argv     => [qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", "t/assets/upstream.psgi"],
        is_ready => sub {
            check_port($upstream_port);
        },
    );
    # spawn h2o
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    # connect, send, fetch response
    my $resp = send_and_receive($server->{port});
    like $resp, qr{^HTTP/1\.1 404 Not Found\r\n.*HTTP/1\.1 404 Not Found\r\n}s;
};

done_testing;

sub send_and_receive {
    my $server_port = shift;
    my $sock = IO::Socket::INET->new(
        PeerAddr => "127.0.0.1:$server_port",
        Proto    => "tcp",
    ) or die "connection failed:$!";
    my $msg = <<"EOT";
POST / HTTP/1.1\r
Transfer-Encoding: chunked\r
\r
5\r
abcde\r
EOT
    syswrite($sock, $msg) == length($msg)
        or die "failed to send data:$!";
    sleep 1;
    $msg = <<"EOT";
0\r
\r
GET / HTTP/1.0\r
\r
EOT
    syswrite($sock, $msg) == length($msg)
        or die "failed to send data:$!";
    my $resp = '';
    while (sysread($sock, $resp, 65536, length($resp)) != 0) {}
    $resp;
}
