use strict;
use warnings;
use File::Temp qw(tempdir);
use IO::Socket::IP;
use Net::EmptyPort qw(check_port);
use Socket qw(SOCK_STREAM);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

local $SIG{PIPE} = sub {};

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);
my $upstream_port = empty_port();

my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

like send_request(0, 0, ""), qr{^HTTP/1\.1 200 }s, "zero chunks";

like send_request(1000, 1000, ""), qr{^HTTP/1\.1 200 }s, "1000 x 1000B chunks => ok";
like send_request(100, 10000, ""), qr{^HTTP/1\.1 200 }s, "10000 x 100B chunks => ok";
like send_request(10, 100000, ""), qr{^HTTP/1\.1 200 }s, "100000 x 10B chunks => ok";
like send_request(1, 1000000, ""), qr{^HTTP/1\.1 400 }s, "1000000 x 1B chunks => error";
like send_request(1, 100000, ""), qr{^HTTP/1\.1 400 }s, "100000 x 1B chunks => ok"; # below our 100KB threshold

like send_request(100, 10000, "; ext=small"), qr{^HTTP/1\.1 200 }s, "100B chunks with small ext => ok";
like send_request(100, 10000, "; ext=" . "x" x 1000), qr{^HTTP/1\.1 400 }s, "100B chunks with 1KB ext => error";

sub send_request {
    my ($len, $count, $extra) = @_;

    my $chunk = sprintf("%x%s\r\n", $len, $extra) . "x" x $len . "\r\n";

    my $conn = IO::Socket::IP->new(
        PeerHost => "127.0.0.1",
        PeerPort => $server->{port},
        Type     => SOCK_STREAM,
    ) or die "failed to connect to 127.0.0.1:@{[$server->{port}]}:$!";
    syswrite $conn, "POST /echo-headers HTTP/1.1\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n";
    syswrite $conn, join "", map { $chunk } (0..($count - 1));
    sleep 0.1; # chunk decoder detects attack only at the end of the bytes returned by `recv`, so add a sleep before sending the
               # last chunk
    syswrite $conn, "${chunk}0\r\n\r\n";
    sysread $conn, my $resp, 65536;
    $resp;
}

undef $upstream;
undef $server;

done_testing();
