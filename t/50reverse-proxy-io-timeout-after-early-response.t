use strict;
use warnings;
use IO::Socket::INET;
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use Time::HiRes qw(time);
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

# the upstream sends the response head and part of the body as soon as it receives the request head, then reads the
# request body but sends nothing more
my $upstream_port = empty_port();
my $upstream = spawn_forked(sub {
    my $listener = IO::Socket::INET->new(
        LocalHost => '127.0.0.1',
        LocalPort => $upstream_port,
        Proto     => 'tcp',
        Listen    => 5,
        ReuseAddr => 1,
    ) or die "failed to listen:$!";
    while (my $conn = $listener->accept) {
        my $req = '';
        while ($req !~ /\r\n\r\n/s) {
            $conn->sysread($req, 4096, length $req) or last;
        }
        $conn->syswrite("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello");
        my $buf;
        while ($conn->sysread($buf, 4096)) {}
    }
});
wait_port($upstream_port);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port/
        proxy.timeout.io: 1000
EOT

# send the request body slowly so that the response head is received before the request body is sent entirely
my $start_at = time;
my $resp = `(printf a; sleep 1; printf a) | curl --silent --show-error --max-time 10 -T - http://127.0.0.1:$server->{port}/ 2>&1`;
my $elapsed = time - $start_at;
unlike $resp, qr/Operation timed out/, "io timeout is applied after the request is sent";
cmp_ok $elapsed, '<', 5, "upstream is timed out promptly";

done_testing();
