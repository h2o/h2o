use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use Time::HiRes qw(sleep);

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $tempdir = tempdir(CLEANUP => 1);

my $upstream_port = empty_port();
my $upstream = IO::Socket::INET->new(
    LocalHost => '127.0.0.1',
    LocalPort => $upstream_port,
    Proto => 'tcp',
    Listen => 1,
    Reuse => 1
) or die "cannot create socket: $!";

sub do_upstream {
    my ($sock) = @_;
    my $client = $sock->accept;
    while (my $buf = <$client>) {
        last if $buf eq "\r\n";
    }
    sleep 0.1; # proxy-first-byte-time
    $client->send("HTTP/1.1 200 OK\r\nContent-Length:1\r\nConnection: close\r\n\r\n");
    $client->flush;
    sleep 0.1; # proxy-response-time
    $client->send('x');
    $client->flush;
    close($client);
}

my $logfile = "$tempdir/access.log";
my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 10
hosts:
  default:
    paths:
      "/":
        - mruby.handler: |
            proc {|env|
              sleep 0.1 # proxy-idle-time
              [399, {}, []]
            }
        - proxy.reverse.url: http://127.0.0.1:$upstream_port
access-log:
  path: $logfile
  format: "@{[
    join("\\t", map { "$_:%{proxy-$_-time}x" }
      qw(idle connect request first-byte response total)
    )
  ]}"
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;

    my $backlog_filler = IO::Socket::INET->new(
        PeerHost => '127.0.0.1',
        PeerPort => $upstream_port,
        Proto => 'tcp',
    ) or die "cannot create socket: $!";

    open(CURL, "$curl --silent -kv $proto://127.0.0.1:$port/ 2>&1 |");

    sleep 0.2; # proxy-idle-time + proxy-connect-time
    $upstream->accept->close;

    do_upstream($upstream);
    while (<CURL>) {}

    my @log = do {
        open my $fh, "<", $logfile
            or die "failed to open $logfile: $!";
        map { my $l = $_; chomp $l; $l } <$fh>;
    };
    my $log = pop(@log);
    my $timings = +{ map { split(':', $_, 2) } split("\t", $log) };
    within_eps($timings, 'idle', 0.1);
    within_eps($timings, 'connect', 0.1);
    within_eps($timings, 'request', 0);
    within_eps($timings, 'first-byte', 0.1);
    within_eps($timings, 'response', 0.1);
    within_eps($timings, 'total', 0.2);
    pass;
    
});

sub within_eps {
    my ($timings, $name, $expected, $eps) = @_;
    $eps ||= $expected / 10;
    cmp_ok $timings->{$name}, '>=', $expected - $eps, ">= $name - eps";
    cmp_ok $timings->{$name}, '<=', $expected + $eps, "<= $name + eps";
}

done_testing();

