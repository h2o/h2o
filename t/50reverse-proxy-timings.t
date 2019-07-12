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
    sleep 0.1; # proxy.process-time
    $client->send("HTTP/1.1 200 OK\r\nContent-Length:1\r\nConnection: close\r\n\r\n");
    $client->flush;
    sleep 0.1; # proxy.response-time
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
              sleep 0.1 # proxy.idle-time
              [399, {}, []]
            }
        - proxy.reverse.url: http://127.0.0.1:$upstream_port
        - server-timing: ENFORCE
access-log:
  path: $logfile
  format: "@{[
    join("\\t", map { "proxy.$_:%{proxy.$_-time}x" }
      qw(idle connect request process response total)
    )
  ]}"
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;

    open(CURL, "$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/ |");

    do_upstream($upstream);
    my $resp = join('', <CURL>);

    subtest 'access-log' => sub {
        my @log = do {
            open my $fh, "<", $logfile
                or die "failed to open $logfile: $!";
            map { my $l = $_; chomp $l; $l } <$fh>;
        };
        my $log = pop(@log);
        my $timings = +{ map { split(':', $_, 2) } split("\t", $log) };
        within_eps($timings, 'proxy.idle', 0.1);
        within_eps($timings, 'proxy.connect', 0, 0.01);
        within_eps($timings, 'proxy.request', 0);
        within_eps($timings, 'proxy.process', 0.1);
        within_eps($timings, 'proxy.response', 0.1);
        within_eps($timings, 'proxy.total', 0.2);
    };

    subtest 'server-timing' => sub {
        like $resp, qr/^trailer: server-timing/mi;
        my $st = +{};
        while ($resp =~ /^server-timing: ([^\r\n]+)/mig) {
            $st = +{ %$st, map { split ('; dur=', $_) } split(', ', $1) };
        }
        within_eps($st, 'proxy.idle', 100);
        within_eps($st, 'proxy.connect', 0, 10);
        within_eps($st, 'proxy.request', 0);
        within_eps($st, 'proxy.process', 100);
        within_eps($st, 'proxy.response', 100);
        within_eps($st, 'proxy.total', 200);
    };
});

sub within_eps {
    my ($timings, $name, $expected, $eps) = @_;
    $eps ||= $expected / 10;
    cmp_ok $timings->{$name}, '>=', $expected - $eps, ">= $name - eps";
    cmp_ok $timings->{$name}, '<=', $expected + $eps, "<= $name + eps";
}

done_testing();

