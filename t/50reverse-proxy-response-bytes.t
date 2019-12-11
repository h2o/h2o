use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;
use Time::HiRes qw(sleep);
use IO::Socket::INET;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $tempdir = tempdir(CLEANUP => 1);

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $logfile = "$tempdir/access.log";
my $server = spawn_h2o(<< "EOT");
http2-idle-timeout: 10
hosts:
  default:
    paths:
      "/":
        - proxy.reverse.url: http://127.0.0.1:$upstream_port
access-log:
  path: $logfile
  format: "@{[ join("\\t", map { "proxy.response-bytes$_:%{proxy.response-bytes$_}x" } ('', '-header', '-body')) ]}"
EOT


my ($headers) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/alice.txt");
like $headers, qr{^HTTP/1\.1 200 }s;

sleep 0.1;

my @log = do {
    open my $fh, "<", $logfile
        or die "failed to open $logfile: $!";
    map { my $l = $_; chomp $l; $l } <$fh>;
};
my $log = pop(@log);
my %map = map { split(':', $_) } split("\t", $log);

my $expected_body_size = 1661;
my $expected_header_size = 217;

is $map{'proxy.response-bytes-body'}, $expected_body_size, 'body';
is $map{'proxy.response-bytes-header'}, $expected_header_size, 'header';
is $map{'proxy.response-bytes'}, $expected_body_size + $expected_header_size, 'total';

done_testing();

