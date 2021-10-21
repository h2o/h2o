use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();

my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --max-keepalive-reqs 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);


my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $url = "http://127.0.0.1:$server->{port}/?resp:transfer-encoding=foo";
my $resp = `curl --silent --http1.1 --dump-header /dev/stdout $url`;
like $resp, qr{HTTP/[^ ]+ 502\s}m;

done_testing();

