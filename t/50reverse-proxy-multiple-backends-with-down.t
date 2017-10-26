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
my $unused_port = empty_port();

my $guard = spawn_server(
argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
is_ready =>  sub {
    check_port($upstream_port);
},
);

sub do_test {
    my $balancer = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url:
          - http://127.0.0.1.XIP.IO:$unused_port/echo-server-port
          - http://127.0.0.1.XIP.IO:$upstream_port/echo-server-port
        proxy.reverse.balancer: $balancer
EOT
    
    for my $i (1..50) {
        run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/`;
            is $resp, $upstream_port;
        });
    }
}

do_test("round-robin");
do_test("least-conn");
do_test("hash");
done_testing();
