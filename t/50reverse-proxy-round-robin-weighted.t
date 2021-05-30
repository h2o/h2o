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

my $upstream_port1 = empty_port();
my $upstream_port2 = empty_port();

my $guard1 = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port1, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port1);
    },
);

my $guard2 = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port2, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port2);
    },
);

my $access_count1 = 0;
my $access_count2 = 0;
my $unexpected = 0;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url:
          - http://localhost.examp1e.net:$upstream_port1/echo-server-port
          -
            url: http://localhost.examp1e.net:$upstream_port2/echo-server-port
            weight: 2
EOT

sub do_test {
    run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/`;
            if ($resp eq $upstream_port1) {
                $access_count1 += 1;
            } elsif ($resp eq $upstream_port2) {
                $access_count2 += 1;
            } else {
                $unexpected = 1;
            }
            isnt $unexpected, 1;
        });
}

for my $i (1..30) {
    do_test();
    if ($unexpected == 1) {
        last
    }
}

isnt $unexpected, 1;
is((2 * $access_count1), $access_count2, "load balanced");
done_testing();
