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

my $guard = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

sub doit {
    my $preserve = shift;
    my $expected = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://localhost.examp1e.net:$upstream_port
        proxy.preserve-host: $preserve
EOT
    my $port = $server->{port};
    if ($preserve eq "OFF") {
        $port = $upstream_port;
    }

    my $curl = 'curl --silent -v --dump-header /dev/stderr';
    my ($headers, $body) = run_prog("$curl "
        . " --request-target 'http://127.0.0.1:@{[$server->{port}]}/echo-headers' "
        . " --header 'Host: 127.0.0.1:@{[$server->{port}]}' "
        . " http://127.0.0.1:@{[$server->{port}]}/echo-headers");

    like $body, qr/^host: $expected:$port/mi, 'host header is the expected one';
}

doit("ON", "127.0.0.1");
doit("OFF", "localhost.examp1e.net");


done_testing();
