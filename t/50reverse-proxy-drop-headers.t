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

subtest 'request-header' => sub {
# proxy-authenticate

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1.XIP.IO:$upstream_port
EOT

    my $curl = 'curl --silent --dump-header /dev/stderr';
    my ($headers, $body) = run_prog("$curl"
        . " -H 'Proxy-Authenticate: hoge'"
        . " -H 'Date: Thu, 01 Jan 1970 00:00:00 GMT'"
        . " http://127.0.0.1:@{[$server->{port}]}/echo-headers");
    unlike $body, qr/^proxy-authenticate:/mi, 'proxy-authenticate header should be dropped';
    like $body, qr/^date:/mi, 'date request header is not dropped';
};

subtest 'response header' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1.XIP.IO:$upstream_port
EOT

    my $curl = 'curl --silent --dump-header /dev/stderr';
    my ($headers, $body) = run_prog("$curl http://127.0.0.1:@{[$server->{port}]}/fixed-date-header");
    unlike $headers, qr/Thu, 01 Jan 1970 00:00:00 GMT/, "date response header from upstream should be dropped and replaced";
};

done_testing();
