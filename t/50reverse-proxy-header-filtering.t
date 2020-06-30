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

sub do_test {
    my $directive = shift;
    my $headers = shift;
    my $expected = shift;
    my $not_expected = shift;

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        $directive
EOT

    run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl $headers --silent $proto://127.0.0.1:$port/echo-headers`;
            if ($expected ne "") {
                if (ref($expected) eq 'ARRAY') {
                    foreach my $exp ( @{$expected} ) {
                        like $resp, qr/^$exp$/mi, "$exp present";
                    }
                } else {
                    like $resp, qr/^$expected$/mi, "$expected present";
                }
            }
            if ($not_expected ne "") {
                if (ref($not_expected) eq 'ARRAY') {
                    foreach my $nexp ( @{$not_expected} ) {
                        unlike $resp, qr/^$nexp$/mi, "$nexp not present";
                    }
                } else {
                    unlike $resp, qr/^$not_expected$/mi, "$not_expected not present";
                }
            }
        });
}

subtest "unsetunless" => sub  {
    do_test('proxy.header.unsetunless: [ "a" ]', "-Ha:1 -Hb:2", "a: 1", "b: 2");
    do_test('proxy.header.unsetunless: [ "c" ]', "-Ha:1 -Hb:2 -Hc:3", "c: 3", ["a: 1", "b: 2"]);
};
subtest "unset" => sub  {
    do_test('proxy.header.unset: [ "a", ]', "-Ha:1 -Hb:2", "b: 2", "a: 1");
};
subtest "unsetunless case insensitive" => sub  {
    do_test('proxy.header.unsetunless: [ "A" ]', "-Ha:1 -Hb:2", "a: 1", "b: 2");
    do_test('proxy.header.unsetunless: [ "a" ]', "-HA:1 -Hb:2", "a: 1", "b: 2");
};
subtest "cookie_list_allow" => sub  {
    do_test('proxy.header.cookie.unsetunless: [ "a" ]', '-H"cookie:a=1; b=2; c=3"', "cookie: a=1", "");
};
subtest "cookie_list_deny" => sub  {
    do_test('proxy.header.cookie.unset: [ "a" ]', '-H"cookie:a=1; b=2; c=3"', "cookie: b=2; c=3", "");
};
subtest "cookie_list_allow case sensitive" => sub  {
    do_test('proxy.header.cookie.unsetunless: [ "A" ]', '-H"cookie:a=1; b=2; c=3; A=4"', "cookie: A=4", "");
};

done_testing();
