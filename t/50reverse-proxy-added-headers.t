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
    my $emit_xff = shift;
    my $emit_via = shift;
    my $emit_xff_str = $emit_xff ? "ON" : "OFF";
    my $emit_via_str = $emit_via ? "ON" : "OFF";

    my $server = spawn_h2o(<< "EOT");
proxy.emit-x-forwarded-headers: $emit_xff_str
proxy.emit-via-header: $emit_via_str
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://localhost.examp1e.net:$upstream_port
EOT

    run_with_curl($server, sub {
            my ($proto, $port, $curl) = @_;
            my $resp = `$curl --silent $proto://127.0.0.1:$port/echo-headers`;
            if ($emit_xff) {
                like $resp, qr/^x-forwarded-for: ?127\.0\.0\.1$/mi, "x-forwarded-for";
                like $resp, qr/^x-forwarded-proto: ?$proto$/mi, "x-forwarded-proto";
            } else {
                unlike $resp, qr/^x-forwarded-for: ?127\.0\.0\.1$/mi, "x-forwarded-for not present";
                unlike $resp, qr/^x-forwarded-proto: ?$proto$/mi, "x-forwarded-proto not present";
            }
            if ($emit_via) {
                like $resp, qr/^via: ?[^ ]+ 127\.0\.0\.1:$port$/mi, "via";
            } else {
                unlike $resp, qr/^via: ?[^ ]+ 127\.0\.0\.1:$port$/mi, "via";
            }
            $resp = `$curl --silent --header 'X-Forwarded-For: 127.0.0.2' --header 'Via: 2 example.com' $proto://127.0.0.1:$port/echo-headers`;
            if ($emit_xff) {
                like $resp, qr/^x-forwarded-for: ?127\.0\.0\.2, 127\.0\.0\.1$/mi, "x-forwarded-for (append)";
            } else {
                like $resp, qr/^x-forwarded-for: ?127\.0\.0\.2$/mi, "x-forwarded-for only contains the original header";
            }
            if ($emit_via) {
                like $resp, qr/^via: ?2 example.com, [^ ]+ 127\.0\.0\.1:$port$/mi, "via (append)";
            } else {
                like $resp, qr/^via: 2 example.com$/mi, "via left as-is";
            }
        });
}

do_test(0, 0);
do_test(0, 1);
do_test(1, 0);
do_test(1, 1);

done_testing();
