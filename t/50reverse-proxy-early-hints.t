use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use URI::Escape;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /on:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.forward-early-hints: ON
      /off:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

subtest 'on' => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/on/early-hints`;
        like $resp, qr{^HTTP/[\d.]+ 103}mi;
        (my $eh, $resp) = split(/\r\n\r\n/, $resp, 2);
        like $eh, qr{^link: </index.js>; rel=preload}mi;
    });
};

subtest 'on but no hints' => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/on/early-hints?empty=1`;
        unlike $resp, qr{^HTTP/[\d.]+ 103}mi;
    });
};

subtest 'off' => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/off/early-hints`;
        unlike $resp, qr{^HTTP/[\d.]+ 103}mi;
    });
};

done_testing();
