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

subtest 'all' => sub {
    my $server = spawn_h2o(<< "EOT");
proxy.forward-early-hints: all
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp;
        $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/early-hints`;
        like $resp, qr{^HTTP/[\d.]+ 103}mi;
        (my $eh, $resp) = split(/\r\n\r\n/, $resp, 2);
        like $eh, qr{^link: </index.js>; rel=preload}mi;

        $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/early-hints?empty=1`;
        unlike $resp, qr{^HTTP/[\d.]+ 103}mi, 'no hints received';
    });
};

subtest 'except-h1 (default)' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/early-hints`;
        if ($curl =~ /http2/) {
            like $resp, qr{^HTTP/[\d.]+ 103}mi;
        } else {
            unlike $resp, qr{^HTTP/[\d.]+ 103}mi;
        }
    });
};

subtest 'none' => sub {
    my $server = spawn_h2o(<< "EOT");
proxy.forward-early-hints: none
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/early-hints`;
        unlike $resp, qr{^HTTP/[\d.]+ 103}mi;
    });
};

done_testing();
