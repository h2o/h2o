use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

# start upstream
my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [
        qw(plackup -MPlack::App::File -s Starlet --access-log /dev/null -p), $upstream_port,
        ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

subtest 'preserve-host' => sub {
    my $doit = sub {
        my $flag = shift;
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.preserve-host: $flag
EOT
        my $res = `curl --silent http://127.0.0.1:$server->{port}/echo-headers`;
        like $res, qr/^host: 127.0.0.1:@{[ $flag eq 'ON' ? $server->{port} : $upstream_port ]}$/im;
    };

    subtest 'ON' => sub {
        $doit->("ON");
    };
    subtest 'OFF' => sub {
        $doit->("OFF");
    };
};

subtest 'timeout.io' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.timeout.io: 2000
EOT
    my $fetch = sub {
        my $sleep = shift;
        `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/sleep-and-respond?sleep=$sleep 2>&1 > /dev/null`;
    };
    my $resp = $fetch->(1);
    like $resp, qr{^HTTP/1\.1 200 }s, "respond before timeout";
    my $resp = $fetch->(3);
    like $resp, qr{^HTTP/1\.1 502 }s, "respond after timeout";
};

done_testing;
