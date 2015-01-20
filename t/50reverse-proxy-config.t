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
        my $res = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/echo 2>&1 > /dev/null`;
        like $res, qr/^x-req-host: 127.0.0.1:@{[ $flag eq 'ON' ? $server->{port} : $upstream_port ]}/im;
    };

    subtest 'ON' => sub {
        $doit->("ON");
    };
    subtest 'OFF' => sub {
        $doit->("OFF");
    };
};

done_testing;
