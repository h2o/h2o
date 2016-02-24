use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();

my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null -p), $upstream_port, ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

my $h2o = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

subtest 'http1' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    my $doit = sub {
        my ($proto, $port) = @_;
        my $extra = '';
        if ($proto eq 'https') {
            $extra .= ' --insecure';
            $extra .= ' --http1.1'
                if curl_supports_http2();
        }
        subtest $proto => sub {
            my $resp = `curl --max-time 1 $extra $proto://127.0.0.1:$port/streaming-body 2>&1`;
            like $resp, qr/operation timed out/i, "operation should time out";
            sleep 1;
            $resp = `curl --silent --dump-header /dev/stderr $extra $proto://127.0.0.1:$port/ 2>&1 > /dev/null`;
            like $resp, qr{^HTTP/[^ ]+ 404\s}s, "server is still alive";
        };
    };
    $doit->('http', $h2o->{port});
    $doit->('https', $h2o->{tls_port});
};

# note: implement test using HTTP/2, nghttp --timeout 2 does not seem to work like above

done_testing;
