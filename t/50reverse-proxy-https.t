use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv => [
        qw(
            plackup -s Standalone --ssl=1 --ssl-key-file=examples/h2o/server.key --ssl-cert-file=examples/h2o/server.crt --port
        ),
        $upstream_port, ASSETS_DIR . "/upstream.psgi"
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/verify":
        proxy.reverse.url: https://127.0.0.1:$upstream_port
      "/no-verify":
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.ssl.verify-peer: OFF
      "/wikipedia":
        proxy.reverse.url: https://en.wikipedia.org/wiki/Main_Page
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    my $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port/verify/ 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/[^ ]* 502\s}is;
    $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port/no-verify/ 2>&1 > /dev/null`;
    unlike $resp, qr{^HTTP/[^ ]* 502\s}is;
    $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port/wikipedia/ 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/[^ ]* 200\s}is;
});

done_testing();
