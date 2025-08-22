use strict;
use warnings;
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();
my $upstream = spawn_server(
    argv     => [
        qw(plackup -s Starlet --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi",
    ],
    is_ready => sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(sub {
        my ($port, $tls_port) = @_;
        return << "EOT";
http1-upgrade-to-http2: OFF
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: http://127.0.0.1:$upstream_port
        proxy.tunnel: OFF
EOT
});

my ($head, $body) = run_prog("curl --http2 -sv http://127.0.0.1:$server->{port}/echo-headers");
like $head, qr{HTTP/1.1 200 OK}, "Status code is 200, protocol is 1.1";
like $body, qr{connection: keep-alive}, "connection: keep-alive";
unlike $body, qr{upgrade:}, "No upgrade: header";

done_testing;
