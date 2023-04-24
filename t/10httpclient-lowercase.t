use strict;
use warnings;
use Test::More;
use t::Util;
use Net::EmptyPort qw(check_port);

my $progname = "h2o-httpclient";
my $progpath = bindir() . "/$progname";
plan skip_all => "$progname not found"
    unless -x $progpath;

my $upstream_port = empty_port();
my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });

my $upstream = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), $upstream_port, ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:$upstream_port
EOT

my $out = `$progpath -3 100 -H sArCaSmCaSe:Enabled http://127.0.0.1:$quic_port/echo-headers`;

like($out, qr/^sarcasmcase: *Enabled$/m);

done_testing;
