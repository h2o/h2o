use strict;
use warnings;
use IO::Socket::IP;
use Socket qw(SOCK_DGRAM);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $v6_probe = IO::Socket::IP->new(
    LocalHost => "::1",
    LocalPort => 0,
    Proto     => "udp",
    Type      => SOCK_DGRAM,
);
plan skip_all => "IPv6 may not be available:$!"
    unless $v6_probe;

my $upstream_port = empty_port({
    host  => "::1",
    proto => "udp",
});
my $upstream = spawn_h2o_raw(<< "EOT", [{host => "::1", port => $upstream_port, proto => "udp"}]);
listen:
  type: quic
  host: ::1
  port: $upstream_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

my $proxy = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://[::1]:$upstream_port
        proxy.http3.ratio: 100
EOT

run_with_curl($proxy, sub {
    my ($proto, $port, $curl) = @_;
    my $resp = `$curl --silent --show-error --dump-header /dev/stdout $proto://127.0.0.1:$port/index.txt`;
    like $resp, qr{^HTTP/[^ ]* 200}mi;
    like $resp, qr{^hello$}m;
});

done_testing;
