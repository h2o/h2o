use strict;
use warnings;
use IO::Socket::IP;
use Socket qw(SOCK_DGRAM);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $v6_probe = IO::Socket::IP->new(
    LocalHost => "::1",
    LocalPort => 0,
    Proto     => "udp",
    Type      => SOCK_DGRAM,
);
plan skip_all => "IPv6 may not be available:$!"
    unless $v6_probe;

my $quic_port = empty_port({
    host  => "::1",
    proto => "udp",
});
my $server = spawn_h2o_raw(<< "EOT", [{host => "::1", port => $quic_port, proto => "udp"}]);
listen:
  type: quic
  host: ::1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

my $resp = `$client_prog -3 100 https://[::1]:$quic_port 2>&1`;
like $resp, qr{^HTTP/.*\n\nhello\n$}s;

done_testing;
