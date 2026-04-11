use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $upstream = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
my $upstream_port = $upstream->{quic_port};

my $proxy = spawn_h2o(<< "EOT");
proxy.ssl.verify-peer: OFF
proxy.http3.ratio: 100
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
EOT

run_with_curl($proxy, sub {
    my ($proto, $port, $curl) = @_;
    my $resp = `$curl --silent --show-error --dump-header /dev/stdout $proto://127.0.0.1:$port/index.txt`;
    like $resp, qr{^HTTP/[^ ]* 200}mi;
    like $resp, qr{^hello$}m;
});

done_testing;
