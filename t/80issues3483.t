use strict;
use warnings;
use Test::More;
use t::Util;

# this test checks if an infinite loop is generated when the URI path includes a %00

plan skip_all => "curl not found"
    unless prog_exists("curl");

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    my $resp = `$curl --silent --dump-header /dev/stdout $proto://127.0.0.1:$port/%00`;
    like $resp, qr{^HTTP/\S+ 404};
});

undef $server;

done_testing();
