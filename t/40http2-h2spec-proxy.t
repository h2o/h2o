use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'h2spec not found'
  unless prog_exists('h2spec');

my $upstream = spawn_h2o(<<EOT);
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
EOT

for my $upstream (
    "http://127.0.0.1:$upstream->{port}/",
    "https://127.0.0.1:$upstream->{tls_port}/",
) {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: $upstream
        proxy.ssl.cafile: share/h2o/ca-bundle.crt
        proxy.ssl.verify-peer: OFF
EOT

    my $output = `h2spec -t -k -p $server->{tls_port} 2>&1`;
    unlike $output, qr/Failures:/;
    like $output, qr/ 0 failed/;
}

done_testing();
