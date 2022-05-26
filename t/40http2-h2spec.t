use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'h2spec not found'
    unless prog_exists('h2spec');

for my $offload (qw(OFF ON)) {
    subtest "ssl-offload=$offload" => sub {
        run_tests($offload);
    };
}

sub run_tests {
    my $offload = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
ssl-offload: $offload
EOT

    my $output = `h2spec -t -k -p $server->{tls_port} 2>&1`;
    unlike $output, qr/Failures:/;
}

done_testing();
