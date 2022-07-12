use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'h2spec not found'
    unless prog_exists('h2spec');

my @offload_modes = qw(off);
if ($^O eq 'linux') {
    push @offload_modes, "kernel";
    push @offload_modes, "zerocopy"
        if server_features()->{"ssl-zerocopy"} && cpuinfo_can_ntaes();
}

for my $offload (@offload_modes) {
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
    like $output, qr/ 0 failed/;
}

done_testing();

sub cpuinfo_can_ntaes {
    system("egrep '^flags.* aes .* avx2 ' /proc/cpuinfo > /dev/null") == 0;
}
