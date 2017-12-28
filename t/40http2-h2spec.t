use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'h2spec not found'
    unless prog_exists('h2spec');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
EOT

is system(qw(h2spec -t -k -p), $server->{tls_port}), 0;

done_testing();
