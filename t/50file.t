use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'trailing-slash' => sub {
  my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT

  my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt/ 2>&1 > /dev/null`;
  like $resp, qr{^HTTP/1.1 404 File Not Found}s, "status";
};

done_testing;
