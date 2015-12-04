use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
header.add: "strict-transport-security: max-age=31536000; includeSubDomains; preload "
header.unset: last-modified
EOT

my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt 2>&1 > /dev/null`;
like $resp, qr{^HTTP/1\.1 200 }s, "200 response";
like $resp, qr{^strict-transport-security: max-age=31536000; includeSubDomains; preload\r$}im, "hsts added";
is +(() = $resp =~ m{^strict-transport-security:}img), 1, "header added only once";
unlike $resp, qr{^last-modified: }, "last-modified unset";

done_testing();
