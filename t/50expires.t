use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub fetch {
    my $extra_conf = shift;
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: examples/doc_root
$extra_conf
EOT
    return `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/ 2>&1 > /dev/null`;
}


my $resp = fetch('');
unlike $resp, qr/^cache-control:.*\Wmax-age/im, "off by default";

$resp = fetch(<< 'EOT');
expires: OFF
EOT
unlike $resp, qr/^cache-control:.*\Wmax-age/im, "explicitly turned off";

$resp = fetch(<< 'EOT');
expires: 1 day
EOT
like $resp, qr/^cache-control:.*\Wmax-age=86400\W/im, "expires 1 day";

$resp = fetch(<< 'EOT');
        expires: OFF
expires: 1 day
EOT
unlike $resp, qr/^cache-control:.*\Wmax-age/im, "on at global, off at path-level";

done_testing();
