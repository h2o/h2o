use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'etag' => sub {
    my $fetch = sub {
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
    };

    my $etag_re = qr/^etag: /im;
    my $resp = $fetch->('');
    like $resp, $etag_re, "default is on";
    $resp = $fetch->('file.etag: off');
    unlike $resp, $etag_re, "off";
    $resp = $fetch->('file.etag: on');
    like $resp, $etag_re, "on";
};

done_testing();
