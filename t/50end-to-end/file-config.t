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

subtest 'dir-listing' => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /off:
        file.dir: examples/doc_root
        file.dirlisting: off
      /on:
        file.dir: examples/doc_root
        file.dirlisting: on
    file.index: []
EOT

    my $fetch = sub {
        my $path = shift;
        return `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path 2>&1 > /dev/null`;
    };

    my $resp = $fetch->("/on/");
    like $resp, qr{^HTTP/1\.[0-9]+ 200 }s, "ON returns 200";
    $resp = $fetch->("/off/");
    like $resp, qr{^HTTP/1\.[0-9]+ 403 }s, "OFF returns 403";
};

done_testing();
