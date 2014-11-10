use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        file.dir: t/50end-to-end/mimemap/docroot
      /addtypes:
        file.dir: t/50end-to-end/mimemap/docroot
        file.mime.addtypes:
          application/xhtml+xml: .xhtml
      /removetypes:
        file.dir: t/50end-to-end/mimemap/docroot
        file.mime.removetypes:
          - .xhtml
      /settypes:
        file.dir: t/50end-to-end/mimemap/docroot
        file.mime.settypes:
          text/xml: .xhtml
    file.mime.addtypes:
      application/xml: .xhtml
  default-type-test:
    paths:
      /:
        file.dir: t/50end-to-end/mimemap/docroot
    file.mime.setdefaulttype: application/xhtml+xml
file.index:
  - index.xhtml
EOT

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $CURL_CMD = q{curl --silent --show-error --output /dev/null --write-out '%{content_type}'};
my $port = $server->{port};
my %expected = (
    '/'             => 'application/xml',
    '/addtypes/'    => 'application/xhtml+xml',
    '/removetypes/' => 'application/octet-stream',
    '/settypes/'    => 'text/xml',
);

for my $path (sort keys %expected) {
    my $ct = `$CURL_CMD http://127.0.0.1:$port$path`;
    is $ct, $expected{$path}, "$path";
    $ct = `$CURL_CMD http://127.0.0.1:$port${path}index.xhtml`;
    is $ct, $expected{$path}, "${path}index.xhtml";
}

my $ct = `$CURL_CMD --header 'host: default-type-test' http://127.0.0.1:$port/`;
is $ct, 'application/xhtml+xml', 'setdefaulttype';

done_testing;
