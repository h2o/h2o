use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Test::More;
use t::Util;

my %files = map { +($_ => md5_file($_)) } qw(index.txt halfdome.jpg);

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
file.index:
  - index.xhtml
file.mime.addtypes:
  application/xml: .xhtml
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
    is $ct, $expected{$path};
    $ct = `$CURL_CMD http://127.0.0.1:$port${path}index.xhtml`;
    is $ct, $expected{$path};
}

done_testing;
