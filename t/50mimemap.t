use strict;
use warnings;
use Test::More;
use t::Util;

my $CURL_CMD = q{curl --silent --show-error --output /dev/null --write-out '%{content_type}'};

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest "basic" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        file.dir: t/50mimemap/doc_root
      /addtypes:
        file.dir: t/50mimemap/doc_root
        file.mime.addtypes:
          application/xhtml+xml: .xhtml
      /removetypes:
        file.dir: t/50mimemap/doc_root
        file.mime.removetypes:
          - .xhtml
      /settypes:
        file.dir: t/50mimemap/doc_root
        file.mime.settypes:
          text/xml: .xhtml
    file.mime.addtypes:
      application/xml: .xhtml
  default-type-test:
    paths:
      /:
        file.dir: t/50mimemap/doc_root
    file.mime.setdefaulttype: application/xhtml+xml
file.index:
  - index.xhtml
EOT

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
};

subtest "issue730" => sub {
    my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
file.mime.addtypes:
  "text/plain; charset=mycharset": ".txt"
EOT
    my $ct = `$CURL_CMD http://127.0.0.1:$server->{port}/index.txt`;
    is $ct, "text/plain; charset=mycharset";
};

subtest "reset mimemap to minimum" => sub {
    my $server = spawn_h2o(<< 'EOT');
file.mime.setdefaulttype: "application/octet-stream"
file.mime.settypes: {}
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
    my $ct = `$CURL_CMD http://127.0.0.1:$server->{port}/index.txt`;
    is $ct, "application/octet-stream";
};

done_testing;
