use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'nghttp not found'
    unless prog_exists('nghttp');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          lambda do |env|
            push_paths = []
            if env["PATH_INFO"] == "/"
              push_paths << "/index.js"
            end
            return [
              399,
              push_paths.empty? ? {} : {"link" => push_paths.map{|p| "<#{p}>; rel=preload"}.join("\\n")},
              [],
            ]
          end
        file.dir: @{[ DOC_ROOT ]}
http2-casper: ON
EOT

my $doit = sub {
    my ($proto, $port) = @_;

    subtest "without-fingerprint" => sub {
        my $resp = `nghttp -n -v --stat $proto://127.0.0.1:$port/`;
        like $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\n.*\s/\n}is, "js pushed before html";
        like $resp, qr{recv \(stream_id=2\) cache-fingerprint-key: 5399\n}is, "has fingerprint for pushed js";
    };
};

$doit->('http', $server->{port});

done_testing;
