use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;
use JSON;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $server = spawn_h2o(<< "EOT");
throttle-response: ON
hosts:
  default:
    debug-state: ON
    paths:
      /:
        mruby.handler: |
          proc {|env|
            [399, { "link" => "</halfdome.jpg>; rel=preload" }, [] ]
          }
        file.dir: @{[ DOC_ROOT ]}
        header.add: "X-Traffic: 100000"
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl_cmd) = @_;
    $curl_cmd .= " --silent --show-error";
    my $debug_state_url = "$proto://127.0.0.1:$port/.well-known/h2interop/state";

    if ($curl_cmd =~ /--http2/) {
        subtest "single stream itself" => sub {
            my ($headers, $body) = run_prog("$curl_cmd --dump-header /dev/stderr $debug_state_url");
            like($headers, qr!^HTTP/2 200!);
            my $data;
            lives_ok { $data = decode_json($body) };
            is($data->{streams}->{1}->{state}, 'OPEN');
        };
    } else {
        subtest "return_404_when_http1" => sub {
            my ($headers, $body) = run_prog("$curl_cmd --dump-header /dev/stderr $debug_state_url");
            like($headers, qr!^HTTP/1.1 404!);
        };
    }

});

done_testing();
