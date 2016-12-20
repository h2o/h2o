use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;
use JSON;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'minimum' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    http2-debug-state: minimum
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $curl_cmd) = @_;
        $curl_cmd .= " --silent --show-error";
        my $url = "$proto://127.0.0.1:$port/.well-known/h2/state";

        if ($curl_cmd =~ /--http2/) {
            subtest "single stream itself" => sub {
                my ($headers, $body) = run_prog("$curl_cmd --dump-header /dev/stderr $url");
                like($headers, qr!^HTTP/2(\.0)? 200!);
                my $data;
                lives_ok { $data = decode_json($body) };
                is($data->{streams}->{1}->{state}, 'HALF_CLOSED_REMOTE');
            };
        } else {
            subtest "return_404_when_http1" => sub {
                my ($headers, $body) = run_prog("$curl_cmd --dump-header /dev/stderr $url");
                like($headers, qr!^HTTP/1.1 404!);
            };
        }
    });
};

subtest 'hpack' => sub {
    plan skip_all => "curl does not support HTTP/2"
        unless curl_supports_http2();

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    http2-debug-state: hpack
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    my ($proto, $port) = ('https', $server->{tls_port});
    my $curl_cmd = 'curl --insecure --http2 --silent --show-error --dump-header /dev/stderr';
    my $url = "$proto://127.0.0.1:$port/.well-known/h2/state";

    subtest "with hpack state" => sub {
        my ($headers, $body) = run_prog("$curl_cmd $url");
        like($headers, qr!^HTTP/2(\.0)? 200!);
        my $data;
        lives_ok { $data = decode_json($body) };
        ok(exists $data->{hpack});
    };
};

done_testing();
