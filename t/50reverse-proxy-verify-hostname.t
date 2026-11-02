use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'openssl not found' unless prog_exists('openssl');
plan skip_all => 'curl not found' unless prog_exists('curl');

# The existing certificate has CN=localhost.examp1e.net, which must not match 127.0.0.1.
for my $version ('TLSv1.2', 'TLSv1.3') {
    subtest $version => sub {
        plan skip_all => 'openssl does not support TLS 1.3'
            if $version eq 'TLSv1.3' && !openssl_supports_tls13();

        my $upstream_port = empty_port();
        my $upstream = spawn_h2o_raw(<< "EOT", [$upstream_port]);
listen:
  port: $upstream_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    min-version: $version
    max-version: $version
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

        my $proxy_port = empty_port();
        my $proxy = spawn_h2o_raw(<< "EOT", [$proxy_port]);
listen:
  host: 127.0.0.1
  port: $proxy_port
proxy.ssl.cafile: misc/test-ca/root/ca.crt
proxy.ssl.session-cache: OFF
hosts:
  default:
    paths:
      /matching:
        proxy.reverse.url: https://localhost.examp1e.net:$upstream_port/
      /mismatched:
        proxy.reverse.url: https://127.0.0.1:$upstream_port/
      /no-verify:
        proxy.ssl.verify-peer: OFF
        proxy.reverse.url: https://127.0.0.1:$upstream_port/
EOT

        for my $case (
            ['matching', 200],
            ['mismatched', 502],
            ['no-verify', 200],
        ) {
            my ($path, $status) = @$case;
            my $resp = `curl --silent --show-error --noproxy '*' --max-time 10 --dump-header /dev/stdout http://127.0.0.1:$proxy_port/$path/index.txt`;
            is $?, 0, "$path request completed";
            like $resp, qr{^HTTP/1\.1 $status }, "$path status";
            if ($status == 502) {
                like $resp, qr{certificate name mismatch}, 'hostname verification rejected the certificate';
                unlike $resp, qr{^hello$}m, 'upstream response was not forwarded';
            } else {
                like $resp, qr{^hello$}m, "$path upstream response";
            }
        }
    };
}

done_testing();
