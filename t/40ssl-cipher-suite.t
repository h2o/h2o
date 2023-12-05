use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port);
use Test::More;
use t::Util;

plan skip_all => "could not find openssl (1)"
    unless prog_exists("openssl");
plan skip_all => "no support for chacha20poly1305"
    unless grep { /^TLS_CHACHA20_POLY1305_SHA256$/m } split /:/, `openssl ciphers`;

my $tempdir = tempdir(CLEANUP => 1);
my $port = empty_port();

# spawn server that only accepts AES128-SHA (tls1.2), or CHACHA20POLY1305 -> AES128GCMSHA256 (tls1.3), see if appropriate cipher-
# suites are selected
subtest "select-cipher" => sub {
    my $server = spawn_h2o_raw(<< "EOT", [ $port ]);
listen:
  host: 127.0.0.1
  port: $port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    cipher-suite: AES128-SHA
    cipher-suite-tls1.3: [TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256]
    cipher-preference: server
    max-version: TLSv1.3
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    subtest "tls1.2" => sub {
        # connect to the server with AES256-SHA as the first choice, and check that AES128-SHA was selected
        my $log = run_openssl_client({ host => "127.0.0.1", port => $port, opts => "-tls1_2 -cipher AES256-SHA:AES128-SHA" });
        like $log, qr/^\s*Cipher\s*:\s*AES128-SHA\s*$/m;

        # connect to the server with AES256-SHA as the only choice, and check that handshake failure is returned
        $log = run_openssl_client({ host => "127.0.0.1", port => $port, opts => "-tls1_2 -cipher AES256-SHA" });
        like $log, qr/alert handshake failure/m; # "handshake failure" the official name for TLS alert 40
    };

    subtest "tls1.3" => sub {
        plan skip_all => "openssl does not support tls 1.3"
            unless openssl_supports_tls13();
        # TLS 1.3 test
        my $log = run_openssl_client({ host => "127.0.0.1", port => $port, opts => "-tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256" });
        like $log, qr/^\s*Cipher\s*:\s*TLS_CHACHA20_POLY1305_SHA256\s*$/m;

        $log = run_openssl_client({ host => "127.0.0.1", port => $port, opts => "-tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384" });
        unlike $log, qr/TLS_AES_256_GCM_SHA384/m;
    };
};

subtest "tls12-on-picotls" => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    my $doit = sub {
        my $ssl_offload = shift;

        for my $set (
            ["examples/h2o/server.key", "examples/h2o/server.crt", {
                    "ECDHE-RSA-AES128-GCM-SHA256" => 128,
                    "ECDHE-RSA-AES256-GCM-SHA384" => 256,
                    "ECDHE-RSA-CHACHA20-POLY1305" => 256,
            }],
            ["deps/picotls/t/assets/secp256r1/key.pem", "deps/picotls/t/assets/secp256r1/cert.pem", {
                "ECDHE-ECDSA-AES128-GCM-SHA256" => 128,
                "ECDHE-ECDSA-AES256-GCM-SHA384" => 256,
                "ECDHE-ECDSA-CHACHA20-POLY1305" => 256,
            }]) {
            my ($key_file, $cert_file, $ciphers) = @$set;
            my $server = spawn_h2o_raw(<< "EOT", [ $port ]);
listen:
  host: 127.0.0.1
  port: $port
  ssl:
    identity:
    - key-file: $key_file
      certificate-file: $cert_file
    cipher-suite: "@{[ join q(:), sort keys %$ciphers ]}"
    cipher-preference: server
    max-version: TLSv1.3
ssl-offload: $ssl_offload
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
access-log:
  path: $tempdir/access_log
  format: "%{ssl.protocol-version}x %{ssl.cipher}x %{ssl.cipher-bits}x %{ssl.backend}x"
EOT

            open my $logfh, "<", "$tempdir/access_log"
                or die "failed to open $tempdir/access_log:$!";
            for my $cipher (sort keys %$ciphers) {
                subtest $cipher => sub {
                    plan skip_all => "$cipher is unavailable"
                        unless do { `openssl ciphers | fgrep $cipher`; $? == 0 };
                    my $output = `curl --silent -k --tls-max 1.2 --ciphers $cipher https://127.0.0.1:$port/`;
                    is $output, "hello\n", "output";
                    sleep 1; # make sure log is emitted
                    sysread $logfh, my $log, 4096; # use sysread to avoid buffering that prevents us from reading what's being appended
                    like $log, qr/^TLSv1\.2 $cipher $ciphers->{$cipher} picotls$/m, "log";
                };
            }
        }
    };

    subtest "libcrypto" => sub {
        $doit->("off");
    };
    subtest "zerocopy" => sub {
        plan skip_all => "zerocopy not available"
            unless server_features()->{"ssl-zerocopy"};
        $doit->("zerocopy");
    };
    # add ktls when we add support for TLS/1.2?
};

subtest "tls12-rsa-pkcs1" => sub {
    my $server = spawn_h2o_raw(<< "EOT", [ $port ]);
listen:
  host: 127.0.0.1
  port: $port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    my $output = run_openssl_client({
        host => "127.0.0.1",
        port => $port,
        opts => "-no_tls1_3 -sigalgs RSA+SHA256",
        request => "GET / HTTP/1.0\r\n\r\n",
    });
    like $output, qr{\nHTTP/1\.1 200 OK.*\nhello\n}s;
};

done_testing;
