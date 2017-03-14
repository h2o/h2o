use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'root-redirect' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /abc:
        file.dir: @{[ DOC_ROOT ]}
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my ($stderr, $stdout) = run_prog("$curl --silent --show-error --max-redirs 0 --dump-header /dev/stderr $proto://127.0.0.1:$port/abc");
        like $stderr, qr{^HTTP/[^ ]+ 301\s}s, "is 301";
        like $stderr, qr{^location: ?/abc/\r$}im, "location header";
    });
};

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

subtest 'send-compressed' => sub {
    my $doit = sub {
        my ($send_compressed, $curl_opts, $paths, $expected_length) = @_;
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
@{[ $send_compressed ? "file.send-compressed: $send_compressed" : "" ]}
EOT
        my $fetch = sub {
            my $path = shift;
            subtest "send-compressed:@{[ $send_compressed || q(default) ]}, $curl_opts, $path" => sub {
                my $resp = `curl --silent --dump-header /dev/stderr $curl_opts http://127.0.0.1:$server->{port}$path 2>&1 > /dev/null`;
                if ($send_compressed ne 'gunzip') {
                    like $resp, qr/^content-length:\s*$expected_length\r$/im, "length is as expected";
                }
                if ($send_compressed eq 'ON' || $send_compressed eq 'gunzip') {
                    like $resp, qr/^vary:\s*accept-encoding\r$/im, "has vary set";
                } else {
                    unlike $resp, qr/^vary:\s*accept-encoding\r$/im, "not has vary set";
                }
            };
        };
        $fetch->($_) for @$paths;
    };

    my $index_orig_len = (stat 't/assets/doc_root/index.txt')[7];
    my $index_gz_len = (stat 't/assets/doc_root/index.txt.gz')[7];
    my $index_br_len = (stat 't/assets/doc_root/index.txt.br')[7];
    my $alice2_orig_len = `gzip -cd < t/assets/doc_root/alice2.txt.gz | wc -c`;
    my $alice2_gz_len = (stat 't/assets/doc_root/alice2.txt.gz')[7];

    $doit->("", "", ['/index.txt', '/'], $index_orig_len);
    $doit->("", q{--header "Accept-Encoding: gzip"}, ['/index.txt', '/'], $index_orig_len);
    $doit->("OFF", q{--header "Accept-Encoding: gzip"}, ['/index.txt', '/'], $index_orig_len);
    $doit->("OFF", q{--header "Accept-Encoding: br, gzip"}, ['/index.txt', '/'], $index_orig_len);

    $doit->("ON", "", ['/index.txt', '/'], $index_orig_len);
    $doit->("ON", q{--header "Accept-Encoding: gzip"}, ['/index.txt', '/'], $index_gz_len);
    $doit->("ON", q{--header "Accept-Encoding: gzip, deflate"}, ['/index.txt', '/'], $index_gz_len);
    $doit->("ON", q{--header "Accept-Encoding: deflate, gzip"}, ['/index.txt', '/'], $index_gz_len);
    $doit->("ON", q{--header "Accept-Encoding: deflate"}, ['/index.txt', '/'], $index_orig_len);
    $doit->("ON", q{--header "Accept-Encoding: br, gzip"}, ['/index.txt', '/'], $index_br_len);
    $doit->("ON", q{--header "Accept-Encoding: gzip, br"}, ['/index.txt', '/'], $index_br_len);
    $doit->("ON", q{--header "Accept-Encoding: br"}, ['/index.txt', '/'], $index_br_len);

    $doit->("gunzip", "", ['/alice2.txt'], $alice2_orig_len);
    $doit->("gunzip", q{--header "Accept-Encoding: gzip"}, ['/alice2.txt'], $alice2_gz_len);


    subtest 'MSIE-workaround' => sub {
        my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir:       t/assets/doc_root
        file.send-gzip: ON
EOT
        my $resp = `curl --silent --dump-header /dev/stderr --user-agent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" --header "Accept-Encoding: gzip" http://127.0.0.1:$server->{port}/ 2>&1 > /dev/null`;
        like $resp, qr/^content-length:\s*$index_gz_len\r$/im, "length is as expected";
        like $resp, qr/^cache-control:.*private.*\r$/im, "cache-control: private";
        unlike $resp, qr/^vary:/im, "no vary";
    };
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
        run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}$path");
    };

    my ($headers, $content) = $fetch->("/on/");
    like $headers, qr{^HTTP/1\.[0-9]+ 200 }s, "ON returns 200";
    unlike $content, qr{examples}, "result should not include internal info";
    ($headers, $content) = $fetch->("/off/");
    like $headers, qr{^HTTP/1\.[0-9]+ 403 }s, "OFF returns 403";
};

done_testing();
