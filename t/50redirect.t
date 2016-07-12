use strict;
use warnings;
use Test::More;
use t::Util;

subtest "basic" => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    my $curl = "curl --insecure";
    $curl .= " --http1.1"
        if curl_supports_http2();

    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        redirect: https://example.com/
      /abc/:
        redirect:
          status: 301
          url:    http://example.net/bar/
EOT

    my $doit = sub {
        my ($url, $expected_status, $expected_location) = @_;
        subtest $url => sub {
            my ($stderr, $stdout) = run_prog("$curl --silent --show-error --max-redirs 0 --dump-header /dev/stderr $url");
            like $stderr, qr{^HTTP/[^ ]+ $expected_status\s}s, "status";
            like $stderr, qr{^location: ?$expected_location\r$}im, "location";
        };
    };

    $doit->("http://127.0.0.1:$server->{port}/foo", 302, "https://example.com/foo");
    $doit->("https://127.0.0.1:$server->{tls_port}/foo", 302, "https://example.com/foo");
    $doit->("http://127.0.0.1:$server->{port}/abc/foo/baz", 301, "http://example.net/bar/foo/baz");
    $doit->("http://127.0.0.1:$server->{port}/abc/foo:baz", 301, "http://example.net/bar/foo:baz");
    $doit->("http://127.0.0.1:$server->{port}/foo?abc=def", 302, qr{https://example.com/foo\?abc=def});
    $doit->("http://127.0.0.1:$server->{port}/foo%0D%0Aa:1", 302, "https://example\.com/foo\%0d\%0aa:1");
};

subtest "trailing-slash" => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /p1:
        redirect: /dest
      /p2:
        redirect: /dest/
      /p3/:
        redirect: /dest
      /p4/:
        redirect: /dest/
EOT

    run_with_curl($server, sub {
        my ($proto, $port, $cmd) = @_;
        my $fetch = sub {
            my $path = shift;
            my ($stderr, $stdout) = run_prog("$cmd --silent --show-error --max-redirs 0 --dump-header /dev/stderr $proto://127.0.0.1:$port$path");
            $stderr;
        };
        subtest "p1" => sub {
            like $fetch->("/p1"), qr{^location:\s*/dest\r$}im;
            like $fetch->("/p12"), qr{^HTTP/\S*\s+404}is;
            like $fetch->("/p1?abc"), qr{^location:\s*/dest\?abc\r$}im;
            like $fetch->("/p1/"), qr{^location:\s*/dest/\r$}im;
            like $fetch->("/p1/abc"), qr{^location:\s*/dest/abc\r$}im;
        };
        subtest "p2" => sub {
            like $fetch->("/p2"), qr{^location:\s*/dest/\r$}im;
            like $fetch->("/p12"), qr{^HTTP/\S*\s+404}is;
            like $fetch->("/p2?abc"), qr{^location:\s*/dest/\?abc\r$}im;
            like $fetch->("/p2/"), qr{^location:\s*/dest/\r$}im;
            like $fetch->("/p2/abc"), qr{^location:\s*/dest/abc\r$}im;
        };
        subtest "p3" => sub {
            like $fetch->("/p3"), qr{^HTTP/\S*\s+404}is;
            like $fetch->("/p3/"), qr{^location:\s*/dest/\r$}im;
            like $fetch->("/p3/abc"), qr{^location:\s*/dest/abc\r$}im;
        };
        subtest "p4" => sub {
            like $fetch->("/p4"), qr{^HTTP/\S*\s+404}is;
            like $fetch->("/p4/"), qr{^location:\s*/dest/\r$}im;
            like $fetch->("/p4/abc"), qr{^location:\s*/dest/abc\r$}im;
        };
    });
};

done_testing;
