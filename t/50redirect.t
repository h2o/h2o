use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        redirect: https://example.com/
      /abc:
        redirect:
          status: 301
          url:    http://example.net/bar/
EOT

sub doit {
    my ($url, $expected_status, $expected_location) = @_;
    subtest $url => sub {
        my ($stderr, $stdout) = run_prog("curl --silent --show-error --insecure --max-redirs 0 --dump-header /dev/stderr $url");
        like $stderr, qr{^HTTP/[^ ]+ $expected_status\s}s, "status";
        like $stderr, qr{^location: ?$expected_location\r$}im, "location";
    };
}

doit("http://127.0.0.1:$server->{port}/foo", 302, "https://example.com/foo");
doit("https://127.0.0.1:$server->{tls_port}/foo", 302, "https://example.com/foo");
doit("http://127.0.0.1:$server->{port}/abc/foo/baz", 301, "http://example.net/bar/foo/baz");
doit("http://127.0.0.1:$server->{port}/foo?abc=def", 302, qr{https://example.com/foo\?abc=def});
doit("http://127.0.0.1:$server->{port}/foo%0D%0Aa:1", 302, "https://example\.com/foo\%0d\%0aa\%3a1");

done_testing;
