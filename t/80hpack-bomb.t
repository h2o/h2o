use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'curl does not support HTTP/2'
    unless curl_supports_http2();

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
EOT

subtest "decoded header count soft limit" => sub {
    my ($headers, $body) = get_with_headers(95);
    like $headers, qr{^HTTP/2 200\s*$}m, "request within the decoded header limit succeeds";

    ($headers, $body) = get_with_headers(101);
    like $headers, qr{^HTTP/2 400\s*$}m, "request exceeding the decoded header limit fails";
    like $body, qr{headers too long}, "soft error is reported";
};

undef $server;

done_testing;

sub get_with_headers {
    my $num_headers = shift;
    my $headers = join " ", map { "-H 'x-hpack-bomb-$_: v'" } 1..$num_headers;
    return run_prog("curl --http2 --insecure --silent --show-error --dump-header /dev/stderr $headers https://127.0.0.1:$server->{tls_port}/");
}
