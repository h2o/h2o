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

subtest "decoded section size limit" => sub {
    my $client_prog = bindir() . "/h2o-httpclient";
    plan skip_all => "$client_prog not found"
        unless -e $client_prog;
    for my $proto (qw(2 3)) {
        subtest "HTTP/$proto" => sub {
            my $port = $proto == 3 ? $server->{quic_port} : $server->{tls_port};
            my $get = sub {
                my $num_headers = shift;
                my $headers = join " ", map { "-H x-hpack-bomb-$_:@{['a' x 9000]}" } 1..$num_headers;
                return `$client_prog -k -$proto 100 $headers https://127.0.0.1:$port/ 2>&1`;
            };
            like $get->(40), qr{^HTTP/$proto 200\s*$}m, "request within the decoded size limit succeeds";
            my $resp = $get->(50);
            like $resp, qr{^HTTP/$proto 400\s*$}m, "request exceeding the decoded size limit fails";
            like $resp, qr{headers too long}, "soft error is reported";
        };
    }
};

undef $server;

done_testing;

sub get_with_headers {
    my $num_headers = shift;
    my $headers = join " ", map { "-H 'x-hpack-bomb-$_: v'" } 1..$num_headers;
    return run_prog("curl --http2 --insecure --silent --show-error --dump-header /dev/stderr $headers https://127.0.0.1:$server->{tls_port}/");
}
