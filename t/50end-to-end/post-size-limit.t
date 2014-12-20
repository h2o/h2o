use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< 'EOT');
hosts:
  default:
    paths:
      /:
        file.dir: examples/doc_root
limit-request-body: 6
EOT

subtest 'http1' => sub {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    my $doit = sub {
        my ($proto, $port, $chunked) = @_;
        my $url = "$proto://127.0.0.1:$port/";
        my $extra = "";
        $extra .= " --insecure"
            if $proto eq 'https';
        $extra .= " --header 'Transfer-Encoding: chunked'"
            if $chunked;
        subtest "$proto, @{[ $chunked ? 'chunked' : 'content-length' ]}" => sub {
            my $resp = `curl --silent --dump-header /dev/stderr --data hello $extra $url 2>&1 > /dev/null`;
            like $resp, qr{^HTTP/1\.[0-9]+ 404 }s, 'shorter than the limit';
            $resp = `curl --silent --dump-header /dev/stderr --data helloworld $extra $url 2>&1 > /dev/null`;
            like $resp, qr{^HTTP/1\.[0-9]+ 413 }s, 'longer than the limit';
        };
    };
    $doit->("http", $server->{port});
    $doit->("http", $server->{port}, 1);
    $doit->("https", $server->{tls_port});
    $doit->("https", $server->{tls_port}, 1);
};

done_testing();
