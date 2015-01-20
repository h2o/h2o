use strict;
use warnings;
use File::Temp qw(tempfile);
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
            like $resp, qr{^HTTP/1\.[0-9]+ 405 }s, 'shorter than the limit';
            $resp = `curl --silent --dump-header /dev/stderr --data helloworld $extra $url 2>&1 > /dev/null`;
            like $resp, qr{^HTTP/1\.[0-9]+ 413 }s, 'longer than the limit';
        };
    };
    $doit->("http", $server->{port});
    $doit->("http", $server->{port}, 1);
    $doit->("https", $server->{tls_port});
    $doit->("https", $server->{tls_port}, 1);
};

subtest 'http2' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');

    my $doit = sub {
        my ($proto, $port) = @_;
        my $url = "$proto://127.0.0.1:$port/";
        my $opts = '';
        $opts .= " -u"
            if $proto eq 'http';
        subtest $proto => sub {
            {
                my ($tempfh, $tempfn) = tempfile;
                print $tempfh 'hello';
                close $tempfh;
                my $resp = `nghttp -d $tempfn -s $url 2>&1`;
                like $resp, qr/^\s*status:\s*405\s*$/im, 'shorter than the limit';
            }
            {
                my ($tempfh, $tempfn) = tempfile;
                print $tempfh 'helloworld';
                close $tempfh;
                my $resp = `nghttp -v -d $tempfn -s $url 2>&1`;
                like $resp, qr/recv RST_STREAM[^\n]*\n[^\n]*error_code=REFUSED_STREAM/is, 'shorter than the limit';
            }
        };
    };
    $doit->("http", $server->{port});
    $doit->("https", $server->{tls_port});
};

done_testing();
