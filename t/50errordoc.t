use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'basic' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  status: 404
  url: /404.html
EOT

    my $expected = do {
        open my $fh, '<', "@{[DOC_ROOT]}/404.html"
            or die "failed to read file:@{[DOC_ROOT]}/404.html:$!";
        local $/;
        <$fh>;
    };
    my $doit = sub {
        my ($proto, $port) = @_;
        my $resp = `curl --silent --insecure $proto://127.0.0.1:$port/nonexist`;
        is $resp, $expected, "content";
        $resp = `curl --silent --insecure --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404 }s, "status";
        like $resp, qr{\r\ncontent-type: text/html.*\r\n}is, "content-type";
        like $resp, qr{\r\ncontent-length: @{[length $expected]}\r\n}is, "content-length";
        unlike $resp, qr{\r\nlast-modified: }is, "no last-modified";
        unlike $resp, qr{\r\etag: }is, "no etag";
    };

    subtest 'HTTP/1.1' => sub {
        subtest 'http' => sub {
            $doit->('http', $server->{port});
        };
        subtest 'https' => sub {
            $doit->('https', $server->{tls_port});
        };
    };
};

done_testing;
