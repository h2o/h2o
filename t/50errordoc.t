use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');

sub run_tests {
    my ($server, $cb) = @_;
    subtest 'HTTP/1.1' => sub {
        subtest 'http' => sub {
            $cb->('http', '', $server->{port});
        };
        subtest 'https' => sub {
            $cb->('https', '--insecure', $server->{tls_port});
        };
    };
    subtest 'HTTP/2' => sub {
        plan skip_all => 'curl does not support HTTP/2'
            unless curl_supports_http2();
        $cb->('https', '--http2 --insecure', $server->{tls_port});
    };
}

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
    run_tests($server, sub {
        my ($proto, $opts, $port) = @_;
        my $resp = `curl $opts --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, $expected, "content";
        $resp = `curl $opts --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404\s}s, "status";
        like $resp, qr{\r\ncontent-type:\s*text/html.*\r\n}is, "content-type";
        like $resp, qr{\r\ncontent-length:\s*@{[length $expected]}\r\n}is, "content-length";
        unlike $resp, qr{\r\nlast-modified:}is, "no last-modified";
        unlike $resp, qr{\r\etag:}is, "no etag";
    });
};

subtest 'double-error' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  status: 404
  url: /nonexist
EOT

    run_tests($server, sub {
        my ($proto, $opts, $port) = @_;
        my $resp = `curl $opts --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, "not found", "content";
        $resp = `curl $opts --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404\s}s, "status";
        like $resp, qr{\r\ncontent-type:\s*text/plain.*\r\n}is, "content-type";
        like $resp, qr{\r\ncontent-length:\s*@{[length "not found"]}\r\n}is, "content-length";
        unlike $resp, qr{\r\nlast-modified:}is, "no last-modified";
        unlike $resp, qr{\r\etag:}is, "no etag";
    });
};

subtest 'redirect' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  status: 404
  url: /subdir
EOT

    my $expected = do {
        open my $fh, '<', "@{[DOC_ROOT]}/subdir/index.txt"
            or die "failed to read file:@{[DOC_ROOT]}/subdir/index.txt:$!";
        local $/;
        <$fh>;
    };
    run_tests($server, sub {
        my ($proto, $opts, $port) = @_;
        my $resp = `curl $opts --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, $expected, "content";
        $resp = `curl $opts --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404\s}s, "status";
        like $resp, qr{\r\ncontent-type:\s*text/plain.*\r\n}is, "content-type";
        like $resp, qr{\r\ncontent-length:\s*@{[length $expected]}\r\n}is, "content-length";
        unlike $resp, qr{\r\nlast-modified:}is, "no last-modified";
        unlike $resp, qr{\r\etag:}is, "no etag";
    });
};

subtest 'multi-error' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  - status: 404
    url: /404.html
  - status: 500
    url: /500.html
EOT

    run_tests($server, sub {
        my ($proto, $opts, $port) = @_;
        my $resp = `curl $opts --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404\s}s, "status";
    });
};

done_testing;
