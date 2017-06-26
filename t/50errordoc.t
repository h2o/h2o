use strict;
use warnings;
use Test::More;
use Test::Exception;
use t::Util;

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
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, $expected, "content";
        $resp = `$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
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

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, "not found", "content";
        $resp = `$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
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
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, $expected, "content";
        $resp = `$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
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

    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404\s}s, "status";
    });
};

subtest 'multi-status-error' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  - status: [404, 405]
    url: /404.html
EOT

    my $expected = do {
        open my $fh, '<', "@{[DOC_ROOT]}/404.html"
            or die "failed to read file:@{[DOC_ROOT]}/404.html:$!";
        local $/;
        <$fh>;
    };
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/nonexist`;
        is $resp, $expected, "content";
        $resp = `$curl --silent --dump-header /dev/stderr $proto://127.0.0.1:$port/nonexist 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 404\s}s, "status";
    });
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent -X POST $proto://127.0.0.1:$port/index.txt`;
        is $resp, $expected, "content";
        $resp = `$curl --silent --dump-header /dev/stderr -X POST $proto://127.0.0.1:$port/index.txt 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]+ 405\s}s, "status";
    });
};

subtest "empty status" => sub {
    throws_ok sub {
        spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  - status: []
    url: /404.html
EOT
    }, qr/server failed to start/, 'status must not be empty';
};

subtest "duplicated statuses" => sub {
    throws_ok sub {
        spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
error-doc:
  - status: [@{[ join(', ', (400 .. 599), 599) ]}]
    url: /error.html
EOT
    }, qr/server failed to start/, 'duplicated statuses';
};

done_testing;
