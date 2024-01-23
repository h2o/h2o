use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< "EOT");
header.set: "global1: one"
header.set: "global2: two"
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
  added:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
    header.set: "host3: three"
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    subtest "default" => sub {
        my ($headers, $body) = run_prog("$curl --dump-header /dev/stderr --silent --show-error -H 'Host: default' $proto://127.0.0.1:$port/");
        is $body, "hello\n", "body";
        like $headers, qr{\nglobal1:\s+one\r?\nglobal2:\s+two\r?\n}s, "headers";
    };
    subtest "added" => sub {
        my ($headers, $body) = run_prog("$curl --dump-header /dev/stderr --silent --show-error -H 'Host: added' $proto://127.0.0.1:$port/");
        is $body, "hello\n", "body";
        like $headers, qr{\nglobal1:\s+one\r?\nglobal2:\s+two\r?\nhost3:\s+three\r?\n}s, "headers";
    };
});

done_testing();
