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
        my ($stderr, $stdout) = run_prog("$curl --dump-header /dev/stdout --silent --show-error -H 'Host: default' $proto://127.0.0.1:$port/");
        like $stdout, qr{\nglobal1:\s+one\r?\nglobal2:\s+two\r?\n.*\r?\nhello\n$}s;
    };
    subtest "added" => sub {
        my ($stderr, $stdout) = run_prog("$curl --dump-header /dev/stdout --silent --show-error -H 'Host: added' $proto://127.0.0.1:$port/");
        like $stdout, qr{\nglobal1:\s+one\r?\nglobal2:\s+two\r?\nhost3:\s+three.*\r?\nhello\n$}s;
    };
});

done_testing();
