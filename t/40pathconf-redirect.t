use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
      /abc:
        file.dir: @{[ DOC_ROOT ]}
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    my ($stderr, $stdout) = run_prog("$curl --silent --show-error --max-redirs 0 --dump-header /dev/stderr $proto://127.0.0.1:$port/abc");
    like $stderr, qr{^HTTP/[^ ]+ 301\s}s, "is 301";
    like $stderr, qr{^location: ?/abc/\r$}im, "location header";
});

done_testing;
