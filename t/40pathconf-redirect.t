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

sub doit {
    my ($proto, $port) = @_;
    my ($stderr, $stdout) = run_prog("curl --silent --show-error --insecure --max-redirs 0 --dump-header /dev/stderr $proto://127.0.0.1:$port/abc");
    like $stderr, qr{^HTTP/1\.1 301 .*}s, "is 301";
    like $stderr, qr{^location: /abc/\r$}im, "location header";
}

subtest 'http' => sub { doit('http', $server->{port}); };
subtest 'https' => sub { doit('https', $server->{tls_port}); };

done_testing;
