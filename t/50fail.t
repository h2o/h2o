use strict;
use warnings;
use Test::More;
use t::Util;

my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        fail: 403
      /abc:
        fail: 500
EOT

sub doit {
    my ($url, $expected_status, $expected_reason) = @_;
    my ($stderr, $stdout) = run_prog("curl --silent --show-error --insecure --max-redirs 0 --dump-header /dev/stderr $url");
    like $stderr, qr{^HTTP/1\.1 $expected_status $expected_reason}s, "Status is $expected_status $expected_reason";
}

doit("http://127.0.0.1:$server->{port}/foo", 403, "Forbidden");
doit("http://127.0.0.1:$server->{port}/abc/foo", 500, "Internal Server Error");

done_testing;
