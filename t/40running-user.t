use strict;
use warnings;
use Test::More;
use t::Util;

run_as_root();

plan skip_all => "user 'nobody' does not exist"
    unless defined getpwnam("nobody");

subtest "set-user" => sub {
    doit("nobody");
};

subtest "automatic fallback to nobody" => sub {
    doit('');
};

done_testing;

sub doit {
    my $user = shift;
    my $server = spawn_h2o({
      user => $user,
      conf => << "EOT",
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
    });

    my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/ 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1}s;
}
