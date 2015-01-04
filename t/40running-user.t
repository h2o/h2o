use strict;
use warnings;
use English;
use Test::More;
use t::Util;

plan skip_all => "not running as root"
    if $UID != 0;
plan skip_all => "user 'nobody' does not exist"
    unless defined getpwnam("nobody");


subtest "set-user" => sub {
    doit(<< 'EOT');
user: nobody
EOT
};

subtest "automatic fallback to nobody" => sub {
    doit('');
};

done_testing;

sub doit {
    my $conf = shift;
    my $server = spawn_h2o(<< "EOT");
$conf
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

    my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/ 2>&1 > /dev/null`;
    like $resp, qr{^HTTP/1}s;
}
