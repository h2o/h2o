use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

subtest "fastcgi" => sub {
    my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
hosts:
  default:
    paths:
      "/":
        setenv:
          "FOO": "1"
        file.dir: @{[ DOC_ROOT ]}
EOT
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent $proto://127.0.0.1:$port/printenv.cgi`;
        like $resp, qr{^FOO:1$}im;
    });
};

done_testing();
