# this test checks the behavior of `file.custom-handler` and `fastcgi.spawn`
use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
eval q{use CGI; 1}
    or plan skip_all => 'CGI.pm not found';

# spawn h2o
my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: .cgi
  fastcgi.spawn: "exec \$H2O_ROOT/share/h2o/fastcgi-cgi"
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

run_with_curl($server, sub {
    my ($proto, $port, $curl) = @_;
    my $resp = `$curl --silent $proto://127.0.0.1:$port/hello.cgi?name=world`;
    is $resp, "Hello world", "GET";
    $resp = `$curl --silent -F name=world $proto://127.0.0.1:$port/hello.cgi`;
    is $resp, "Hello world", "POST";
});

done_testing();
