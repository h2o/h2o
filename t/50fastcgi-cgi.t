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

my $resp = `curl --silent http://127.0.0.1:$server->{port}/hello.cgi/world`;
is $resp, "Hello world";

done_testing();
