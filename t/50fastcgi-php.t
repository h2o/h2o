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
plan skip_all => 'php-cgi not found'
    unless prog_exists('php-cgi');

# spawn h2o
my $server = spawn_h2o(<< "EOT");
file.custom-handler:
  extension: .php
  fastcgi.spawn: "exec php-cgi"
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT

my $resp = `curl --silent http://127.0.0.1:$server->{port}/index.txt`;
is $resp, "hello\n", 'ordinary file';

my $resp = `curl --silent http://127.0.0.1:$server->{port}/hello.php`;
is $resp, 'hello world', 'php';

done_testing();
