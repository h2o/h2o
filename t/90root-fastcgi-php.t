# this test checks the behavior of `file.custom-handler` and `fastcgi.spawn`
use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'test requires root privileges'
    unless $< == 0;
plan skip_all => 'user: nobody does not exist'
    unless getpwnam 'nobody';
plan skip_all => 'user: daemon does not exist'
    unless getpwnam 'daemon';

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'php-cgi not found'
    unless prog_exists('php-cgi');

sub check_resp {
    my $port = shift;
    my $resp = `curl --silent http://127.0.0.1:$port/index.txt`;
    is $resp, "hello\n", 'ordinary file';
    $resp = `curl --silent http://127.0.0.1:$port/hello.php`;
    is $resp, 'hello world', 'php';
}

subtest 'user-in-global-conf' => sub {
    my $server = spawn_h2o(<< "EOT");
user: nobody
file.custom-handler:
  extension: .php
  fastcgi.spawn: "exec php-cgi"
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT
    check_resp($server->{port});
};

subtest 'user-in-fastcgi.spawn' => sub {
    my $server = spawn_h2o(<< "EOT");
user: nobody
file.custom-handler:
  extension: .php
  fastcgi.spawn:
    command: "exec php-cgi"
    user:    daemon
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT
    check_resp($server->{port});
};

subtest 'user-not-in-map-style-fastcgi.spawn' => sub {
    my $server = spawn_h2o(<< "EOT");
user: nobody
file.custom-handler:
  extension: .php
  fastcgi.spawn:
    command: "exec php-cgi"
hosts:
  default:
    paths:
      "/":
        file.dir: @{[ DOC_ROOT ]}
EOT
    check_resp($server->{port});
};

done_testing();
