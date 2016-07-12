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

$resp = `curl --silent http://127.0.0.1:$server->{port}/hello.php`;
is $resp, 'hello world', 'php';

subtest 'server-push' => sub {
    plan skip_all => 'nghttp not found'
        unless prog_exists('nghttp');
    my $doit = sub {
        my ($proto, $port) = @_;
        my $resp = `nghttp -n --stat '$proto://127.0.0.1:$port/hello.php?link=<index.js>\%3b\%20rel=preload'`;
        like $resp, qr{\nid\s*responseEnd\s.*\s/index\.js\n.*\s/hello\.php\?}is, $proto;
    };
    $doit->('http', $server->{port});
    $doit->('https', $server->{tls_port});
};

subtest 'huge-headers' => sub {
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        my $resp = `$curl --silent --dump-header /dev/stderr --max-redirs 0 $proto://127.0.0.1:$port/issues/951.php 2>&1 > /dev/null`;
        like $resp, qr{^HTTP/[^ ]* 302 ?}is;
        like $resp, qr{^set-cookie: ?}im;
    });
};

done_testing();
