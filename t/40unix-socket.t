use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'nc -U not found'
    unless prog_exists('nc') and `nc -h 2>&1` =~ /-U\t+Use UNIX domain socket/;

my $tempdir = tempdir(CLEANUP => 1);
my $sock_path = "$tempdir/h2o.sock";

my $server = spawn_h2o(<< "EOT");
listen:
  type: unix
  port: $sock_path
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT

my $resp = `(echo "GET / HTTP/1.0" ; echo) | nc -U $sock_path 2>&1`;
like $resp, qr{^HTTP/1\.[0-9]+ 200 OK\r\n}s;

done_testing;
