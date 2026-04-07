use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use Net::EmptyPort qw(wait_port);
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $doc_root = "$tempdir/doc_root";
mkdir $doc_root
    or die "failed to create $doc_root:$!";
open my $fh, ">", "$doc_root/index.txt"
    or die "failed to create $doc_root/index.txt:$!";
print {$fh} "." x (5 * 1024 * 1024);
close $fh;

my $quic_port = empty_port({
    host  => "0.0.0.0",
    proto => "udp",
});

my $conf = << "EOT";
access-log:
  format: "%{http3.quic-stats}x"
  path: "$tempdir/access_log"
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: $doc_root
EOT

my $server = spawn_h2o($conf);
wait_port({port => $quic_port, proto => "udp"});

my $resp = `$client_prog -3 100 -k https://127.0.0.1:$quic_port/index.txt 2>&1`;
like $resp, qr{^HTTP/3 200\b}ms, "http/3 is ok";

sleep 0.1;

open my $logfh, "<", "$tempdir/access_log"
    or die "failed to open $tempdir/access_log:$!";
my @lines = <$logfh>;
is scalar(@lines), 1, "one access log line";
like $lines[0], qr{(?:^|,)num-paths\.ecn-validated=[1-9][0-9]*(?:,|$)}, "ecn validation succeeded";

done_testing;
