use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

# Interop check of the QPACK encoder and decoder against nghttp3, using h2load over HTTP/3. h2load advertises a non-zero
# SETTINGS_QPACK_MAX_TABLE_CAPACITY (`--header-table-size`) and uses the dynamic table when encoding requests, so both directions
# exercise dynamic-table inserts. The access log counters are checked so that the test does not pass by not inserting at all.

plan skip_all => "h2load not found"
    unless prog_exists("h2load");

my $tempdir = tempdir(CLEANUP => 1);
my $access_log = "$tempdir/access.log";

my $server = spawn_h2o(<< "EOT");
access-log:
  path: $access_log
  format: "enc=%{http3.qpack.encoder-stats}x dec=%{http3.qpack.decoder-stats}x"
hosts:
  default:
    paths:
      "/":
        header.add: "x-interop-res: abcdefghijklmnopqrstuvwxyz"
        file.dir: @{[ DOC_ROOT ]}
EOT

my $out = `h2load --h3 -n 100 -c 2 -m 4 --header-table-size=4096 -H "x-interop-req: abcdefghijklmnopqrstuvwxyz" https://127.0.0.1:$server->{quic_port}/ 2>&1`;
plan skip_all => "h2load does not support HTTP/3"
    unless $out =~ /^UDP datagram:/m;
like $out, qr/^requests: 100 total, 100 started, 100 done, 100 succeeded, 0 failed, 0 errored, 0 timeout$/m, "all requests succeeded"
    or diag $out;

undef $server; # graceful shutdown flushes the access log

my $log = do {
    open my $fh, "<", $access_log
        or die "failed to open $access_log:$!";
    local $/;
    <$fh>;
};
like $log, qr/enc=\S*insert-with(?:out)?-name-reference=[1-9]/, "h2o encoder inserted into the dynamic table";
like $log, qr/enc=\S*dynamic-table-size-update=1\b/, "h2o encoder set the dynamic table capacity";
like $log, qr/dec=\S*insert-with(?:out)?-name-reference=[1-9]/, "h2o decoder received inserts from nghttp3";

done_testing;
