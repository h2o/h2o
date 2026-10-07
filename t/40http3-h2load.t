use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

# Interop checks of the QPACK encoder and decoder against nghttp3, using h2load over HTTP/3. h2load advertises a non-zero
# SETTINGS_QPACK_MAX_TABLE_CAPACITY (`--header-table-size`) and uses the dynamic table when encoding requests, so both directions
# exercise dynamic-table inserts. The access log counters are checked so that the tests do not pass by not inserting at all.

plan skip_all => "h2load not found"
    unless prog_exists("h2load");
# h2load built without HTTP/3 accepts --h3 but does not use QUIC; only QUIC runs report UDP datagrams
plan skip_all => "h2load does not support HTTP/3"
    unless `h2load --h3 -n 1 https://127.0.0.1:1/ 2>&1` =~ /^UDP datagram:/m;

my $tempdir = tempdir(CLEANUP => 1);
my $access_log = "$tempdir/access.log";

subtest "interop" => sub {
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
    like $out, qr/^requests: 100 total, 100 started, 100 done, 100 succeeded, 0 failed, 0 errored, 0 timeout$/m,
        "all requests succeeded"
        or diag $out;

    undef $server; # graceful shutdown flushes the access log

    my $log = read_log();
    like $log, qr/enc=\S*insert-with(?:out)?-name-reference=[1-9]/, "h2o encoder inserted into the dynamic table";
    like $log, qr/enc=\S*dynamic-table-size-update=1\b/, "h2o encoder set the dynamic table capacity";
    like $log, qr/dec=\S*insert-with(?:out)?-name-reference=[1-9]/, "h2o decoder received inserts from nghttp3";
};

subtest "required insert count wraps" => sub {
    plan skip_all => "mruby is off"
        unless server_features()->{mruby};

    # With a 128-byte decoder table, MaxEntries is 4 and the Required Insert Count wraps every 8 inserts (RFC 9204 Section
    # 4.5.1.1). Refinement is driven to keep swapping by repeating the pattern of test_response_swap with rotating roles: the
    # first response of each 40-response cycle carries three headers, then the keeper repeats, then the newcomer replaces the
    # victim, which costs an insert and a Duplicate. Nothing else is indexed: the body has no known length, so no content-length
    # is sent, and the date is too large to fit in the table.
    unlink $access_log;
    my $server = spawn_h2o(<< "EOT");
send-server-name: OFF
access-log:
  path: $access_log
  format: "enc=%{http3.qpack.encoder-stats}x"
hosts:
  default:
    paths:
      "/":
        mruby.handler: |
          class Body
            def each
              yield "hello\\n"
            end
          end
          cnt = 0
          Proc.new do |env|
            names = ["x-a", "x-b", "x-c", "x-d", "x-e"]
            c, i = cnt / 40, cnt % 40
            cnt += 1
            keeper, victim, newcomer = names[c % 5], names[(c + 1) % 5], names[(c + 2) % 5]
            sent = i == 0 ? [keeper, victim, newcomer] : i <= 30 ? [keeper] : [newcomer]
            h = {"date" => "x" * 100}
            sent.each { |n| h[n] = n[2] * 20 }
            [200, h, Body.new]
          end
EOT

    my $out = `h2load --h3 -n 200 -c 1 -m 1 --header-table-size=128 https://127.0.0.1:$server->{quic_port}/ 2>&1`;
    like $out, qr/^requests: 200 total, 200 started, 200 done, 200 succeeded, 0 failed, 0 errored, 0 timeout$/m,
        "all requests succeeded"
        or diag $out;

    undef $server;

    # the counters are cumulative per connection, and there is only one connection; sum the inserts in the last line
    my ($last) = read_log() =~ /([^\n]*)\n\z/;
    my $inserts = 0;
    $inserts += $1
        while $last =~ /(?:insert-with-name-reference|insert-without-name-reference|duplicate)=(\d+)/g;
    cmp_ok $inserts, ">=", 8, "the Required Insert Count reached FullRange (2 * MaxEntries)";
};

done_testing;

sub read_log {
    open my $fh, "<", $access_log
        or die "failed to open $access_log:$!";
    local $/;
    <$fh>;
}
