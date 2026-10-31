use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};
plan skip_all => 'curl not found'
    unless prog_exists('curl');

# Tests that the HTTP/3 client opens a new connection when the number of concurrent requests reaches
# `proxy.http3.max-concurrent-streams`. Overlapping requests are sent to an upstream that is slow to respond, and the number of
# distinct connections is counted using the access log of the upstream.

my $tempdir = tempdir(CLEANUP => 1);

sub num_upstream_connections {
    my $max_concurrent_streams_conf = shift;

    my $upstream_port = empty_port({ host => "127.0.0.1", proto => "udp" });
    my $access_log = "$tempdir/access-log-" . ($max_concurrent_streams_conf ? "limited" : "default");
    my $upstream = spawn_h2o_raw(<< "EOT", [{host => "127.0.0.1", port => $upstream_port, proto => "udp"}]);
listen:
  type: quic
  host: 127.0.0.1
  port: $upstream_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
access-log:
  path: $access_log
  format: "%{connection-id}x"
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            sleep 1
            [200, {}, ["hello\\n"]]
          end
EOT

    # use one thread, as each thread has its own pool of connections to upstream
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
proxy.ssl.verify-peer: OFF
hosts:
  default:
    paths:
      /:
        proxy.reverse.url: https://127.0.0.1:$upstream_port
        proxy.http3.ratio: 100
$max_concurrent_streams_conf
EOT

    my @fhs = map {
        open my $fh, "-|", "curl --silent --show-error --dump-header /dev/stdout http://127.0.0.1:$server->{port}/ 2>&1"
            or die "failed to spawn curl:$!";
        $fh;
    } 1..3;
    for my $fh (@fhs) {
        my $resp = do { local $/; <$fh> };
        like $resp, qr{^HTTP/[^ ]* 200.*^hello$}msi, "response";
    }

    # requests are logged by upstream when disposed, which might happen after the response is received by the client
    my @lines;
    for (1..50) {
        open my $fh, "<", $access_log
            or die "failed to open $access_log:$!";
        @lines = <$fh>;
        last if @lines >= 3;
        sleep 0.1;
    }
    is scalar(@lines), 3, "all requests have reached upstream";
    my %conns = map { $_ => 1 } @lines;
    return scalar keys %conns;
}

is num_upstream_connections(""), 1, "requests share one connection by default";
is num_upstream_connections("        proxy.http3.max-concurrent-streams: 1"), 3, "one connection per request when limit is 1";

done_testing;
