use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

# test scenario:
# 1. setup a server that responds after 5 seconds
# 2. establish a connection and send a request
# 3. initiate shutdown before the server responds
# 4. try to establish another connection, which should be rejected
# 5. check that we get the response for the first request

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
http3-graceful-shutdown-timeout: 60
hosts:
  default:
    paths:
      /:
        mruby.handler: |
          Proc.new do |env|
            sleep 5
            [200, {}, ["morning"]]
          end
EOT

wait_port({port => $quic_port, proto => 'udp'});

open my $client1, '-|', "$client_prog -3 100 https://127.0.0.1:$quic_port/ 2>&1"
    or die "failed to launch $client_prog:$?";
sleep 1;
kill 'TERM', $server->{pid};
sleep 1;
my $client2_timespent = time;
open my $client2, '-|', "$client_prog -3 100 https://127.0.0.1:$quic_port/ 2>&1"
    or die "failed to launch $client_prog:$?";
$client2_timespent = time - $client2_timespent;

like do { local $/; join "", <$client1>}, qr{^HTTP/[0-9\.]+ 200.*morning$}s, "client1 gets a response";
is do { local $/; join "", <$client2>}, "connection failure\n", "client2 fails to connect";
cmp_ok $client2_timespent, '<', 1, "client2 did not time out";

done_testing;
