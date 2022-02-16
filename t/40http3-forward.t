use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use Time::HiRes qw(time);
use t::Util;
use JSON;

plan skip_all => 'mruby support is off'
    unless server_features()->{mruby};

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

plan skip_all => "macOS has issues https://twitter.com/kazuho/status/1298073110587949056"
    if $^O eq 'darwin';

# This test utilizes two properties of BSD socket:
#  * a port on a specific address can be bind(2)-ed after the same port on the ANY address in bound
#  * any address within 127.0.0.0/24 is a local address that a server can accept packets
#
# Therefore, the test steps are:
#  1. create a client that connects to the server listening at 0.0.0.0 and sends a request slowly
#  2. create a new server listening at 127.0.0.1, that will forward the packets of the slow request to the original server (that
#     can still receive packets at 127.0.0.2)
#  3. check that the slow request completes *after* the new server is up

my $quic_port = empty_port({ host  => "0.0.0.0", proto => "udp" });

# start server1 at 0.0.0.0, check that it is up
my $server1 = spawn("0.0.0.0", 1);
is do {my $fh = fetch(""); local $/; join "", <$fh> }, "server=1", "server1 is up";

# initiate the slow request
my $slow_fh = fetch("-b 1200 -c 20 -i 100");
sleep 1;

# start server2 at 127.0.0.1, check that it isup
my $server2 = spawn("127.0.0.1", 2);
is do {my $fh = fetch(""); local $/; join "", <$fh> }, "server=2", "server2 is up";

# check that the slow request was served, going through $server2
my $elapsed = time;
is do {local $/; join "", <$slow_fh>}, "server=1", "slow request succeeded";
$elapsed = time - $elapsed;
cmp_ok $elapsed, '>=', 3, "slow request is so slow that the packets should have gone through server2";

# check that some packets were actually forwarded, and the event counter captured them
my $server1_port = ${server1}->{port};
my $server2_port = ${server2}->{port};

my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:${server1_port}/server-status/json?show=events 2>&1 > /dev/null`;
my $jresp = decode_json("$resp");
my $num_forwarded_received = $jresp->{'http3.forwarded-packet-received'};

$resp = `curl --silent -o /dev/stderr http://127.0.0.1:${server2_port}/server-status/json?show=events 2>&1 > /dev/null`;
$jresp = decode_json("$resp");
my $num_forwarded = $jresp->{'http3.packet-forwarded'};

cmp_ok($num_forwarded, '>', 0, "some packets were forwarded");
is($num_forwarded, $num_forwarded_received, "packets forwarded == packets received");

done_testing;

sub spawn {
    my ($listen_ip, $server_id) = @_;
    my $conf = {opts => [qw(-m worker)], conf => <<"EOT"};
num-threads: 1
listen:
  type: quic
  host: $listen_ip
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
quic-nodes:
  self: $server_id
  mapping:
    1: "127.0.0.2:$quic_port" # server1 can be reached at 127.0.0.2 too
    2: "127.0.0.1:$quic_port"
ssl-session-resumption:
  mode: ticket
  ticket-store: file
  ticket-file: t/40session-ticket/forever_ticket.yaml
hosts:
  default:
    paths:
      "/":
        mruby.handler: |
          Proc.new do |env|
            [200, {}, ["server=$server_id"]]
          end
      "/server-status":
        status: ON
EOT
    spawn_h2o($conf);
}

sub fetch {
    my $opts = shift;
    open my $fh, "-|", "$client_prog -3 100 $opts https://127.0.0.1:$quic_port/ 2> /dev/null"
        or die "failed to spawn $client_prog:$!";
    $fh;
}
