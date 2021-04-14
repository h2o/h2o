use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;
use JSON;

# Refer to 40http3-forward-initial.t for re-generating the input packets.
# quic-initial-w-corrupted-scid.bin and quic-initial-w-zerolen-scid.bin need a DCID based on node_id == 1.

my $tempdir = tempdir(CLEANUP => 1);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
ssl-session-resumption:
  mode: ticket
  ticket-store: file
  ticket-file: t/40session-ticket/forever_ticket.yaml
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
      "/server-status":
        status: ON

quic-nodes:
  self: 1
  mapping:
   1: "127.0.0.1:8443"
   2: "127.0.0.2:8443"
   3: "127.0.0.3:8443"
EOT

wait_port({port => $quic_port, proto => 'udp'});

# throw packets to h2o

# Test 1:
# Throw decryptable Initial first, then second-flight Initial with corrupted SCID
# For the second packet, the correct behavior is to discard the packet.
system("perl", "t/udp-generator.pl", "127.0.0.1", "$quic_port", "t/assets/quic-decryptable-initial.bin", "t/assets/quic-initial-w-corrupted-scid.bin") == 0 or die "Failed to launch udp-generator";

# make sure the server did not crash
my $port = $server->{port};
for my $i(1 .. 2) {
	sleep 1;
	ok system("curl -ksfL http://127.0.0.1:$port > /dev/null") == 0, "server is alive after getting an Initial with corrupted SCID ($i)";
}

sub get_num_connections() {
  my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$port/server-status/json?show=main 2>&1 > /dev/null`;
  my $jresp = decode_json("$resp");;
  return $jresp->{'connections'};
}

# one for curl, one for half-opened QUIC conenction by quic-decryptable-initial.bin above
ok get_num_connections() == 2, "Number of connections is two";

# Test 2:
# Throw Initial with h2o-issued (valid) DCID and zero-length SCID
system("perl", "t/udp-generator.pl", "127.0.0.1", "$quic_port", "t/assets/quic-initial-w-zerolen-scid.bin") == 0 or die "Failed to launch udp-generator";

for my $i(1 .. 2) {
	sleep 1;
	ok system("curl -ksfL http://127.0.0.1:$port > /dev/null") == 0, "server is alive after getting an Initial with zero-length SCID ($i)";
}

# packet from test 2 shall be dropped and should not affect connection count
ok get_num_connections() == 2, "Number of connections is still two";

# shutdown h2o
undef $server;

done_testing;
