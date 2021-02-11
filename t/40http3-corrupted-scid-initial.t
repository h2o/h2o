use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;

# Refer to 40http3-forward-initial.t for re-generating the input packets.
# quic-initial-w-corrupted-scid.bin needs a DCID based on node_id == 1.

plan skip_all => 'python3 not found'
    unless prog_exists('python3');

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
quic-nodes:
  self: 1
  mapping:
   1: "127.0.0.1:8443"
   2: "127.0.0.2:8443"
   3: "127.0.0.3:8443"
EOT

wait_port({port => $quic_port, proto => 'udp'});

# throw packets to h2o

# Throw decryptable Initial first, then second-flight Initial with corrupted SCID
# For the second packet, the correct behavior is to discard the packet.
system("python3", "t/udp-generator.py", "127.0.0.1", "$quic_port", "t/assets/quic-decryptable-initial.bin", "t/assets/quic-initial-w-corrupted-scid.bin") == 0 or die "Failed to launch udp-generator";

# make sure the server did not crash
my $port = $server->{port};
for my $i(1 .. 2) {
	sleep 1;
	ok system("curl -ksfL http://127.0.0.1:$port > /dev/null") == 0, "server is alive ($i)";
}

# shutdown h2o
undef $server;

done_testing;
