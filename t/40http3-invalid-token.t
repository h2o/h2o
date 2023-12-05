use strict;
use warnings;
use JSON;
use Net::EmptyPort qw(wait_port);
use Test::More;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

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
      "/":
        file.dir: @{[ DOC_ROOT ]}
      "/server-status":
        status: ON
EOT

# Send initial packets with corrupted token
die "t/assets/http3/quic-invalid-token does not exist" unless (-e "t/assets/http3/quic-invalid-token");
system("perl", "t/udp-generator.pl", "127.0.0.1", "$quic_port", "t/assets/http3/quic-invalid-token") == 0 or die "Failed to launch udp-generator";

my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$server->{port}/server-status/json?show=events 2>&1 > /dev/null`;
my $jresp = decode_json("$resp");

my $num_processed = $jresp->{'quic.packet-processed'};
my $num_received = $jresp->{'quic.packet-received'};
is $num_received - $num_processed, 1, "identified invalid packet";

done_testing;
