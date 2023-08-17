use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;
use JSON;

# This test makes sure that h2o correctly handles HTTP/3 handshake timeout.

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $tcp_port = empty_port({
    host  => "127.0.0.1",
    proto => "tcp",
});

my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
  quic:
    # handshake timeout set to zero -- any QUIC connection will result in handshake timeout immediately
    handshake-timeout-rtt-multiplier: 0
listen:
  host: 127.0.0.1
  port: $tcp_port
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
EOT

wait_port({port => $quic_port, proto => 'udp'});

sub get_num_connections() {
	my $port = $server->{port};
	my $resp = `curl --silent -o /dev/stderr http://127.0.0.1:$port/server-status/json?show=main 2>&1 > /dev/null`;
	my $jresp = decode_json("$resp");;
	return $jresp->{'connections'};
}

# Try HTTP/3 connection (which will fail)
my $resp = `$client_prog -3 100 https://127.0.0.1:$quic_port 2>&1`;

# make sure the server did not crash, and the connection counter has been correctly adjusted
my $c = get_num_connections();
is $c, 1;

# shutdown h2o
undef $server;

done_testing;
