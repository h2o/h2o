use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use IO::Select;
use Time::HiRes qw(time sleep);
use Net::EmptyPort qw(empty_port wait_port);
use JSON;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found" unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $probe_log = "$tempdir/probe-log";

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o({ conf => <<"EOT" });
probe-log: $probe_log
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  "*":
    paths:
      /:
        file.dir: examples/doc_root
EOT

wait_port({ port => $quic_port, proto => "udp" });

for my $i(1 ... 3) {
  diag $i;

  my $pid = fork;
  die "Cannot fork: $!" unless defined $pid;
  if ($pid == 0) {
    # child
    sleep 0.1;
    exec($client_prog, "-t", "3", "-3", "100", "https://127.0.0.1:$quic_port/");
    die "Cannot exec $client_prog: $!";
  }
  # parent
  my $client = IO::Socket::UNIX->new(
      Type => SOCK_STREAM(),
      Peer => $probe_log,
  ) or die "Cannot connect to a unix domain socket '$probe_log': $!";

  my $t0 = time();
  my $timeout = 2;
  my $select = IO::Select->new($client);
  my $logs = '';
  while ($select->can_read($timeout)) {
    $timeout -= time() - $t0;
    diag "timeout: $timeout";
    $client->sysread(my $buf, 4096) or last;
    $logs .= $buf;

    last if $timeout <= 0;
  }
  $client->close;

  diag($logs . "\nlength: " . length($logs)) if $ENV{TEST_DEBUG};

  ok $logs, "something is written to the probe log ($i)";
  # check if the logs are valid JSON-Lines
  for my $json (split /\n/, $logs) {
    unless (eval { decode_json($json) }) {
      fail "invalid json: $json\n$@";
    }
  }
}

done_testing;
