use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use IO::Socket::UNIX;
use IO::Select;
use Time::HiRes qw(time sleep);
use Net::EmptyPort qw(empty_port wait_port);
use Carp;
use JSON;
use t::Util;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found" unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $h2olog_socket = "$tempdir/h2olog.sock";
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});


subtest "read socket", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
h2olog-socket:
  path: $h2olog_socket
  permission: 666
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
      "/status":
        status: ON
EOT

  wait_port({ port => $quic_port, proto => "udp" });


  for my $i(1 ... 3) {
    diag $i;

    my $pid = fork;
    die "Cannot fork: $!" unless defined $pid;
    if ($pid == 0) {
      # child
      sleep 0.1;
      exec($client_prog, "-t", "2", "-3", "100", "https://127.0.0.1:$quic_port/");
      die "Cannot exec $client_prog: $!";
    }
    # parent
    my $logs = slurp_h2olog_socket($h2olog_socket, { timeout => 2 });

    diag($logs . "\nlength: " . length($logs)) if $ENV{TEST_DEBUG};

    json_lines_ok($logs, "JSON Lines are written to h2olog socket '$h2olog_socket' ($i)");

    cmp_ok get_status($server)->{"h2olog.lost"}, "==", 0, "does not lost messages";
  }
};

subtest "lost messages", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
h2olog-socket:
  path: $h2olog_socket
  permission: 666
  sndbuf: 1024
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
      "/status":
        status: ON
EOT

  wait_port({ port => $quic_port, proto => "udp" });


  my $client = IO::Socket::UNIX->new(
      Type => SOCK_STREAM,
      Peer => $h2olog_socket,
  ) or croak "Cannot connect to a unix domain socket '$h2olog_socket': $!";
  # a client connects to h2olog socket, but does not read from the socket.

  system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/") == 0 or die $!;
  system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/") == 0 or die $!;
  system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/") == 0 or die $!;

  cmp_ok get_status($server)->{"h2olog.lost"}, ">", 0, "losts messages if client does not read socket";

  # make sure event lost does not break the socket buffer
  my $pid = fork;
  die "Cannot fork: $!" unless defined $pid;
  if ($pid == 0) {
    # child
    sleep 0.1;
    exec($client_prog, "-t", "2", "-3", "100", "https://127.0.0.1:$quic_port/");
    die "Cannot exec $client_prog: $!";
  }
  # parent
  my $logs = slurp_h2olog_socket($h2olog_socket, { timeout => 2 });
  json_lines_ok($logs, "valid JSON Lines are written to h2olog socket '$h2olog_socket' even if some events are lost");
};

sub json_lines_ok {
  my ($json_lines, $msg) = @_;

  ok length($json_lines) > 0, $msg;

  for my $json_str (split /\n/, $json_lines) {
    unless (eval { decode_json($json_str) }) {
      fail "invalid json: $json_str\n$@";
    }
  }
}


sub get_status {
  my ($server) = @_;
  my $status_json = `$client_prog http://127.0.0.1:$server->{port}/status/json`;
  return decode_json($status_json);
}

sub slurp_h2olog_socket {
  my($path, $opts) = @_;
  my $timeout = $opts->{timeout} or croak "timeout is not specified";

  my $client = IO::Socket::UNIX->new(
      Type => SOCK_STREAM,
      Peer => $path,
  ) or croak "Cannot connect to a unix domain socket '$path': $!";

  my $t0 = Time::HiRes::time();
  my $select = IO::Select->new($client);
  my $logs = '';
  while ($select->can_read($timeout)) {
    $timeout -= Time::HiRes::time() - $t0;
    diag "timeout remains: $timeout";
    $client->sysread(my $buf, 4096) or last;
    $logs .= $buf;

    last if $timeout <= 0;
  }
  $client->close;

  return $logs;
}

done_testing;
