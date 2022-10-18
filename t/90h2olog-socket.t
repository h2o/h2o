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
my $h2olog_prog = bindir() . "/h2olog";
plan skip_all => "$h2olog_prog not found" unless -e $h2olog_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $h2olog_socket = "$tempdir/h2olog.sock";
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});


subtest "read socket", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
h2olog:
  path: $h2olog_socket
  permission: 666
  appdata: ON
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

    my $tracer = H2ologTracer->new({
      path => $h2olog_socket,
    });

    system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/");

    my $logs = "";
    until (($logs .= $tracer->get_trace()) =~ m{"type":"h3s_destroy"}) {}

    diag($logs . "\nlength: " . length($logs)) if $ENV{TEST_DEBUG};

    my @events = parse_json_lines($logs) or fail("Invalid JSON lines from '$h2olog_socket' ($i)");

    my ($receive_request) = find_event(\@events, { module => "h2o", type => "receive_request" });
    is $receive_request->{http_version}, 768, "h2o:receive_request ($i)";

    # Test events to cover all the necessary usecases of ptlslog.
    # appdata are emitted as well by setting `h2olog-socket.appdata: ON`
    my (@req_headers) = find_event(\@events, { module => "h2o", type => "receive_request_header" });
    is $req_headers[0]->{name}, ":authority", ":authority";
    is $req_headers[0]->{value}, "127.0.0.1:$quic_port", ":authority value";

    is $req_headers[1]->{name}, ":method", ":method";
    is $req_headers[1]->{value}, "GET", ":method value";

    is $req_headers[2]->{name}, ":path", ":path";
    is $req_headers[2]->{value}, "/", ":path value";

    is $req_headers[3]->{name}, ":scheme", ":scheme";
    is $req_headers[3]->{value}, "https", ":scheme value";

    my ($send_response) = find_event(\@events, { module => "h2o", type => "send_response" });
    is $send_response->{status}, 200, "h2o:send_response ($i)";

    cmp_ok get_status($server)->{"h2olog.lost"}, "==", 0, "does not lost messages ($i)";
  }
};

subtest "lost messages", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
h2olog:
  path: $h2olog_socket
  permission: 666
  sndbuf: 512
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

  # use a hand-written client to read socket with timeouts.
  my $client = IO::Socket::UNIX->new(
      Type => SOCK_STREAM,
      Peer => $h2olog_socket,
  ) or croak "Cannot connect to a unix domain socket '$h2olog_socket': $!";

  system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/") == 0 or die $!;

  cmp_ok get_status($server)->{"h2olog.lost"}, ">", 0, "losts messages if client does not read socket";

  # make sure event lost does not break the output structure

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
  ok scalar(parse_json_lines($logs)), "valid JSON Lines are written to h2olog socket '$h2olog_socket' even if some events are lost";
};

sub find_event {
  my($rows, $matcher) = @_;

  my @results;
  ROW: for my $row (@$rows) {
    for my $key(keys %$matcher) {
      no warnings "uninitialized";
      next ROW if $row->{$key} ne $matcher->{$key};
    }
    push @results, $row;
  }
  return @results;
}

sub parse_json_lines {
  my ($json_lines) = @_;

  my @rows;
  for my $json_str (split /\n/, $json_lines) {
    if (my $row = eval { decode_json($json_str) }) {
      push @rows, $row;
    } else {
      diag "invalid json: $json_str\n$@";
      return;
    }
  }
  return @rows;
}


sub get_status {
  my ($server) = @_;
  my $status_json = `$client_prog http://127.0.0.1:$server->{port}/status/json`;
  if (!$status_json) {
    BAIL_OUT "h2o does not respond to /status/json";
  }
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
