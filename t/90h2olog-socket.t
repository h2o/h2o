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


subtest "h2olog via unix socket", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
listen:
  - type: quic
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
  "h2olog":
    h2olog: appdata
    listen:
      - type: unix
        port: $h2olog_socket
    paths: {}
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
    # appdata are emitted as well by setting either `h2olog.appdata: ON` or `h2olog -a`.
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

  subtest "multi clients", sub {
    my @tracers;

    for (1 .. 5) {
      my $tracer = H2ologTracer->new({
        path => $h2olog_socket,
      });
      push @tracers, $tracer;
    }

    system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/");

    my @logs;
    for my $tracer(@tracers) {
      my $logs = '';
      until (($logs .= $tracer->get_trace()) =~ m{"type":"h3s_destroy"}) {}
      # Removes first some lines until HTTP/3 has been started.
      # THis is because connecting h2olog produces a "h2o:receive_request" and some succeeding events.
      push @logs, $logs =~ s/\A.+?"module":"picotls","type":"new"[^\n]+//xmsr;
    }

    for (my $i = 1; $i < @tracers; $i++) {
      if ($logs[$i] ne $logs[0]) {
        fail "The outputs of multiple h2olog clients differ in #0 vs #$i";
        system("diff -U10 $tracers[0]->{output_file} $tracers[$i]->{output_file}") == 0;
        next;
      }
      cmp_ok length($logs[$i]), ">", 0, "The logs of #$i is not empty";
      is $logs[$i], $logs[0], "same logs (#0 vs #$i)";
    }
  };
};

subtest "lost messages", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
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
  "h2olog":
    h2olog: appdata
    listen:
      - type: unix
        port: $h2olog_socket
        # Set the min value (it's doubled. See socket(7)) to trigger the event lost
        sndbuf: 1024
    paths: {}
EOT

  wait_port({ port => $quic_port, proto => "udp" });


  # A client connects to h2o's h2olog endpoint, but reads nothing.
  my $client = IO::Socket::UNIX->new(
    Type => SOCK_STREAM,
    Peer => $h2olog_socket,
  ) or croak "Cannot connect to a unix domain socket '$h2olog_socket': $!";
  $client->syswrite("GET /.well-known/h2olog HTTP/1.0\r\n\r\n");

  system($client_prog, "-3", "100", "https://127.0.0.1:$quic_port/") == 0 or die $!;

  cmp_ok get_status($server)->{"h2olog.lost"}, ">", 0, "losts messages if client does not read socket";
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

done_testing;
