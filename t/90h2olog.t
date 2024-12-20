#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use Carp;
use File::Temp qw(tempdir);
use Test::More;
use JSON;
use Socket qw(SOCK_STREAM);
use t::Util;

my $h2olog_prog = "misc/h2olog";
my $client_prog = bindir() . "/h2o-httpclient";

plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $h2olog_socket = "$tempdir/h2olog.sock";

my $server = spawn_h2o({
    opts => [qw(--mode=worker)],
    conf => << "EOT",
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
      "/status":
        status: ON
  h2olog:
    h2olog: appdata
    listen:
      - type: unix
        port: $h2olog_socket
    paths: {}
EOT
});

subtest "h2olog", sub {
  my $tracer = H2ologTracer->new({
    path => $h2olog_socket,
    args => [],
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  my $trace;
  until (($trace .= $tracer->get_trace()) =~ m{"h3s_destroy".*"module":"picotls","type":"free"}s) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  # we assume that the last line being read is NOT partial; if it is partial, decode_json fails
  my @events = map { decode_json($_) } split /\n/, $trace;
  is scalar(grep { $_->{type} && $_->{tid} && $_->{time} } @events), scalar(@events), "each event has type, tid, and time";

  my($h3s_accept) = grep { $_->{type} eq "h3s_accept" } @events;
  ok is_uuidv4($h3s_accept->{conn_uuid}), "h3s_accept has a UUIDv4 field `conn_uuid`"
};

subtest "h2olog -t", sub {
  my $tracer = H2ologTracer->new({
    path => $h2olog_socket,
    args => [
      "-t", "h2o:send_response_header",
      "-t", "h2o:receive_request_header",
      "-t", "h2o:h3s_destroy",
    ],
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  my $trace;
  until (($trace .= $tracer->get_trace()) =~ m{"h3s_destroy"}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  my %group_by;
  foreach my $event (map { decode_json($_) } split /\n/, $trace) {
    $group_by{$event->{"type"}}++;
  }

  is_deeply [sort keys %group_by], [sort qw(h3s_destroy send_response_header receive_request_header)];
};

subtest "h2olog -H", sub {
  my $tracer = H2ologTracer->new({
    path => $h2olog_socket,
    args => ["-H"],
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  my $trace;
  until (($trace .= $tracer->get_trace()) =~ m{\bRxProtocol\b}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  like $trace, qr{\bRxProtocol\s+HTTP/3.0\b};
  like $trace, qr{\bTxStatus\s+200\b};
};

subtest "multi clients", sub {
  my @tracers;

  for (1 .. 5) {
    my $tracer = H2ologTracer->new({
      path => $h2olog_socket,
    });
    push @tracers, $tracer;
  }

  system($client_prog, "-3", "100", "https://127.0.0.1:$server->{quic_port}/");

  my @logs;
  for my $tracer(@tracers) {
    my $logs = '';
    until (($logs .= $tracer->get_trace()) =~ m{"type":"h3s_destroy".*"module":"picotls","type":"free"}s) {}
    # Removes first some lines until HTTP/3 has been started.
    # THis is because connecting h2olog produces a "h2o:receive_request" and some succeeding events.
    push @logs, $logs =~ s/\A.+?"module":"picotls","type":"new"[^\n]+//xmsr;
  }

  for (my $i = 1; $i < @tracers; $i++) {
    if ($logs[$i] ne $logs[0]) {
      fail "The outputs of multiple h2olog clients differ in #0 vs #$i";
      system("diff -U10 $tracers[0]->{output_file} $tracers[$i]->{output_file}");
      next;
    }
    cmp_ok length($logs[$i]), ">", 0, "The logs of #$i is not empty";
    is $logs[$i], $logs[0], "same logs (#0 vs #$i)";
  }
};

cmp_ok get_status($server)->{"h2olog.lost"}, "==", 0, "did not lose messages";

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

subtest "lost messages", sub {
  my $server = spawn_h2o({ conf => <<"EOT" });
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

  # A client connects to h2o's h2olog endpoint, but reads nothing.
  my $client = IO::Socket::UNIX->new(
    Type => SOCK_STREAM,
    Peer => $h2olog_socket,
  ) or croak "Cannot connect to a unix domain socket '$h2olog_socket': $!";
  $client->syswrite("GET /.well-known/h2olog HTTP/1.0\r\n\r\n");

  system($client_prog, "-3", "100", "https://127.0.0.1:$server->{quic_port}/") == 0 or die $!;

  cmp_ok get_status($server)->{"h2olog.lost"}, ">", 0, "losts messages if client does not read socket";
};

done_testing();

sub is_uuidv4 {
  my($s) = @_;

  # sited from https://stackoverflow.com/a/19989922/805246
  $s =~ /\A[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\z/i;
}

sub get_status {
  my ($server) = @_;
  my $status_json = `$client_prog http://127.0.0.1:$server->{port}/status/json`;
  if (!$status_json) {
    BAIL_OUT "h2o does not respond to /status/json";
  }
  return decode_json($status_json);
}
