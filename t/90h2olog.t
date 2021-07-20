#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use Net::EmptyPort qw(empty_port);
use Test::More;
use JSON;
use t::Util;

run_as_root();

my $h2olog_prog = bindir() . "/h2olog";
my $client_prog = bindir() . "/h2o-httpclient";

unless ($ENV{DTRACE_TESTS})  {
  plan skip_all => "$h2olog_prog not found"
      unless -e $h2olog_prog;

  plan skip_all => "$client_prog not found"
      unless -e $client_prog;

  plan skip_all => 'dtrace support is off'
      unless server_features()->{dtrace};
}

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o({
    opts => [qw(--mode=worker)],
    conf => << "EOT",
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
});

subtest "h2olog", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => [],
  });

  my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
  like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{"h3s-destroy"}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  my @events = map { decode_json($_) } split /\n/, $trace;
  is scalar(grep { $_->{type} && $_->{tid} && $_->{seq} } @events), scalar(@events), "each event has type, tid and seq";

  my($h3s_accept) = grep { $_->{type} eq "h3s-accept" } @events;
  ok is_uuidv4($h3s_accept->{"conn-uuid"}), "h3s-accept has a UUIDv4 field `conn-uuid`"
};

subtest "h2olog -t", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => [
      "-t", "h2o:send_response_header",
      "-t", "h2o:receive_request_header",
      "-t", "h2o:h3s_destroy",
    ],
  });

  my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
  like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{"h3s-destroy"}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  my %group_by;
  foreach my $event (map { decode_json($_) } split /\n/, $trace) {
    $group_by{$event->{"type"}}++;
  }

  is_deeply [sort keys %group_by], [sort qw(h3s-destroy send-response-header receive-request-header)];
};

subtest "h2olog -H", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-H"],
  });

  my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
  like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{\bRxProtocol\b}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  like $trace, qr{\bRxProtocol\s+HTTP/3.0\b};
  like $trace, qr{\bTxStatus\s+200\b};
};

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();

sub is_uuidv4 {
  my($s) = @_;

  # sited from https://stackoverflow.com/a/19989922/805246
  $s =~ /\A[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\z/i;
}
