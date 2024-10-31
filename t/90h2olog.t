#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use File::Temp qw(tempdir);
use Test::More;
use JSON;
use t::Util;

my $h2olog_prog = "misc/h2olog";
my $client_prog = bindir() . "/h2o-httpclient";

unless ($ENV{DTRACE_TESTS})  {
  plan skip_all => "$client_prog not found"
      unless -e $client_prog;

  plan skip_all => 'dtrace support is off'
      unless server_features()->{dtrace};
}

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
  until (($trace .= $tracer->get_trace()) =~ m{h3s_destroy}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  my @events = map { decode_json($_) } split /\n/, $trace;
  is scalar(grep { $_->{type} } @events), scalar(@events), "each event has type (but tid and seq omitted by v2)";

  my($h3s_accept) = grep { $_->{type} eq "h3s_accept" } @events;
  ok is_uuidv4($h3s_accept->{conn_uuid}), "h3s_accept has a UUIDv4 field `conn_uuid`"
};

TODO: {
  local $TODO = "reenable after adding support for -t";

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
    until (($trace .= $tracer->get_trace()) =~ m{"h3s_destroy"}) {diag $trace}

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    my %group_by;
    foreach my $event (map { decode_json($_) } split /\n/, $trace) {
      $group_by{$event->{"type"}}++;
    }

    is_deeply [sort keys %group_by], [sort qw(h3s_destroy send_response_header receive_request_header)];
  };
}

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

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();

sub is_uuidv4 {
  my($s) = @_;

  # sited from https://stackoverflow.com/a/19989922/805246
  $s =~ /\A[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\z/i;
}
