#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
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

my $server = spawn_h2o({
    args => [qw(--mode=worker)],
    conf => << "EOT",
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

  my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$server->{quic_port}/");
  like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ m{"h3s-destroy"}) {}

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  my @events = map { decode_json($_) } split /\n/, $trace;
  is scalar(grep { $_->{type} && $_->{tid} && $_->{seq} } @events), scalar(@events), "each event has type, tid and seq";
};

subtest "h2olog -H", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-H"],
  });

  my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$server->{quic_port}/");
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
