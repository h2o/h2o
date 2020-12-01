#!perl
# DTRACE_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use Net::EmptyPort qw(empty_port);
use Test::More;
use JSON;
use t::Util;

plan skip_all => "h2olog is supported only for Linux"
    if $^O ne 'linux';

my $h2olog_prog = bindir() . "/h2olog";
plan skip_all => "$h2olog_prog not found"
    unless -e $h2olog_prog;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

plan skip_all => 'dtrace support is off'
    unless server_features()->{dtrace};

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
  my $tracer = spawn_h2olog({
    pid => $server->{pid},
    args => [$ENV{H2OLOG_DEBUG} ? ("-d") : ()],
  });

  my $trace = $tracer->get_trace(sub {
    my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
    is $body, "hello\n", "req: body";
  });

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  ok( (map { decode_json($_) } split /\n/, $trace), "h2olog output is valid JSON Lines");
};

subtest "h2olog -H", sub {
  my $tracer = spawn_h2olog({
    pid => $server->{pid},
    args => ["-H", $ENV{H2OLOG_DEBUG} ? ("-d") : ()],
  });

  my $trace = $tracer->get_trace(sub {
    my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
    is $body, "hello\n", "req: body";
  });

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  ok length($trace), "h2olog output exists"
};

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();
