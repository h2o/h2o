#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use Net::EmptyPort qw(empty_port);
use Test::More;
use JSON;
use t::Util;

plan skip_all => "h2olog is supported only for Linux"
    if $^O ne 'linux';

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
  my $trace = slurp_h2olog({
    pid => $server->{pid},
    args => [$ENV{H2OLOG_DEBUG} ? ("-d") : ()],

    request => sub {
      my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
      like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
      is $body, "hello\n", "req: body";
    },

    is_done => sub {
      my($partial_tace) = @_;

      # it has at least one line
      return $partial_tace =~ /\n/;
    },
  });

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  ok( (map { decode_json($_) } split /\n/, $trace), "h2olog output is valid JSON Lines");
};

subtest "h2olog -H", sub {
  my $trace = slurp_h2olog({
    pid => $server->{pid},
    args => ["-H", $ENV{H2OLOG_DEBUG} ? ("-d") : ()],

    request => sub {
      my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
      like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
      is $body, "hello\n", "req: body";
    },
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
