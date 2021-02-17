#!perl
# DTRACE_TEST=1 to skip to check prereqisites except for OS
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

unless ($ENV{DTRACE_TEST})  {
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

# -F=1 connection sampling per second
subtest "h2olog -R=1.00", sub {
  my $t0 = time();
  my $trace = slurp_h2olog({
    pid => $server->{pid},
    # TODO: use -q (request-header filter; not yet implemented) as well as -t
    args => ["-R", "1.0", "-t", "h2o:receive_request_header", $ENV{H2OLOG_DEBUG} ? ("-d") : ()],

    request => sub {
      for (my $i = 1; $i <= 2; $i++) {
        my ($headers) = run_prog("$client_prog -H x-req-id:$i -3 https://127.0.0.1:$quic_port/");
        like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
      }
    },

    is_done => sub {
      my($partial) = @_;
      return( (time() - $t0) >= 5);
    },
  });

  if ($ENV{H2OLOG_DEBUG}) {
    diag "h2olog output:\n", $trace;
  }

  my @logs = grep {
      $_->{type} eq "receive-request-header" && $_->{name} eq "x-req-id"
    } map { decode_json($_) } split /\n/, $trace;
  diag explain(\@logs);
};


# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();
