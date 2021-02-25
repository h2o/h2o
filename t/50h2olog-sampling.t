#!perl
# DTRACE_TEST=1 to skip to check prereqisites except for OS
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use Net::EmptyPort qw(empty_port);
use Test::More;
use JSON;
use Time::HiRes qw(sleep);
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

diag "quic port: $quic_port / port: $server->{port} / tls port: $server->{tls_port}";

subtest "h2olog -S=0.00", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-S", "0.0"],
  });

  subtest "HTTP/1", sub {
    my ($headers) = run_prog("$client_prog -H x-req-id:42 http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200\b}, "req: HTTP/1";

    my $t0 = time();
    my $timeout = 2;
    my $trace;
    until ($trace = $tracer->get_trace()) {
      Time::HiRes::sleep(0.1);

      if ((time() - $t0) > $timeout) {
        last;
      }
    }

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    pass "nothing is emitted";
  };

  subtest "HTTP/3", sub {
    my ($headers) = run_prog("$client_prog -H x-req-id:42 -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(0.5);
    my $trace;
    until ($trace = $tracer->get_trace()) {}

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    my @logs = map { decode_json($_) } split /\n/, $trace;

    is_deeply [
      grep {
        $_->{type} eq "h3s-accept"
      } @logs
    ], [], "no h3s-accept header in logs";

    is_deeply [
      grep {
        $_->{type} eq "h3s-destroy"
      } @logs
    ], [], "no stream-on-destroy header in logs";

    is_deeply [
      grep {
        $_->{type} eq "receive-request-header" && $_->{name} eq "x-req-id"
      } @logs
    ], [], "no x-req-id header in logs";
  };
};


# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();
