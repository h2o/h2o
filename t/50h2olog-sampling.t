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

sub debug_socket_accept {
  my($trace) = @_;

  my @socket_accept_events = grep { /"type"\s*:\s*"socket-accept"/ } split /\n/, $trace;
  if (@socket_accept_events) {
    diag("socket-accept: ", @socket_accept_events);
  } else {
    diag("socket-accept: not found");
  }
}

subtest "h2olog -S=1.00", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-S", "1.0"],
  });
  subtest "TCP", sub {
    my ($headers) = run_prog("$client_prog http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200\b}, "req: HTTP/1";

    my $trace;
    until (($trace = $tracer->get_trace()) =~ /\n/) {}
    debug_socket_accept($trace);

    my @logs = map { decode_json($_) } split /\n/, $trace;
    my($event) = grep { $_->{type} eq "socket-accept" } @logs;

    is $event->{"info-sock-type"}, "SOCK_STREAM";
    like $event->{"info-src"}, qr/\A127\.0\.0\.1:\d+\z/, "source (remote) addr";
    is $event->{"info-dest"}, "127.0.0.1:$server->{port}", "destination (local) addr";
  };

  subtest "QUIC", sub {
    my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\b}, "req: HTTP/3";

    my $trace;
    until (($trace = $tracer->get_trace()) =~ /\n/) {}
    debug_socket_accept($trace);
    my @logs = map { decode_json($_) } split /\n/, $trace;
    my($event) = grep { $_->{type} eq "socket-accept" } @logs;

    like $event->{"info-src"}, qr/\A127\.0\.0\.1:\d+\z/, "destination (remote) addr";
    is $event->{"info-dest"}, "127.0.0.1:$quic_port", "source (local) addr";
  };
};

subtest "h2olog -S=0.00", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-S", "0.0"],
  });

  subtest "TCP", sub {
    my ($headers) = run_prog("$client_prog http://127.0.0.1:$server->{port}/");
    like $headers, qr{^HTTP/1\.1 200\b}, "req: HTTP/1";

    sleep(1);
    my $trace =  $tracer->get_trace();
    debug_socket_accept($trace);

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    is $trace, "", "nothing is emitted";
  };

  subtest "QUIC", sub {
    my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();
    debug_socket_accept($trace);

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
  };
};

subtest "multiple h2olog with sampling filters", sub {
  my $tracer1 = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-S", "0.0"],
  });
  my $tracer2 = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-S", "0.0"],
  });

  my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
  like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

  my($trace1, $trace2);
  until (($trace1 = $tracer1->get_trace()) =~ /\n/){}
  until (($trace2 = $tracer2->get_trace()) =~ /\n/){}

  diag "tracer1:", $trace1;
  diag "tracer2:", $trace2;

  pass "multiple tracers can attach to the same h2o process";
};

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

done_testing();
