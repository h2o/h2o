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

# make sure the h2o_return map does not exist at first,
# but don't unlink it elsewhere to make sure `h2o_return` stuff works if the map already exists.
unlink("/sys/fs/bpf/h2o_return");

sub spawn_my_h2o {
  my($quic_port) = @_;
  return spawn_h2o({
    opts => [qw(--mode=worker)],
    user => getpwuid($ENV{SUDO_UID}),
    conf => << "EOT",
usdt-selective-tracing: ON
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
}

subtest "h2olog should be able to start when h2o has no `usdt-selective-tracing: ON`", sub {
  my $server = spawn_h2o(<<'EOT');
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => [],
  });

  my ($headers) = run_prog("$client_prog http://127.0.0.1:$server->{port}/");
  like $headers, qr{^HTTP/1\.1 200\b}, "req: HTTP/1";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ /\n/) {}
  pass "h2olog has startded successfully";
};


my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_my_h2o($quic_port);

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
    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }
    my @logs = map { decode_json($_) } split /\n/, $trace;
    ok scalar(grep { $_->{type} eq "h1-accept" } @logs), "h1-accept has been logged";
  };
  subtest "QUIC", sub {
    my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\b}, "req: HTTP/3";

    my $trace;
    until (($trace = $tracer->get_trace()) =~ /\n/) {}
    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }
    my @logs = map { decode_json($_) } split /\n/, $trace;
    ok scalar(grep { $_->{type} eq "h3s-accept" } @logs), "h3s-accept has been logged";
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

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    is $trace, "", "nothing has been logged";
  };

  subtest "QUIC", sub {
    my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();

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
    ], [], "no h3s-destroy header in logs";
  };
};

subtest "h2olog -A=127.0.0.2", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-A", "127.0.0.2"],
  });

  subtest "with non-matched IP address", sub {
    my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();

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
    ], [], "no h3s-destroy header in logs";
  };

  subtest "with matched IP address", sub {
    my ($headers) = `curl --interface 127.0.0.2 --head -sSf http://127.0.0.1:$server->{port}/`;
    like $headers, qr{^HTTP/1\.1 200\b}, "req: HTTP/1.1";

    sleep(1);
    my $trace = $tracer->get_trace();

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    my @logs = map { decode_json($_) } split /\n/, $trace;

    is_deeply scalar(grep {
        $_->{type} eq "h1-accept"
      } @logs), 1, "h1-accept header in logs";

    is_deeply scalar(grep {
        $_->{type} eq "h1-close"
      } @logs), 1, "h1-close header in logs";
  };
};

subtest "h2olog -N=localhost.examp1e.net", sub {
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-N", "localhost.examp1e.net"],
  });

  subtest "with non-matched domain name", sub {
    my ($headers) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();

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
    ], [], "no h3s-destroy header in logs";
  };

  subtest "with matched domain name", sub {
    my ($headers) = run_prog("$client_prog -3 https://localhost.examp1e.net:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    my @logs = map { decode_json($_) } split /\n/, $trace;

    is_deeply scalar(grep {
        $_->{type} eq "h3s-accept"
      } @logs), 1, "h3s-accept header in logs";

    is_deeply scalar(grep {
        $_->{type} eq "h3s-destroy"
      } @logs), 1, "h3s-destroy header in logs";
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

  if ($ENV{H2OLOG_DEBUG}) {
    diag "tracer1:", $trace1;
    diag "tracer2:", $trace2;
  }

  pass "multiple tracers can attach to the same h2o process";
};

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;

subtest "h2o_return exists", sub {
  ok -f "/sys/fs/bpf/h2o_return", "h2o_return does exist";

  my $server = spawn_my_h2o($quic_port);

  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => ["-S", "0.0"],
  });

  my ($headers) = run_prog("$client_prog -3 100 https://127.0.0.1:$quic_port/");
  like $headers, qr{^HTTP/3 200\b}, "req: HTTP/3";

  my $trace;
  until (($trace = $tracer->get_trace()) =~ /\n/) {}
  my @logs = map { decode_json($_) } split /\n/, $trace;

  is scalar(
    grep {
      $_->{type} eq "h3s-accept"
    } @logs
  ), 0, "no h3s-accept header in logs";
};

done_testing();
