#!perl
# H2OLOG_DEBUG=1 for more runtime logs
use strict;
use warnings FATAL => "all";
use File::Temp qw(tempdir);
use Test::More;
use JSON;
use Time::HiRes qw(sleep);
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
# an attempt to reduce flakiness (at least that caused by there being many worker threads)
num-threads: 1
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

subtest "h2olog -S=1.00", sub {
  my $tracer = H2ologTracer->new({
    path => $h2olog_socket,
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
    ok scalar(grep { $_->{type} eq "h1_accept" } @logs), "h1-accept has been logged";
  };
  subtest "QUIC", sub {
    my ($headers) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
    like $headers, qr{^HTTP/3 200\b}, "req: HTTP/3";

    my $trace;
    until (($trace = $tracer->get_trace()) =~ /\n/) {}
    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }
    my @logs = map { decode_json($_) } split /\n/, $trace;
    ok scalar(grep { $_->{type} eq "h3s_accept" } @logs), "h3s-accept has been logged";
  };
};

subtest "h2olog -S=0.00", sub {
  my $tracer = H2ologTracer->new({
    path => $h2olog_socket,
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
    my ($headers) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
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
    path => $h2olog_socket,
    args => ["-A", "127.0.0.2"],
  });

  subtest "with non-matched IP address", sub {
    my ($headers) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
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

    diag $trace
        unless test_is_passing();
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
        $_->{type} eq "h1_accept"
      } @logs), 1, "h1-accept header in logs";

    is_deeply scalar(grep {
        $_->{type} eq "h1_close"
      } @logs), 1, "h1-close header in logs";

    diag $trace
        unless test_is_passing();
  };

};

subtest "h2olog -N=localhost.examp1e.net", sub {
  my $tracer = H2ologTracer->new({
    path => $h2olog_socket,
    args => ["-N", "localhost.examp1e.net"],
  });

  subtest "with non-matched domain name", sub {
    my ($headers) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    my @logs = map { decode_json($_) } split /\n/, $trace;

    is_deeply [
      grep {
        $_->{type} eq "h3s_accept"
      } @logs
    ], [], "no h3s-accept header in logs";

    is_deeply [
      grep {
        $_->{type} eq "h3s_destroy"
      } @logs
    ], [], "no h3s-destroy header in logs";
  };

  subtest "with matched domain name", sub {
    my ($headers) = run_prog("$client_prog -3 100 https://localhost.examp1e.net:$server->{quic_port}/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";

    sleep(1);
    my $trace = $tracer->get_trace();

    if ($ENV{H2OLOG_DEBUG}) {
      diag "h2olog output:\n", $trace;
    }

    my @logs = map { decode_json($_) } split /\n/, $trace;

    is_deeply scalar(grep {
        $_->{type} eq "h3s_accept"
      } @logs), 1, "h3s-accept header in logs";

    is_deeply scalar(grep {
        $_->{type} eq "h3s_destroy"
      } @logs), 1, "h3s-destroy header in logs";
  };
};
subtest "multiple h2olog with sampling filters", sub {
  my $tracer1 = H2ologTracer->new({
    path => $h2olog_socket,
    args => ["-S", "0.0"],
  });
  my $tracer2 = H2ologTracer->new({
    path => $h2olog_socket,
    args => ["-S", "0.0"],
  });

  my ($headers) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/");
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

diag "shutting down ...";
undef $server;

done_testing();
