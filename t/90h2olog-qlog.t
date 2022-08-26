#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# TEST_DEBUG=1 for more logs
# TEST_QLOG_DIR=<dir> to save qlogs to <dir>
#   h2olog-qlog.json - the output of h2olog v1
#   h2olog2-qlog.json - the output of h2olog v2

use strict;
use warnings FATAL => "all";
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use JSON;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use t::Util;

get_exclusive_lock(); # take exclusive lock before sudo closes LOCKFD
run_as_root();

my $h2olog_prog = bindir() . "/h2olog";
my $client_prog = bindir() . "/h2o-httpclient";
my $qlog_adapter = "./deps/quicly/misc/qlog-adapter.py";

my $tempdir = tempdir(CLEANUP => 1);
my $qlog_dir = $ENV{TEST_QLOG_DIR} || $tempdir;
make_path($qlog_dir);


unless ($ENV{DTRACE_TESTS})  {
  plan skip_all => "$h2olog_prog not found"
      unless -e $h2olog_prog;

  plan skip_all => "$client_prog not found"
      unless -e $client_prog;
}

sub spawn_h2o_with_quic {
  my ($h2olog_args, $logfile) = @_;

  my $quic_port = empty_port({
      host  => "127.0.0.1",
      proto => "udp",
  });

  my $server = spawn_h2o({
  opts => [qw(--mode=worker)],
  user => scalar(getpwuid($ENV{SUDO_UID})),
  conf => << "EOT",
h2olog-socket:
  path: $tempdir/h2olog.sock
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

  wait_port({
    port => $quic_port,
    proto => "udp",
  });

  $server->{quic_port} = $quic_port;

  return $server;
}

subtest "h2olog to qlog", sub {
  my $server = spawn_h2o_with_quic();
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => [],
    output_dir => $qlog_dir,
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/halfdome.jpg");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  undef $server;

  is system("$qlog_adapter < $tracer->{output_file} > $qlog_dir/h2olog-qlog.json"), 0, "qlog-adapter can handle the logs";
};

subtest "h2olog (v2) to qlog", sub {
  my $server = spawn_h2o_with_quic();

  system("$h2olog_prog -u $tempdir/h2olog.sock > $qlog_dir/h2olog2.jsonl &");
  sleep 1;

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/halfdome.jpg");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  undef $server;

  is system("$qlog_adapter < $qlog_dir/h2olog2.jsonl > $qlog_dir/h2olog2-qlog.json"), 0, "qlog-adapter can handle the logs";
};

done_testing();
