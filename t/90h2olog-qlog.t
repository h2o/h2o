#!perl
# DTRACE_TESTS=1 to skip to check prereqisites
# TEST_DEBUG=1 for more logs
# TEST_QLOG_DIR=<dir> to save qlogs to <dir>
#   h2olog1-qlog.json - the output of h2olog v1
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
  h2olog:
    h2olog: appdata
    listen:
      type: unix
      port: $tempdir/h2olog.sock
    paths: {}
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
  # h2olog and h2olog2 can attach an h2o process at the same time,
  # so they do to compare their outputs.
  # The raw outputs are not the same, though. qlog-converted ones must be equivalent.
  my $server = spawn_h2o_with_quic();

  # h2olog v2
  my $h2olog2_output_file = "$qlog_dir/h2olog2.json";
  system("$h2olog_prog -u $tempdir/h2olog.sock > $h2olog2_output_file &");

  # h2olog v1
  my $tracer = H2ologTracer->new({
    pid => $server->{pid},
    args => [],
    output_dir => $qlog_dir,
  });

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/halfdome.jpg");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";
  my $h2olog1_output_file = $tracer->{output_file};

  diag "shutting down h2o and h2olog ...";
  undef $server;
  undef $tracer;
  diag "done";

  my $h2olog1_qlog = `$qlog_adapter < $h2olog1_output_file | tee $qlog_dir/h2olog1-qlog.json`;
  my $h2olog2_qlog = `$qlog_adapter < $h2olog2_output_file | tee $qlog_dir/h2olog2-qlog.json`;

  my $h2olog1_qlog_obj = eval { decode_json($h2olog1_qlog) } or diag($@, $h2olog1_qlog);
  my $h2olog2_qlog_obj = eval { decode_json($h2olog2_qlog) } or diag($@, $h2olog2_qlog);

  is_deeply $h2olog1_qlog_obj, $h2olog2_qlog_obj, "h2olog v1 and v2 outputs are equivalent";
};

done_testing();
