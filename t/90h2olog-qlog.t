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

my $h2olog_prog = "misc/h2olog";
my $client_prog = bindir() . "/h2o-httpclient";
my $qlog_adapter = "./deps/quicly/misc/qlog-adapter.py";

plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tempdir = tempdir(CLEANUP => 1);
my $qlog_dir = $ENV{TEST_QLOG_DIR} || $tempdir;
make_path($qlog_dir);

sub spawn_h2o_with_quic {
  my ($h2olog_args, $logfile) = @_;

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
  my $server = spawn_h2o_with_quic();

  my $h2olog2_output_file = "$qlog_dir/h2olog2.json";
  system("$h2olog_prog -u $tempdir/h2olog.sock > $h2olog2_output_file &");

  my ($headers, $body) = run_prog("$client_prog -3 100 https://127.0.0.1:$server->{quic_port}/halfdome.jpg");
  like $headers, qr{^HTTP/3 200\n}m, "req: HTTP/3";

  diag "shutting down h2o and h2olog ...";
  undef $server;
  diag "done";

  my $h2olog2_qlog = `$qlog_adapter < $h2olog2_output_file | tee $qlog_dir/h2olog2-qlog.json`;

  my $h2olog2_qlog_obj = eval { decode_json($h2olog2_qlog) } or diag($@, $h2olog2_qlog);
};

done_testing();
