use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $tls_port = empty_port();
my $RAW_CERT_OPT = "-r examples/h2o/server.pub";
my $re_ok = qr{HTTP/1\.1 200 OK\r};
my $re_bad_cert = qr{ptls_handshake:299};

subtest "x509 server" => sub {
    my $server = start_server(1, 0);
    like run_client(""), $re_ok, "client(x509) -> ok";
    like run_client($RAW_CERT_OPT), $re_bad_cert, "client(raw) -> bad_cert";
};

subtest "raw server" => sub {
    my $server = start_server(0, 1);
    like run_client(""), $re_bad_cert, "client(raw) -> bad_cert";
    like run_client($RAW_CERT_OPT), $re_ok, "client(raw) -> ok";
};

subtest "hybrid server" => sub {
    my $server = start_server(1, 1);
    like run_client(""), $re_ok, "client(raw) -> ok";
    like run_client($RAW_CERT_OPT), $re_ok, "client(raw) -> ok";
};

sub start_server {
    my ($use_cert, $use_raw) = @_;

    my $conf = <<"EOT";
hosts:
  "default":
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
num-threads: 1
listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    @{[$use_cert ? "certificate-file: examples/h2o/server.crt" : ""]}
    @{[$use_raw ? "raw-pubkey-file: examples/h2o/server.pub" : ""]}
EOT
    my $server = spawn_h2o_raw($conf, [ $tls_port ]);
}

sub run_client {
    my $opts = shift;
    my $cmd = "exec @{[bindir]}/picotls/cli $opts 127.0.0.1 $tls_port > $tempdir/resp.txt 2>&1";
    open my $fh, "|-", $cmd
        or die "failed to invoke command:$cmd:$!";
    autoflush $fh 1;
    print $fh <<"EOT";
GET / HTTP/1.1\r
Host: 127.0.0.1:$tls_port\r
Connection: close\r
\r
EOT
    sleep 1;
    close $fh;
    open $fh, "<", "$tempdir/resp.txt"
        or die "failed to open file:$tempdir/resp.txt:$!";
    do { local $/; <$fh> };
}
