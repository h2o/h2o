use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $tls_port = empty_port();
my $TLS_RAW_CERT_OPT = "-r examples/h2o/server.pub";
my $TLS_RE_OK = qr{HTTP/1\.1 200 OK\r};
my $TLS_RE_BAD_CERT = qr{ptls_handshake:299};
my $QUIC_RAW_CERT_OPT = "-W examples/h2o/server.pub";
my $QUIC_RE_OK = qr({"type":"application-close-receive");
my $QUIC_RE_BAD_CERT = qr({"type":"transport-close-receive",.*"error-code":299,)m;

subtest "x509 server" => sub {
    my $server = start_server(1, 0);
    subtest "tls13" => sub {
        like run_picotls_client({ port => $tls_port }), $TLS_RE_OK, "x509 -> ok";
        like run_picotls_client({ port => $tls_port, opts => $TLS_RAW_CERT_OPT }), $TLS_RE_BAD_CERT, "raw -> bad_cert";
    };
    subtest "quic" => sub {
        like run_quic_client(""), $QUIC_RE_OK, "x509 -> ok";
        like run_quic_client($QUIC_RAW_CERT_OPT), $QUIC_RE_BAD_CERT, "raw -> bad_cert";
    };
};

subtest "raw server" => sub {
    my $server = start_server(0, 1);
    subtest "tls13" => sub {
        like run_picotls_client({ port => $tls_port }), $TLS_RE_BAD_CERT, "x509 -> bad_cert";
        like run_picotls_client({ port => $tls_port, opts => $TLS_RAW_CERT_OPT }), $TLS_RE_OK, "raw -> ok";
    };
    subtest "quic" => sub {
        like run_quic_client(""), $QUIC_RE_BAD_CERT, "x509 -> ok";
        like run_quic_client($QUIC_RAW_CERT_OPT), $QUIC_RE_OK, "raw -> bad_cert";
    };
};

subtest "hybrid server" => sub {
    my $server = start_server(1, 1);
    subtest "tls13" => sub {
        like run_picotls_client({ port => $tls_port }), $TLS_RE_OK, "raw -> ok";
        like run_picotls_client({ port => $tls_port, opts => $TLS_RAW_CERT_OPT }), $TLS_RE_OK, "raw -> ok";
    };
    subtest "quic" => sub {
        like run_quic_client(""), $QUIC_RE_OK, "x509 -> ok";
        like run_quic_client($QUIC_RAW_CERT_OPT), $QUIC_RE_OK, "raw -> bad_cert";
    };
};

done_testing;

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
  ssl: &ssl
    key-file: examples/h2o/server.key
    @{[$use_cert ? "certificate-file: examples/h2o/server.crt" : ""]}
    @{[$use_raw ? "raw-pubkey-file: examples/h2o/server.pub" : ""]}
listen:
  port: $tls_port
  type: quic
  ssl:
    <<: *ssl
EOT
    my $server = spawn_h2o_raw($conf, [ $tls_port ]);
}

sub run_quic_client {
    my $opts = shift;
    my $cmd = "@{[bindir]}/quicly/cli $opts -a h3-29 -e /dev/stdout 127.0.0.1 $tls_port 2>&1";
    open my $fh, "-|", $cmd
        or die "failed to invoke command:$cmd:$!";
    do { local $/; <$fh> };
}
