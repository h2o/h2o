use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $tls_port = empty_port();
my $tls12_flag = '--tls-max 1.2';
my $good_client_key_cert = '--key t/assets/test_client.key --cert t/assets/test_client.crt';
my $wrong_client_key_cert = '--key examples/h2o/server.key --cert examples/h2o/server.crt';
my $TLS_RE_OK = qr{hello};
my $TLS_RE_BAD_CERT = qr{ptls_handshake:299};

my $server = start_server();
like run_tls_client("", $good_client_key_cert), $TLS_RE_OK, "mTLS13";
#like run_tls_client($tls12_flag, $good_client_key_cert), $TLS_RE_OK, "mTLS12";

unlike run_tls_client("", ""), $TLS_RE_OK, "mTLS13 no client cert";
#unlike run_tls_client($tls12_flag, ""), $TLS_RE_OK, "mTLS12 no client cert";

unlike run_tls_client("", $wrong_client_key_cert), $TLS_RE_OK, "mTLS13 wrong client cert";
#unlike run_tls_client($tls12_flag, $wrong_client_key_cert), $TLS_RE_OK, "mTLS12 wrong client cert";

done_testing;

sub start_server {
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
    certificate-file: examples/h2o/server.crt
    client-ca-file: examples/h2o/test_client_ca.crt
EOT
    my $server = spawn_h2o_raw($conf, [ $tls_port ]);
}

sub run_tls_client {
    my $use_tls12 = shift;
    my $client_key_cert = shift;
    my $resp = `curl --silent --cacert misc/test-ca/ca.crt $client_key_cert https://127.0.0.1.xip.io:$tls_port $use_tls12`;
    return $resp;
}


