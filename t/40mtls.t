use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $tls_port = empty_port();
my $good_client_key_cert = '--key t/assets/test_client.key --cert t/assets/test_client_intermediate.crt';
my $wrong_client_key_cert = '--key examples/h2o/server.key --cert examples/h2o/server.crt';
my $TLS_RE_OK = qr{hello};

my $server = start_server();

subtest "tls1.2" => sub {
    my $tls12_flag = '--tls-max 1.2';
    like run_tls_client($tls12_flag, $good_client_key_cert), $TLS_RE_OK, "mTLS12";
    unlike run_tls_client($tls12_flag, ""), $TLS_RE_OK, "mTLS12 no client cert";
    unlike run_tls_client($tls12_flag, $wrong_client_key_cert), $TLS_RE_OK, "mTLS12 wrong client cert";
};

subtest "tls1.3" => sub {
    plan skip_all => 'curl does not support TLS 1.3'
        unless curl_support_tls13();
    my $tls13_flag = '--tlsv1.3 --tls-max 1.3';
    like run_tls_client($tls13_flag, $good_client_key_cert), $TLS_RE_OK, "mTLS13";
    unlike run_tls_client($tls13_flag, ""), $TLS_RE_OK, "mTLS13 no client cert";
    unlike run_tls_client($tls13_flag, $wrong_client_key_cert), $TLS_RE_OK, "mTLS13 wrong client cert";
};

done_testing;

sub start_server {
    my $conf = <<"EOT";
hosts:
  "default":
    paths:
      "/":
        file.dir: @{[DOC_ROOT]}
listen:
  port: $tls_port
  ssl: &ssl
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    client-ca-file: examples/h2o/test_client_int_ca.crt
EOT
    my $server = spawn_h2o_raw($conf, [ $tls_port ]);
}

sub run_tls_client {
    my $use_tls12 = shift;
    my $client_key_cert = shift;
    my $resp = `curl --silent --cacert misc/test-ca/ca.crt $client_key_cert https://127.0.0.1.xip.io:$tls_port $use_tls12`;
    return $resp;
}

sub curl_support_tls13 {
    my $openssl_ver = `curl --version`;
    $openssl_ver =~ /OpenSSL\/(\d+)\.(\d+)\.(\d+)/
        or die "cannot parse OpenSSL version: $openssl_ver";
    $openssl_ver = $1 * 10000 + $2 * 100 + $3;
    return $openssl_ver >= 10101;
}
