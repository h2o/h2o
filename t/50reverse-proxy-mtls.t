use strict;
use warnings;
use Net::EmptyPort qw(check_port empty_port);
use Test::More;
use t::Util;

plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'plackup not found'
    unless prog_exists('plackup');
plan skip_all => 'Starlet not found'
    unless system('perl -MStarlet /dev/null > /dev/null 2>&1') == 0;

my $upstream_port = empty_port();
my $tls_port = empty_port();
my $tls12_flag = '--tlsv1.2';
my $tls13_flag = '--tlsv1.3';
my $good_client_key_cert = '--key t/assets/test_client.key --cert t/assets/test_client.crt';
my $wrong_client_key_cert = '--key examples/h2o/server.key --cert examples/h2o/server.crt';
my $TLS_RE_OK = qr{hello};

my $guard = spawn_server(
    argv     => [ qw(plackup -s Starlet --keepalive-timeout 100 --access-log /dev/null --listen), "127.0.0.1:$upstream_port", ASSETS_DIR . "/upstream.psgi" ],
    is_ready =>  sub {
        check_port($upstream_port);
    },
);

sub start_server {
    my $conf = <<"EOT";
hosts:
  "default":
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1.xip.io:$upstream_port
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
    my $resp = `curl --silent --cacert misc/test-ca/ca.crt $client_key_cert https://127.0.0.1.xip.io:$tls_port/index.txt $use_tls12`;
    return $resp;
}

my $server = start_server();

sub curl_support_tls13 {
    my $openssl_ver = `curl --version`;
    $openssl_ver =~ /OpenSSL\/(\d+)\.(\d+)\.(\d+)/
        or die "cannot parse OpenSSL version: $openssl_ver";
    $openssl_ver = $1 * 10000 + $2 * 100 + $3;
    return $openssl_ver >= 10101;
}

sleep 2;

if (curl_support_tls13()) {
    like run_tls_client($tls13_flag, $good_client_key_cert), $TLS_RE_OK, "mTLS13";
    unlike run_tls_client($tls13_flag, ""), $TLS_RE_OK, "mTLS13 no client cert";
    unlike run_tls_client($tls13_flag, $wrong_client_key_cert), $TLS_RE_OK, "mTLS13 wrong client cert";
}

like run_tls_client($tls12_flag, $good_client_key_cert), $TLS_RE_OK, "mTLS12";
unlike run_tls_client($tls12_flag, ""), $TLS_RE_OK, "mTLS12 no client cert";
unlike run_tls_client($tls12_flag, $wrong_client_key_cert), $TLS_RE_OK, "mTLS12 wrong client cert";

done_testing();
