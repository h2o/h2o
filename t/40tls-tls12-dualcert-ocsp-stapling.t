#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use t::Util;
use Test::More;

my $tls_port = empty_port({ host => "127.0.0.1", proto => "tcp" });
my $server = spawn_h2o_raw(<<"EOT", [$tls_port]);
num-threads: 1
listen:
  port: $tls_port
  ssl:
    identity:
      - key-file: examples/h2o/server.key
        certificate-file: examples/h2o/server.crt
      - key-file: deps/picotls/t/assets/secp256r1/key.pem
        certificate-file: deps/picotls/t/assets/secp256r1/cert.pem
    ocsp-update-cmd: t/assets/tls12-dualcert-ocsp/mock-ocsp-fetcher.pl
hosts:
  default:
    paths:
      "/":
        file.dir: /tmp
EOT
sleep 2;  # Wait for OCSP to be fetched

# Test default ClientHello (server selects ECDSA by default)
my $default_ch = slurp('t/assets/tls12-dualcert-ocsp/default.bin');
my $response = send_and_recv($tls_port, $default_ch);
like($response, qr/FAKE_OCSP_ECDSA_RESP_TLS12_DUALCERT/,
     'default ClientHello should trigger ECDSA OCSP stapling');

# Test RSA-only ClientHello (server selects RSA)
my $rsa_ch = slurp('t/assets/tls12-dualcert-ocsp/rsa-only.bin');
$response = send_and_recv($tls_port, $rsa_ch);
like($response, qr/FAKE_OCSP_RSA_RESP_TLS12_DUALCERT/,
     'rsa-only ClientHello should trigger RSA OCSP stapling');

# Test ECDSA-only ClientHello (server selects ECDSA)
my $ecdsa_ch = slurp('t/assets/tls12-dualcert-ocsp/ecdsa-only.bin');
$response = send_and_recv($tls_port, $ecdsa_ch);
like($response, qr/FAKE_OCSP_ECDSA_RESP_TLS12_DUALCERT/,
     'ecdsa-only ClientHello should trigger ECDSA OCSP stapling');

done_testing;

# Helper to send ClientHello and receive response
sub send_and_recv {
    my ($port, $clienthello) = @_;

    my $sock = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1',
        PeerPort => $port,
        Proto    => 'tcp',
    ) or die "Failed to connect: $!";

    binmode($sock);
    print $sock $clienthello;

    my $response = '';
    my $select = IO::Select->new($sock);
    while ($select->can_read(2)) {
        last unless $sock->sysread(my $buf, 4096);
        $response .= $buf;
        last if length($response) > 2000;
    }

    close $sock;
    return $response;
}

# Helper to slurp file
sub slurp {
    my $file = shift;
    open my $fh, '<:raw', $file or die "Cannot read $file: $!";
    local $/;
    my $data = <$fh>;
    close $fh;
    return $data;
}