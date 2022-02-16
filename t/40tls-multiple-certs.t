use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port);
use Test::More;
use t::Util;

my $tls_port = empty_port();

plan skip_all => 'openssl s_client does not support TLS 1.3 + ECDSA' unless do {
    my $resp = `openssl s_client -tls1_3 -sigalgs ECDSA+SHA256 -connect 127.0.0.1:$tls_port < /dev/null 2>&1`;
    $resp =~ /^connect:errno=/m;
};

my $server = spawn_h2o_raw(<<"EOT", [ $tls_port ]);
num-threads: 1
listen:
  port: $tls_port
  ssl: &ssl
    identity:
    - key-file: deps/picotls/t/assets/secp256r1/key.pem
      certificate-file: deps/picotls/t/assets/secp256r1/cert.pem
    - key-file: examples/h2o/server.key
      certificate-file: examples/h2o/server.crt
listen:
  port: $tls_port
  type: quic
  ssl:
    <<: *ssl
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

sub doit {
    my ($algs, $expected) = @_;
    my $resp = `openssl s_client -sigalgs $algs -connect 127.0.0.1:$tls_port < /dev/null 2>&1`;
    like $resp, qr/\nPeer signature type: $expected\n.*\nDONE/s, "$algs -> $expected";
}

subtest "use specified" => sub {
    doit('RSA-PSS+SHA256', 'RSA-PSS');
    doit('ECDSA+SHA256', 'ECDSA');
};

subtest "prefer alternative" => sub {
    doit('RSA-PSS+SHA256:ECDSA+SHA256', 'ECDSA');
    doit('ECDSA+SHA256:RSA-PSS+SHA256', 'ECDSA');
};

# we do not have a way to specify the signature algorithms for QUIC, but at least make sure that it is possible to connect
subtest "quic" => sub {
    my $cmd = "@{[bindir]}/quicly/cli -a h3-29 -e /dev/stdout 127.0.0.1 $tls_port < /dev/null 2>&1";
    open my $fh, "-|", $cmd
        or die "failed to invoke command:$cmd:$!";
    my $output = do { local $/; <$fh> };
    # receipt of application-close in 1-RTT is a proof that the handshake succeeded
    like $output, qr({"type":"application-close-receive");
};

done_testing;
