use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use Time::HiRes qw(sleep);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $tls_port = empty_port();

my $ossl_version = server_features()->{OpenSSL};
# plan skip_all => "KEM is not be supported by $ossl_version"
#     unless $ossl_version =~ /OpenSSL ([0-9]+\.[0-9]+)/ and $1 >= 3.5;
plan skip_all => "KEM is not be supported by $ossl_version"
    unless $ossl_version =~ /CiscoSSL ([0-9]+\.[0-9]+)/ and $1 >= 3.5;

my $conf = <<"EOT";
num-threads: 1
listen:
  port: $tls_port
  ssl: &ssl
    certificate-file: examples/h2o/server.crt
    key-file: examples/h2o/server.key

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

my $server = spawn_h2o_raw($conf, [ $tls_port ]);

subtest "tcp" => sub {
    my $fetch = sub {
        my $kem = shift;

        my $cmd = "@{[bindir()]}/picotls/cli -I -N $kem -j /dev/stdout localhost.examp1e.net $tls_port 2>&1";
        open my $fh, "-|", $cmd
            or die "failed to invoke command:$cmd:$!";
        my $output = do { local $/; <$fh> };
        $output;
    };

    my $doit = sub {
        my $kem = shift;

        my $resp = $fetch->($kem);
        like $resp, qr([{,]"type":"receive_message");
    };

    subtest "tcp_kems" => sub {
        $doit->("MLKEM512");
        $doit->("MLKEM768");
        $doit->("MLKEM1024");
        $doit->("SecP256r1MLKEM768");
        $doit->("SecP384r1MLKEM1024");
        $doit->("X25519MLKEM768");
    };

};

subtest "quic" => sub {
    my $fetch = sub {
        my $kem = shift;
        my $cmd = "@{[bindir()]}/quicly/cli -a h3 -e /dev/stdout -x $kem localhost.examp1e.net $tls_port < /dev/null 2>&1";
        open my $fh, "-|", $cmd
            or die "failed to invoke command:$cmd:$!";
        my $output = do { local $/; <$fh> };
        $output;
    };

    my $doit = sub {
        my $kem = shift;

        # first connection is grease ECH
        my $resp = $fetch->($kem);
        like $resp, qr([{,]"type":"application_close_receive");
    };

    subtest "quic_kems" => sub {
        $doit->("MLKEM512");
        $doit->("MLKEM768");
        $doit->("MLKEM1024");
        $doit->("SecP256r1MLKEM768");
        $doit->("SecP384r1MLKEM1024");
        $doit->("X25519MLKEM768");
    };
};

done_testing;
