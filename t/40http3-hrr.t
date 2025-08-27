use strict;
use warnings;
use File::Temp qw(tempdir);
use Net::EmptyPort qw(wait_port);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;
use JSON;

# skip unless x25519 is supported, in addition to secp256r1 which is mandatory
plan skip_all => "x25519 not supported"
    unless server_features()->{"key-exchanges"} =~ /\s?x25519(,|$)/;
my $h3client = bindir() . "/h2o-httpclient";
plan skip_all => "h2o-httpclient not found"
    unless -x $h3client;

my $tempdir = tempdir(CLEANUP => 1);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

# spawn server that only supports secp256r1
my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
    key-exchange-tls1.3:
    - secp256r1
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

wait_port({port => $quic_port, proto => 'udp'});

subtest "secp256r1 only" => sub {
    doit("secp256r1");
};
subtest "secp256r1-then-secp256r1" => sub {
    doit("secp256r1", "x25519");
};
subtest "x25519-then-secp256r1" => sub {
    doit("x25519", "secp256r1");
};

undef $server;

done_testing;

sub doit {
    my @keyex = @_;
    my $cmd = "$h3client -3 100 -k" .
        join("", map { " --http3-key-exchange $_" } @keyex) .
        " https://127.0.0.1:$quic_port/";
    open my $fh, "-|", "$cmd 2>&1"
        or die "failed to run $cmd: $!";
    my $resp = do { local $/; <$fh> };
    close $fh;
    ok $? == 0, "h2o-httpclient exited with 0";
    like $resp, qr{^HTTP/3 200}, "response code is 200";
    like $resp, qr{\nhello\n$}s, "response body is correct";
}

