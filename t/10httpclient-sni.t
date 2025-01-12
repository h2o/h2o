use strict;
use warnings;
use Test::More;
use t::Util;
use File::Temp qw(tempdir);

my $httpclient = bindir() . '/h2o-httpclient';

my $tcp_port = empty_port({ host  => '0.0.0.0', proto => 'tcp' });
my $udp_port = empty_port({ host  => '0.0.0.0', proto => 'udp' });
my $all_ports = [ { port => $tcp_port, proto => 'tcp' }, { port => $udp_port, proto => 'udp' } ];

my $tempdir = tempdir(CLEANUP => 1);

system(<<"EOT") == 0 or die "shell commands failed";
set -x -e

openssl req -x509 -newkey rsa:2048 -keyout $tempdir/server1.key -out $tempdir/server1.crt -sha256 -days 2 -nodes -subj '/CN=localhost.examp1e.net'

openssl req -x509 -newkey rsa:2048 -keyout $tempdir/server2.key -out $tempdir/server2.crt -sha256 -days 2 -nodes -subj '/CN=alternate.localhost.examp1e.net'

mkdir -p $tempdir/share/h2o
cp -ip $tempdir/server2.crt $tempdir/share/h2o/ca-bundle.crt
EOT

my $server = spawn_h2o_raw(<<"EOT", $all_ports);
hosts:
  "localhost.examp1e.net":
    paths:
      /:
        file.dir: examples/doc_root
    listen:
      port: $tcp_port
      ssl: &s1
        certificate-file: $tempdir/server1.crt
        key-file: $tempdir/server1.key
        minimum-version: TLSv1.2
        cipher-preference: server
        cipher-suite: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
    listen:
      port: $udp_port
      type: quic
      ssl:
        <<: *s1
    access-log: /dev/stderr
  "alternate.localhost.examp1e.net":
    paths:
      /:
        file.dir: examples/doc_root.alternate
    listen:
      port: $tcp_port
      ssl: &s2
        certificate-file: $tempdir/server2.crt
        key-file: $tempdir/server2.key
        minimum-version: TLSv1.2
        cipher-preference: server
        cipher-suite: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"
    listen:
      port: $udp_port
      type: quic
      ssl:
        <<: *s1
    access-log: /dev/stderr
EOT

my $out;

subtest "H1 without SNI" => sub {
    $out = `H2O_ROOT=$tempdir $httpclient -2 0 -x https://127.0.0.1:$tcp_port https://alternate.localhost.examp1e.net/index.txt 2>&1`;
    is $?, 256, 'failure expected';
    like $out, qr/self.signed certificate/, 'error message';
};

subtest "H2 without SNI" => sub {
    $out = `H2O_ROOT=$tempdir $httpclient -2 100 -x https://127.0.0.1:$tcp_port https://alternate.localhost.examp1e.net/index.txt 2>&1`;
    is $?, 256, 'failure expected';
    like $out, qr/self.signed certificate/, 'error message';
};

# `h2o-httpclient -3 100` does not seem to care that the server cert does not match the trust root

subtest "H1 with SNI" => sub {
    $out = `H2O_ROOT=$tempdir $httpclient -2 0 -S alternate.localhost.examp1e.net -x https://127.0.0.1:$tcp_port https://alternate.localhost.examp1e.net/index.txt`;
    is $?, 0, 'success';
    is $out, "hello\n", 'response';
};

subtest "H2 with SNI" => sub {
    $out = `H2O_ROOT=$tempdir $httpclient -2 100 -S alternate.localhost.examp1e.net -x https://127.0.0.1:$tcp_port https://alternate.localhost.examp1e.net/index.txt`;
    is $?, 0, 'success';
    is $out, "hello\n", 'response';
};

subtest "H3 with SNI" => sub {
    $out = `H2O_ROOT=$tempdir $httpclient -3 100 -S alternate.localhost.examp1e.net -x https://127.0.0.1:$udp_port https://alternate.localhost.examp1e.net/index.txt`;
    is $?, 0, 'success';
    is $out, "hello\n", 'response';
};

done_testing;
