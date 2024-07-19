use strict;
use warnings;
use Net::EmptyPort qw(wait_port);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $tls_port = empty_port({
    host  => "127.0.0.1",
    proto => "tcp",
});
my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $conf = << "EOT";
listen:
  port: $tls_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
num-threads: 1
hosts:
  default:
    paths:
      /:
        mishandler: ON
EOT
my $guard = spawn_h2o($conf);
wait_port({port => $tls_port, proto => 'tcp'});
wait_port({port => $quic_port, proto => 'udp'});

subtest "h1 unknown path" => sub {
    my $resp = `$client_prog -k -2 0 https://127.0.0.1:$tls_port/other 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello unknown path$}s;
};

subtest "h1 and zero iovecs" => sub {
    my $resp = `$client_prog -k -2 0 https://127.0.0.1:$tls_port/zero 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello world$}s;
};

subtest "h1 and one zero-length iovec" => sub {
    my $resp = `$client_prog -k -2 0 https://127.0.0.1:$tls_port/empty 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello world$}s;
};

subtest "h2 and zero iovecs" => sub {
    my $resp = `$client_prog -k -2 100 https://127.0.0.1:$tls_port/zero 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello world$}s;
};

subtest "h2 and one zero-length iovec" => sub {
    my $resp = `$client_prog -k -2 100 https://127.0.0.1:$tls_port/empty 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello world$}s;
};

subtest "h3 and one zero-length iovec" => sub {
    my $resp = `$client_prog -k -3 100 https://127.0.0.1:$quic_port/empty 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello world$}s;
};

subtest "h3 and zero iovecs" => sub {
    my $resp = `$client_prog -k -3 100 https://127.0.0.1:$quic_port/zero 2>&1`;
    like $resp, qr{^HTTP/.*\n\nhello world$}s;
};

done_testing;
