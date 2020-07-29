use strict;
use warnings FATAL => "all";
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use POSIX ":sys_wait_h";
use Net::EmptyPort qw(empty_port);
use Test::More;
use JSON;
use t::Util;

# NOTE: the test does not work on Travis CI so far.
{
    no warnings 'uninitialized', 'numeric';
    plan skip_all => "skipping h2olog tests (setenv DTRACE_TESTS=2 to run them)"
        unless $ENV{DTRACE_TESTS} >= 2;
}

plan skip_all => "h2olog is supported only for Linux"
    if $^O ne 'linux';

my $h2olog_prog = bindir() . "/h2olog";
plan skip_all => "$h2olog_prog not found"
    unless -e $h2olog_prog;

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

plan skip_all => 'dtrace support is off'
    unless server_features()->{dtrace};
plan skip_all => 'curl not found'
    unless prog_exists('curl');

run_as_root();

my $tempdir = tempdir(CLEANUP => 1);

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

my $server = spawn_h2o({
    opts => [qw(--mode=worker)],
    conf => << "EOT",
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
});

my $tracer = spawn_h2olog({ pid => $server->{pid} });

my $trace;
my $n = 5;
do {
    $trace = $tracer->get_trace(sub {
        my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
        like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
        is $body, "hello\n", "req: body";
    });
} while not defined $trace and --$n >= 0;

diag "h2olog output:";
diag $trace;

ok( (map { decode_json($_) } split /\n/, $trace), "h2olog output is valid JSON Lines");

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;
undef $tracer;

done_testing();
