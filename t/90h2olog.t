use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use POSIX ":sys_wait_h";
use Net::EmptyPort qw(empty_port);
use Test::More;
use JSON;
use t::Util;

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

# spawn h2olog
my $tracer_pid = fork;
die "fork(2) failed:$!"
    unless defined $tracer_pid;
if ($tracer_pid == 0) {
    # child process, spawn h2olog
    exec $h2olog_prog, "quic", "-d", "-p", $server->{pid}, "-w", "$tempdir/h2olog.out";
    die "failed to spawn $h2olog_prog: $!";
}

# wait until h2olog and the trace log becomes ready
my $read_trace;
while (1) {
    sleep 1;
    if (open my $fh, "<", "$tempdir/h2olog.out") {
        my $off = 0;
        $read_trace = sub {
            seek $fh, $off, 0
                or die "seek failed:$!";
            read $fh, my $bytes, 65000;
            $bytes = ''
                unless defined $bytes;
            $off += length $bytes;
            return $bytes;
        };
        last;
    }
    die "h2olog failed to start\n"
        if waitpid($tracer_pid, WNOHANG) == $tracer_pid;
}


my $get_trace = sub {
    # access
    my ($headers, $body) = run_prog("$client_prog -3 https://127.0.0.1:$quic_port/");
    like $headers, qr{^HTTP/3 200\n}, "req: HTTP/3";
    is $body, "hello\n", "req: body";

    # read the trace
    my $delay = 5;
    my $trace;
    do {
        sleep 1;

        if (--$delay <= 0) {
            return undef;
        }
    } while (($trace = $read_trace->()) eq '');
    $trace;
};

# There is a delay for h2olog to attach the h2o process,
# so at first it need to wait for h2olog to get ready.
1 while defined $get_trace->();

# and then make an HTTP/3 request and get the trace logs
my $trace = $get_trace->();

diag "h2olog output:";
diag $trace;

ok( (map { decode_json($_) } split /\n/, $trace), "h2olog output is valid JSON Lines");

# wait until the server and the tracer exits
diag "shutting down ...";
undef $server;
while (waitpid($tracer_pid, 0) != $tracer_pid) {}

done_testing();
