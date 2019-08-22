use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;

plan skip_all => 'dtrace support is off'
    unless server_features()->{dtrace};
plan skip_all => 'curl not found'
    unless prog_exists('curl');
plan skip_all => 'bpftrace not found'
    unless prog_exists('bpftrace');
plan skip_all => 'test requires root privileges'
    unless $< == 0;

my $tempdir = tempdir(CLEANUP => 1);

my $server = spawn_h2o({
    opts => [qw(--mode=worker)],
    conf => << 'EOT',
user: nobody
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
});

# spawn bpftrace
my $tracer_pid = fork;
die "fork(2) failed:$!"
    unless defined $tracer_pid;
if ($tracer_pid == 0) {
    # child process, spawn bpftrace
    close STDOUT;
    open STDOUT, ">", "$tempdir/trace.out"
        or die "failed to create temporary file:$tempdir/trace.out:$!";
    exec "unbuffer", "bpftrace", "-p", $server->{pid}, "-e", <<'EOT';
usdt::h2o_receive_request {printf("*** %llu:%llu version %d.%d ***\n", arg0, arg1, arg2 / 256, arg2 % 256)}
usdt::h2o_receive_request_header {printf("%s: %s\n", str(arg2, arg3), str(arg4, arg5))}
EOT
    die "failed to spawn bpftrace:$!";
}

# wait until bpftrace and the trace log becomes ready
my $read_trace;
while (1) {
    sleep 0.1;
    if (open my $fh, "<", "$tempdir/trace.out") {
        my $off = 0;
        $read_trace = sub {
            seek $fh, $off, 0
                or die "seek failed:$!";
            read $fh, my $bytes, 10000;
            $bytes = ''
                unless defined $bytes;
            $off += length $bytes;
            return $bytes;
        };
        last;
    }
    die "bpftrace failed to start\n"
        if waitpid($tracer_pid, WNOHANG) == $tracer_pid;
}
while ($read_trace->() eq '') {
    sleep 0.1;
}
sleep 1;

run_with_curl($server, sub {
    my ($proto, $port, $cmd, $http_ver) = @_;
    # access
    my ($headers, $body) = run_prog("$cmd --silent --dump-header silent --dump-header /dev/stderr $proto://127.0.0.1:$port/");
    is $body, "hello\n";
    like $headers, qr{^HTTP/[0-9\.]+ 200 }s;
    # read the trace
    my $trace;
    while (($trace = $read_trace->()) eq '') {
        sleep 0.1;
    }
    # check
    my ($ver_major, $ver_minor) = (int($http_ver / 256), $http_ver % 256);
    like $trace, qr{^\*{3} \d+:1 version $ver_major\.$ver_minor \*{3}$}m;
    like $trace, qr{^:method: GET$}m;
    like $trace, qr{^:scheme: $proto$}m;
    like $trace, qr{^:authority: 127\.0\.0\.1:$port$}m;
    like $trace, qr{^:path: /$}m;
});

# wait until the server and the tracer exits
undef $server;
while (waitpid($tracer_pid, 0) != $tracer_pid) {}


done_testing();
