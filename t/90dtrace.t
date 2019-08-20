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
    exec "bpftrace", "-p", $server->{pid}, "-e", <<'EOT';
usdt::h2o_receive_request {printf("*** %llu:%llu version %d.%d ***\n", arg0, arg1, arg2 / 256, arg2 % 256)}
usdt::h2o_receive_request_header {printf("%s: %s\n", str(arg2, arg3), str(arg4, arg5))}
EOT
    die "failed to spawn bpftrace:$!";
}

# wait until bpftrace becomes ready (which can be detecting by it emitting preamble to the log file)
while (1) {
    sleep 0.1;
    last if -e "$tempdir/trace.out" && +(stat "$tempdir/trace.out")[7] > 0;
    die "bpftrace failed to start\n"
        if waitpid($tracer_pid, WNOHANG) == $tracer_pid;
}
sleep 1;

my ($headers, $body) = run_prog("curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/");
is $body, "hello\n";
like $headers, qr{^HTTP/1\.1 200 }s;

# wait until the server and the tracer exits
sleep 1;
undef $server;
while (waitpid($tracer_pid, 0) != $tracer_pid) {}

my $lines = do {
    open my $fh, "<", "$tempdir/trace.out"
        or die "failed to open $tempdir/trace.out:$!";
    local $/;
    <$fh>;
};
like $lines, qr{^\*{3} \d+:1 version 1\.1 \*{3}$}m;
like $lines, qr{^:method: GET$}m;
like $lines, qr{^:authority: 127\.0\.0\.1:\d+$}m;
like $lines, qr{^:path: /$}m;

done_testing();
