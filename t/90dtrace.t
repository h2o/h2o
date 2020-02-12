use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;

run_as_root();

plan skip_all => 'dtrace support is off'
    unless server_features()->{dtrace};
plan skip_all => 'curl not found'
    unless prog_exists('curl');

if ($^O eq 'linux') {
    plan skip_all => 'bpftrace not found'
        unless prog_exists('bpftrace');
    # NOTE: the test is likely to depend on https://github.com/iovisor/bpftrace/pull/864
    plan skip_all => "skipping bpftrace tests (setenv DTRACE_TESTS=1 to run them)"
        unless $ENV{DTRACE_TESTS};
} else {
    plan skip_all => 'dtrace not found'
        unless prog_exists('dtrace');
    plan skip_all => 'unbuffer not found'
        unless prog_exists('unbuffer');
}

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
    if ($^O eq 'linux') {
        exec qw(bpftrace -v -B none -p), $server->{pid}, "-e", <<'EOT';
struct st_h2o_http2_frame_t {uint32_t length; uint8_t type; uint8_t flags; uint32_t stream_id;};
usdt::h2o:receive_request {printf("*** %llu:%llu version %d.%d ***\n", arg0, arg1, arg2 / 256, arg2 % 256)}
usdt::h2o:receive_request_header {printf("%s: %s\n", str(arg2, arg3), str(arg4, arg5))}
usdt::h2o:send_response {printf("%llu:%llu status:%u\n", arg0, arg1, arg2)}
usdt::h2o:send_response_header {printf("%s: %s\n", str(arg2, arg3), str(arg4, arg5))}
usdt::h2o:h2_unknown_frame_type {
    printf("Unknown HTTP/2 frame type: %d stream_id: %d\n",
        arg1,
        ((struct st_h2o_http2_frame_t *)arg2)->stream_id)
}
EOT
        die "failed to spawn bpftrace:$!";
    } else {
        exec(
            qw(unbuffer dtrace -p), $server->{pid}, "-n", <<'EOT',
:h2o::receive_request {
    printf("\nXXXX*** %u:%u version %d.%d ***\n", arg0, arg1, arg2 / 256, arg2 % 256);
}
EOT
            "-n", <<'EOT',
:h2o::receive_request_header {
    name = (char *)copyin(arg2, arg3);
    name[arg3] = '\0';
    value = (char *)copyin(arg4, arg5);
    value[arg5] = '\0';
    printf("\nXXXX%s: %s\n", stringof(name), stringof(value));
}
EOT
            "-n", <<'EOT',
:h2o::send_response {
    printf("\nXXXX%u:%u status:%u\n", arg0, arg1, arg2);
}
EOT
            "-n", <<'EOT',
:h2o::send_response_header {
    name = (char *)copyin(arg2, arg3);
    name[arg3] = '\0';
    value = (char *)copyin(arg4, arg5);
    value[arg5] = '\0';
    printf("\nXXXX%s: %s\n", stringof(name), stringof(value));
}
EOT
            "-n", <<'EOT'
struct st_h2o_http2_frame_t {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
};
:h2o::h2_unknown_frame_type {
    printf("\nXXXXUnknown HTTP/2 frame type: %d stream_id: %d\n",
        arg1,
        ((struct st_h2o_http2_frame_t *) copyin(arg2, sizeof(struct st_h2o_http2_frame_t)))->stream_id);
}
EOT
        );
        die "failed to spawn dtrace:$!";
    }
}

# wait until bpftrace and the trace log becomes ready
my $read_trace;
while (1) {
    sleep 1;
    if (open my $fh, "<", "$tempdir/trace.out") {
        my $off = 0;
        $read_trace = sub {
            seek $fh, $off, 0
                or die "seek failed:$!";
            read $fh, my $bytes, 65000;
            $bytes = ''
                unless defined $bytes;
            $off += length $bytes;
            if ($^O ne 'linux') {
                $bytes = join "", map { substr($_, 4) . "\n" } grep /^XXXX/, split /\n/, $bytes;
            }
            return $bytes;
        };
        last;
    }
    die "bpftrace failed to start\n"
        if waitpid($tracer_pid, WNOHANG) == $tracer_pid;
}
if ($^O eq 'linux') {
    while ($read_trace->() eq '') {
        sleep 1;
    }
}
sleep 1;

run_with_curl($server, sub {
    my ($proto, $port, $cmd, $http_ver) = @_;
    my $get_trace = sub {
        # access
        my ($headers, $body) = run_prog("$cmd --silent --dump-header silent --dump-header /dev/stderr $proto://127.0.0.1:$port/");
        is $body, "hello\n";
        like $headers, qr{^HTTP/[0-9\.]+ 200 }s;
        # read the trace
        my $trace;
        do {
            sleep 1;
        } while (($trace = $read_trace->()) eq '');
        $trace;
    };
    # Warm up so that constant elements of HPACK static table gets paged in.  Bpftrace can only log information that is available in
    # the main memory; see https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-September/001035.html
    $get_trace->() if $^O eq 'linux' && $http_ver == 0x200;
    # get trace
    my $trace = $get_trace->();
    my ($ver_major, $ver_minor) = (int($http_ver / 256), $http_ver % 256);
    like $trace, qr{^\*{3} \d+:1 version $ver_major\.$ver_minor \*{3}$}m;
    like $trace, qr{^:method: GET$}m;
    like $trace, qr{^:scheme: $proto$}m;
    like $trace, qr{^:authority: 127\.0\.0\.1:$port$}m;
    like $trace, qr{^:path: /$}m;
    like $trace, qr{^\d+:1 status:200}m;
    like $trace, qr{content-length: 6}m;
    like $trace, qr{content-type: text/plain}m;
    like $trace, qr{accept-ranges: bytes}m;
});

subtest "http/2 unknown frames" => sub {
    my ($output, $stderr) = run_with_h2get($server, <<"EOR");
    begin
        h2g = H2.new
        host = "https://#{ARGV[0]}"
        h2g.connect(host)
        h2g.send_prefix()
        h2g.send_settings([[2,0]])
        # Ack settings
        settings_exch = 0
        while settings_exch < 2 do
            f = h2g.read(-1)
            puts f.to_s()
            if f.type == "SETTINGS" and (f.flags & 1 == 1) then
                settings_exch += 1
                next
            elsif f.type == "SETTINGS" then
                h2g.send_settings_ack()
                settings_exch += 1
                next
            end
        end
        h2g.send_raw_frame(1, 101)
        h2g.send_raw_frame(3, 103)
        h2g.send_raw_frame(5, 105)
        f = h2g.read(500) # Wait for a while to allow above frames to sent out before closing the connection
        h2g.close()
        h2g.destroy()
    rescue Exception => e
        h2g.close()
        puts e.message
        puts e.backtrace.inspect
    end
EOR

    my $trace;
    do {
        sleep 1;
    } while (($trace = $read_trace->()) eq '');

    like $trace, qr{Unknown HTTP/2 frame type: 101 stream_id: 1}s;
    like $trace, qr{Unknown HTTP/2 frame type: 103 stream_id: 3}s;
    like $trace, qr{Unknown HTTP/2 frame type: 105 stream_id: 5}s;
};

# wait until the server and the tracer exits
undef $server;
while (waitpid($tracer_pid, 0) != $tracer_pid) {}


done_testing();
