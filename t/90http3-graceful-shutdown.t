use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use POSIX ":sys_wait_h";
use Test::More;
use t::Util;

# test scenario:
# 0. set up a probe for client to emit message on GOAWAY reception
# 1. send SIGTERM to server to generate GOAWAY
# 2. upon receiving GOAWAY, tracer will emit message
# 3. make sure an expected string (from the GOAWAY probe) appears in the tracer log

check_dtrace_availability();

plan skip_all => 'curl not found'
    unless prog_exists('curl');

plan skip_all => 'mruby support is off'
	unless server_features()->{mruby};

my $tempdir = tempdir(CLEANUP => 1);

my $client_prog = bindir() . "/h2o-httpclient";
plan skip_all => "$client_prog not found"
    unless -e $client_prog;

my $quic_port = empty_port({
    host  => "127.0.0.1",
    proto => "udp",
});

# spawn a simple HTTP/3 echo server, excerpted from 40http3.t
my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
http3-graceful-shutdown-timeout: 1
hosts:
  default:
    paths:
      /echo:
        mruby.handler: |
          Proc.new do |env|
            [200, {}, env["rack.input"]]
          end
EOT

wait_port({port => $quic_port, proto => 'udp'});

# launch httpclient
my $client_pid = fork;
die "fork failed:$!"
	unless defined $client_pid;

if ($client_pid == 0) {
	my @args = ("$client_prog", qw(-3 -t 5 -d 1000 -b 10 -c 2 -i 1000), "https://127.0.0.1:$quic_port/echo");
	exec @args;
	die "should not reach here!";
}

# spawn bpftrace/dtrace to probe GOAWAY frame reception
my $tracer_pid = fork;
die "fork(2) failed:$!"
	unless defined $tracer_pid;
if ($tracer_pid == 0) {
	# child process, spawn bpftrace
	close STDOUT;
	open STDOUT, ">", "$tempdir/trace.out"
		or die "failed to create temporary file:$tempdir/trace.out:$!";
	if ($^O eq 'linux') {
		# because there is no easy way to inspect the payload, we inspect the length of the payload instead
		# as a minimal validation
		exec qw(bpftrace -v -B none -p), $client_pid, "-e", <<'EOT';
usdt::h2o:h3_frame_receive { if (arg0 == 7) { printf("H3 GOAWAY frame received: len=%d\n", arg2); } }
EOT
		die "failed to spawn bpftrace:$!";
	} else {
		exec(
			qw(unbuffer dtrace -p), $client_pid, "-n", <<'EOT',
:h2o-httpclient::h3_frame_receive {
	if (arg0 == 7) {
		printf("\nXXXXH3 GOAWAY frame received: len=%d\n", arg2);
	}
}
EOT
		);
		die "failed to spawn dtrace:$!";
	}
}

# wait until bpftrace and the trace log becomes ready
my $read_trace = get_tracer($tracer_pid, "$tempdir/trace.out");
if ($^O eq 'linux') {
    while ($read_trace->() eq '') {
        sleep 1;
    }
}
sleep 2;

# shutdown server, which will send SIGTERM to the server and it will then send GOAWAY to the client
undef $server;

sleep 3;

my $trace;
do {
	sleep 1;
} while (($trace = $read_trace->()) eq '');

like $trace, qr{H3 GOAWAY frame received: len=8}s; # first GOAWAY frame, stream_id=2^62-1
like $trace, qr{H3 GOAWAY frame received: len=1}s; # second GOAWAY frame, stream_id=last stream ID that the client sent
# note: once the client implements correct handling of GOAWAY, it will exit at the first GOAWAY,
# so it will never see the second one.

# `http3-graceful-shutdown-timeout` > 0 lets the server forcefully close connections at the end,
# which then lets the client exit. Here we just claim a defunct process (otherwise the tracer would stuck).
while (waitpid($client_pid, 0) != $client_pid) {}

# wait for the tracer to exit
while (waitpid($tracer_pid, 0) != $tracer_pid) {}

done_testing;
