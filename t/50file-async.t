use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use Scope::Guard qw(guard);
use Test::More;
use t::Util;

plan skip_all => "use of io_uring not enabled"
    unless server_features()->{io_uring};
plan skip_all => "io_uring is available only on linux"
    if $^O ne "linux";
check_dtrace_availability();

my $tempdir = tempdir(CLEANUP => 1);

# create content
our @FILESIZE = qw(11 4095 4096 1000000 2000000);
for my $s (@FILESIZE) {
    open my $fh, ">", "$tempdir/$s.txt"
        or die "failed to create file:$tempdir/$s.txt:$!";
    print $fh "1" x $s;
}

subtest "no-batch" => sub {
    run_tests(1);
};

subtest "batch=16" => sub {
    run_tests(16);
};

sub run_tests {
    my $batch_size = shift;
    # spawn server
    my $quic_port = empty_port({
        host  => "127.0.0.1",
        proto => "udp",
    });
    my $server = spawn_h2o(<< "EOT");
listen:
  type: quic
  host: 127.0.0.1
  port: $quic_port
  ssl:
    key-file: examples/h2o/server.key
    certificate-file: examples/h2o/server.crt
hosts:
  default:
    paths:
      /:
        file.dir: $tempdir
io_uring-batch-size: $batch_size
EOT
    wait_port({port => $quic_port, proto => "udp"});

    # launch tracer
    my $tracer_pid = fork;
    die "fork(2) failed:$!"
        unless defined $tracer_pid;
    if ($tracer_pid == 0) {
        # child process, spawn bpftrace
        close STDOUT;
        open STDOUT, ">", "$tempdir/trace.out"
            or die "failed to create temporary file:$tempdir/trace.out:$!";
        exec qw(bpftrace -v -B none -p), $server->{pid}, "-e", <<'EOT';
usdt::h2o:socket_read_file_async_start { printf("read_file_async\n"); }
EOT
        die "failed to spawn dtrace:$!";
    }

    # wait until bpftrace and the trace log becomes ready
    my $read_trace = get_tracer($tracer_pid, "$tempdir/trace.out");
    while ($read_trace->() eq '') {
      sleep 1;
    }
    sleep 2;

    my $doit = sub {
        my $fetch = shift;
        for my $size (@FILESIZE) {
            subtest "size=$size" => sub {
                my $resp = $fetch->("$size.txt");
                sleep 1;
                my $trace = $read_trace->();
                subtest "access type" => sub {
                    if ($batch_size == 1) {
                        unlike $trace, qr/read_file_async/;
                    } else {
                        like $trace, qr/read_file_async/;
                    }
                };
                is length($resp), $size, "size";
                is md5_hex($resp), md5_file("$tempdir/$size.txt"), "md5";
            };
        };
    };

    # run test with each protocol
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        $doit->(sub {
            my $fn = shift;
            `$curl --silent --dump-header /dev/null '$proto://127.0.0.1:$port/$fn'`;
        });
    });
    subtest 'http/3' => sub {
        my $h3client = bindir() . "/h2o-httpclient";
        plan skip_all => "$h3client not found"
            unless -e $h3client;
        $doit->(sub {
            my $fn = shift;
            `$h3client -3 100 https://127.0.0.1:$quic_port/$fn 2> /dev/null`;
        });
    };

    undef $server;
    while (waitpid($tracer_pid, 0) != $tracer_pid) {}
}

done_testing;
