use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use Scope::Guard qw(guard);
use t::Util;

my @FILESIZE = qw(11 4095 4096 1000000 2000000);

plan skip_all => "io_uring is available only on linux"
    if $^O ne "linux";
check_dtrace_availability();

# setup
my $tempdir = tempdir(CLEANUP => 1);
my $mount_point = "$tempdir/mnt";
my $image = "$tempdir/tiny.img";
mkdir $mount_point
    or die "failed to create directory $mount_point:$!";
create_diskimage($image, $mount_point);

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
        file.dir: $tempdir/mnt
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
    my $guard = guard {
        system "umount", "-f", $mount_point;
    };
    system("mount", $image, $mount_point) == 0
        or die "failed to mount image:$?";
    for my $size (@FILESIZE) {
        subtest "size=$size" => sub {
            my $fn = "$size.txt";
            subtest "first-access" => sub {
                my $resp = $fetch->($fn);
                sleep 1;
                my $trace = $read_trace->();
                like $trace, qr/read_file_async/, "async";
                is length($resp), $size, "size";
                is md5_hex($resp), md5_file("$mount_point/$fn"), "md5";
            };
            subtest "second-access" => sub {
                my $resp = $fetch->($fn);
                sleep 1;
                my $trace = $read_trace->();
                is $trace, "", "sync";
                is length($resp), $size, "size";
                is md5_hex($resp), md5_file("$mount_point/$fn"), "md5";
            };
        };
    }
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

done_testing;

sub create_diskimage {
    my ($image, $mount_point) = @_;
    system(qw(dd if=/dev/zero), "of=$image", qw(count=4 bs=1M)) == 0
        or die "dd failed:$?";
    system("mke2fs", $image) == 0
        or die "mke2fs failed:$?";
    system("mount", $image, $mount_point) == 0
        or die "failed to mount $image at $mount_point:$?";
    for my $size (@FILESIZE) {
        open my $fh, ">", "$mount_point/$size.txt"
            or die "failed to open $mount_point/$size.txt:$!";
        print $fh "1"
            for 1..$size;
        close $fh;
    }
    system("umount", $mount_point) == 0
        or die "failed to unmount:$?";
}
