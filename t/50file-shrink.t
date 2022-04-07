use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use IO::Handle;
use Net::EmptyPort qw(empty_port wait_port);
use Test::More;
use Time::HiRes qw(time);
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);
my $testdata = "hello world\n" x 100_000;

subtest "no-batch" => sub {
    run_tests(1);
};

subtest "batch=16" => sub {
    plan skip_all => "use of io_uring not enabled"
        unless server_features()->{io_uring};
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
        header.add: "X-Traffic: 200000" # takes about 5 seconds
throttle-response: ON
@{[$batch_size != 1 ? "io_uring-batch-size: $batch_size" : ""]}
EOT
    wait_port({port => $quic_port, proto => "udp"});

    my $doit = sub {
        my $fetch = shift;

        # write file
        open my $fh, ">", "$tempdir/index.txt"
            or die "failed to create file $tempdir/index.txt:$!";
        print $fh $testdata;
        $fh->flush;

        my $normal_time = measure_elapsed(sub {
            subtest "normal" => sub {
                my $resp = $fetch->("index.txt");
                is $?, 0, "exit status";
                is md5_hex($resp), md5_hex($testdata), "data";
            };
        });
        my $shrink_time = measure_elapsed(sub {
            subtest "shrink" => sub {
                # spawn child prcoess that truncates the file after 2 seconds
                my $pid = fork;
                die "fork failed:$!"
                    unless defined $pid;
                if ($pid == 0) {
                    sleep 2;
                    truncate($fh, 800000)
                        or die "truncate failed:$!";
                    exit 0;
                }
                # fetch file (which would return a partial result)
                my $resp = $fetch->("index.txt");
                isnt $?, 0, "exit status";
                cmp_ok length($resp), "<", length($testdata), "length";
                is md5_hex($resp), md5_hex(substr($testdata, 0, length($resp))), "data";
                # reap pid
                while (waitpid($pid, 0) != $pid) {}
            };
        });
        cmp_ok $normal_time, ">", $shrink_time, "shrink should not wait until I/O timeout";
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
}

done_testing;

sub measure_elapsed {
    my $start = time;
    shift->();
    return time - $start;
}
