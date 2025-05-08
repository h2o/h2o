use strict;
use warnings;
use BSD::Resource;
use File::Temp qw(tempdir);
use Path::Tiny;
use Test::More;
use t::Util;

plan skip_all => 'io_uring support is off'
    unless server_features()->{io_uring};
plan skip_all => 'h2load not found'
    unless prog_exists('h2load');

my $tempdir = tempdir(CLEANUP => 1);

# upstream is spawned before setrlimit(2)
my $upstream = spawn_h2o(<< "EOT");
num-threads: 1
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT

# allow each process open only as many as 30 files
setrlimit(RLIMIT_NOFILE, 30, 30);

subtest "file" => sub {
    doit(<< "EOT");
file.io_uring: ON
hosts:
  default:
    paths:
      /:
        file.dir: t/assets/doc_root
EOT
};

subtest "proxy" => sub {
    doit(<< "EOT");
hosts:
  default:
    paths:
      "/":
        proxy.reverse.url: http://127.0.0.1:@{[$upstream->{port}]}/
EOT
};

undef $upstream;

done_testing();

sub doit {
    my $conf = shift;
    my $server = spawn_h2o(<< "EOT");
num-threads: 1
max-connections: 20
error-log: $tempdir/error.log
$conf
EOT

    # Check we get some 200s (we might get 503s due to not being able to open the file rather than pipe), and that we see some
    # pipe errors. The test is run twice to make sure that the server did not crash in the first iteration.
    for (1..2) {
        subtest "run $_" => sub {
            my $bench_out = `h2load -n 400 -c 20 -t 1 http://127.0.0.1:@{[$server->{port}]}/halfdome.jpg`;
            diag $bench_out;
            like $bench_out, qr/status codes: [1-9][0-9]* 2xx,/, "some 200s";
            like path("$tempdir/error.log")->slurp,
                qr{failed to allocate a pipe for async I/O; falling back to blocking I/O}, "some pipe errors";
        };
    }
}
