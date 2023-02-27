use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

my $tempdir = tempdir(CLEANUP => 1);

plan skip_all => 'curl not found'
    unless prog_exists('curl');

subtest 'trailing-slash' => sub {
  my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: @{[DOC_ROOT]}
EOT

  my $resp = `curl --silent --dump-header /dev/stderr http://127.0.0.1:$server->{port}/index.txt/ 2>&1 > /dev/null`;
  like $resp, qr{^HTTP/1.1 404 File Not Found}s, "status";
};

subtest 'update' => sub {
    my $server = spawn_h2o(<< "EOT");
hosts:
  default:
    paths:
      /:
        file.dir: $tempdir
EOT
    my $fn = 1;
    my $write_file = sub {
        # use write-then-rename pattern; otherwise the behavior would become identical to shrinking an existing file that is covered
        # in t/50file-shrink.t
        open my $fh, ">", "$tempdir/.tmpfile"
            or die "failed to open $tempdir/.tmpfile:$!";
        print $fh shift;
        close $fh;
        rename "$tempdir/.tmpfile", "$tempdir/$fn"
            or die "rename failed:$!";
    };
    run_with_curl($server, sub {
        my ($proto, $port, $curl) = @_;
        $write_file->("hello world");
        my $content = `$curl --silent --show-error $proto://127.0.0.1:$port/$fn`;
        is $content, "hello world";
        $write_file->("good bye");
        $content = `$curl --silent --show-error $proto://127.0.0.1:$port/$fn`;
        is $content, "good bye";
        ++$fn;
    });
};

done_testing;
