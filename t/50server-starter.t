use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

plan skip_all => 'start_server not found'
    unless prog_exists('start_server');

my $tempdir = tempdir(CLEANUP => 1);

my $server = spawn_h2o({
    opts => [ qw(--mode=master) ],
    conf => << "EOT",
pid-file: $tempdir/h2o.pid
hosts:
  default:
    paths:
      /:
        file.dir: @{[ DOC_ROOT ]}
EOT
});

subtest 'before-HUP' => sub {
    is read_file("$tempdir/h2o.pid"), "$server->{pid}\n", "pid";
    fetch_test();
};
kill 'HUP', $server->{pid};
sleep 1;
subtest 'after-HUP' => sub {
    fetch_test();
    is read_file("$tempdir/h2o.pid"), "$server->{pid}\n", "pid unchanged";
};

done_testing;

sub fetch_test {
    plan skip_all => 'curl not found'
        unless prog_exists('curl');

    my $doit = sub {
        my ($proto, $port) = @_;
        my $content = `curl --silent --show-error --insecure $proto://127.0.0.1:$port/`;
        is md5_hex($content), md5_file(DOC_ROOT . "/index.txt"), $proto;
    };
    $doit->("http", $server->{port});
    $doit->("https", $server->{tls_port});
}

sub read_file {
    my $fn = shift;
    open my $fh, '<', $fn
        or die "failed to open file:$fn:$!";
    join '', <$fh>;
}
