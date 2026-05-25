use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

my $qif_dir = "deps/qifs";
my $sort_qif = "$qif_dir/bin/sort-qif.pl";
my $t_qif = bindir() . "/t-qif";

plan skip_all => "$qif_dir is not initialized"
    unless -e "$qif_dir/qifs/fb-req-hq.qif" && -x $sort_qif;
plan skip_all => "$t_qif not found"
    unless -x $t_qif;

my $tmpdir = tempdir(CLEANUP => 1);

sub run_to_file {
    my ($out, @cmd) = @_;

    open my $fh, ">", $out
        or die "failed to open $out:$!";
    my $pid = fork;
    die "fork failed:$!"
        unless defined $pid;
    if ($pid == 0) {
        open STDOUT, ">&", $fh
            or die "failed to redirect stdout:$!";
        exec @cmd;
        die "failed to exec @cmd:$!";
    }
    close $fh;

    waitpid $pid, 0;
    return $?;
}

sub normalize_qif {
    my ($in, $out) = @_;
    my $ret = run_to_file($out, $sort_qif, "--strip-comments", "--http", $in);
    is $ret, 0, "normalize $in";
}

subtest "qpackers qpack-05 dynamic table decode" => sub {
    my @cases = (
        {
            name    => "nghttp3 fb requests",
            qif     => "$qif_dir/qifs/fb-req-hq.qif",
            encoded => "$qif_dir/encoded/qpack-05/nghttp3/fb-req-hq.out.4096.100.0",
            args    => ["-s", 4096, "-b", 100, "-d"],
        },
        {
            name    => "nghttp3 fb responses",
            qif     => "$qif_dir/qifs/fb-resp-hq.qif",
            encoded => "$qif_dir/encoded/qpack-05/nghttp3/fb-resp-hq.out.4096.100.0",
            args    => ["-s", 4096, "-b", 100, "-r", "-d"],
        },
        {
            name    => "nghttp3 netbsd requests",
            qif     => "$qif_dir/qifs/netbsd-hq.qif",
            encoded => "$qif_dir/encoded/qpack-05/nghttp3/netbsd-hq.out.512.100.0",
            args    => ["-s", 512, "-b", 100, "-d"],
        },
    );

    for my $case (@cases) {
        subtest $case->{name} => sub {
            my $decoded = "$tmpdir/$case->{name}.decoded.qif";
            my $expected = "$tmpdir/$case->{name}.expected.qif";
            my $actual = "$tmpdir/$case->{name}.actual.qif";

            my $ret = run_to_file($decoded, $t_qif, @{$case->{args}}, $case->{encoded});
            is $ret, 0, "decode $case->{encoded}";

            normalize_qif($case->{qif}, $expected);
            normalize_qif($decoded, $actual);

            my $diff = `diff -u "$expected" "$actual" 2>&1`;
            is $?, 0, "decoded QIF matches source QIF";
            diag $diff
                if $diff ne "";
        };
    }
};

done_testing;
