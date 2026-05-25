use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use t::Util;

my $qif_dir = "deps/qifs";
my $sort_qif = "$qif_dir/bin/sort-qif.pl";
my $t_qif = bindir() . "/t-qif";

plan skip_all => "$t_qif not found"
    unless -x $t_qif;

my $tmpdir = tempdir(CLEANUP => 1);
my $test_index = 0;

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

sub build_cases {
    my @cases;
    for my $encoded (sort glob "$qif_dir/encoded/qpack-05/*/*-hq.out.*") {
        my ($impl, $basename, $table_size, $max_blocked, $ack_mode) =
            $encoded =~ m{encoded/qpack-05/([^/]+)/([^/]+)\.out\.(\d+)\.(\d+)\.(\d+)$}
            or die "unexpected qif filename:$encoded";
        next if $table_size == 0;

        my $qif = "$qif_dir/qifs/$basename.qif";
        die "missing source qif:$qif"
            unless -e $qif;

        my @args = ("-s", $table_size, "-b", $max_blocked);
        push @args, "-r"
            if $basename =~ /resp/;
        push @args, "-d";

        push @cases, {
            name    => "$impl $basename table=$table_size blocked=$max_blocked ack=$ack_mode",
            qif     => $qif,
            encoded => $encoded,
            args    => \@args,
        };
    }
    return @cases;
}

subtest "qpackers qpack-05 dynamic table decode" => sub {
    my @cases = build_cases();
    die "no qpackers qpack-05 dynamic table cases found"
        unless @cases;

    for my $case (@cases) {
        subtest $case->{name} => sub {
            ++$test_index;
            my $decoded = "$tmpdir/$test_index.decoded.qif";
            my $expected = "$tmpdir/$test_index.expected.qif";
            my $actual = "$tmpdir/$test_index.actual.qif";

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
