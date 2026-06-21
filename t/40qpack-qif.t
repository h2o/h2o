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

sub decode_prefixed_int {
    my ($bytes, $off_ref, $prefix) = @_;
    my $mask = (1 << $prefix) - 1;
    my $value = ord(substr($bytes, $$off_ref, 1)) & $mask;
    ++$$off_ref;
    return $value
        if $value != $mask;

    my $shift = 0;
    while (1) {
        my $ch = ord(substr($bytes, $$off_ref, 1));
        ++$$off_ref;
        $value += ($ch & 0x7f) << $shift;
        last
            if ($ch & 0x80) == 0;
        $shift += 7;
    }
    return $value;
}

sub skip_literal_string {
    my ($bytes, $off_ref, $prefix) = @_;
    my $len = decode_prefixed_int($bytes, $off_ref, $prefix);
    $$off_ref += $len;
}

sub count_duplicate_instructions {
    my ($encoded) = @_;
    open my $fh, "<", $encoded
        or die "failed to open $encoded:$!";
    binmode $fh;
    local $/;
    my $bytes = <$fh>;
    my $off = 0;
    my $num_duplicates = 0;

    while ($off < length($bytes)) {
        my ($stream_id, $len) = unpack "Q>N", substr($bytes, $off, 12);
        $off += 12;
        my $payload = substr($bytes, $off, $len);
        $off += $len;
        next
            if $stream_id != 0;

        my $payload_off = 0;
        while ($payload_off < length($payload)) {
            my $ch = ord(substr($payload, $payload_off, 1));
            if (($ch & 0x80) == 0x80) {
                decode_prefixed_int($payload, \$payload_off, 6);
                skip_literal_string($payload, \$payload_off, 7);
            } elsif (($ch & 0xc0) == 0x40) {
                skip_literal_string($payload, \$payload_off, 5);
                skip_literal_string($payload, \$payload_off, 7);
            } elsif (($ch & 0xe0) == 0) {
                decode_prefixed_int($payload, \$payload_off, 5);
                ++$num_duplicates;
            } elsif (($ch & 0xe0) == 0x20) {
                decode_prefixed_int($payload, \$payload_off, 5);
            } else {
                die "unknown encoder instruction";
            }
        }
    }

    return $num_duplicates;
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

sub write_shadow_swap_qif {
    my ($path) = @_;
    open my $fh, ">", $path
        or die "failed to open $path:$!";
    # fill the small table with x-a and x-b, then keep hammering the non-resident x-c
    print $fh ":status\t200\nx-a\taaaaaaaaaaaaaaaaaaaa\nx-b\tbbbbbbbbbbbbbbbbbbbb\nx-c\tcccccccccccccccccccc\n\n";
    for (1..120) {
        print $fh ":status\t200\nx-a\taaaaaaaaaaaaaaaaaaaa\n\n";
    }
    for (1..60) {
        print $fh ":status\t200\nx-c\tcccccccccccccccccccc\n\n";
    }
    close $fh;
}

subtest "h2o encoder refines using Duplicate under t-qif" => sub {
    my $qif = "$tmpdir/shadow-swap.qif";
    my $encoded = "$tmpdir/shadow-swap.encoded";
    my $decoded = "$tmpdir/shadow-swap.decoded.qif";
    my $expected = "$tmpdir/shadow-swap.expected.qif";
    my $actual = "$tmpdir/shadow-swap.actual.qif";

    write_shadow_swap_qif($qif);

    my $ret = run_to_file($encoded, $t_qif, "-s", 128, "-b", 10, "-a", "-r", "--refine-after-full=1", $qif);
    is $ret, 0, "encode synthetic swap qif";
    cmp_ok count_duplicate_instructions($encoded), ">", 0, "refinement emitted Duplicate";

    $ret = run_to_file($decoded, $t_qif, "-s", 128, "-b", 10, "-d", "-r", $encoded);
    is $ret, 0, "decode synthetic swap qif";
    normalize_qif($qif, $expected);
    normalize_qif($decoded, $actual);

    my $diff = `diff -u "$expected" "$actual" 2>&1`;
    is $?, 0, "decoded QIF matches synthetic source QIF";
    diag $diff
        if $diff ne "";
};

subtest "h2o encoder freezes when refinement is off (no Duplicate)" => sub {
    my $qif = "$tmpdir/freeze.qif";
    my $encoded = "$tmpdir/freeze.encoded";
    my $decoded = "$tmpdir/freeze.decoded.qif";
    my $expected = "$tmpdir/freeze.expected.qif";
    my $actual = "$tmpdir/freeze.actual.qif";

    write_shadow_swap_qif($qif);

    my $ret = run_to_file($encoded, $t_qif, "-s", 128, "-b", 10, "-a", "-r", "--refine-after-full=0", $qif);
    is $ret, 0, "encode synthetic swap qif with refinement off";
    is count_duplicate_instructions($encoded), 0, "no Duplicate emitted when refinement is off";

    $ret = run_to_file($decoded, $t_qif, "-s", 128, "-b", 10, "-d", "-r", $encoded);
    is $ret, 0, "decode synthetic swap qif with refinement off";
    normalize_qif($qif, $expected);
    normalize_qif($decoded, $actual);

    my $diff = `diff -u "$expected" "$actual" 2>&1`;
    is $?, 0, "decoded QIF matches synthetic source QIF (refinement off)";
    diag $diff
        if $diff ne "";
};

done_testing;
