#!/usr/bin/env perl
# usage: generate_gitrev.pl [output_header_path]
use strict;
use warnings;

my($outpath) = @ARGV;

my $gitrev = exec_git_command('git rev-parse --short HEAD') or die "failed to get current revision";
my $content = "#define H2O_GITREV $gitrev\n";

my $current = '';
if (defined($outpath)) {
    if (open(my $fh, '<', $outpath)) {
        local $/;
        $current = <$fh>;
    }
}

if ($content ne $current) {
    my $fh;
    if (defined $outpath) {
        open($fh, '>', $outpath) or die "failed to open $outpath: $!";
    } else {
        $fh = \*STDOUT;
    }
    print $fh $content;

    if (defined $outpath) {
        print "Updated $outpath with $gitrev\n";
    }
}

sub exec_git_command {
    my ($cmd) = @_;
    my $out = `$cmd`;
    chomp $out;
    $out;
}
