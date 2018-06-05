#!/usr/bin/env perl
use strict;
use warnings;

my $gitrev = exec_git_command('git rev-parse --short HEAD') or die "failed to get current revision";
my $content = "#define H2O_GITREV $gitrev\n";
my $outpath = 'include/h2o/gitrev.h';

my $current = -f $outpath ? do {
    open(my $fh, '<', $outpath) or die "failed to open $outpath: $!";
    join('', <$fh>);
} : '';

if ($content ne $current) {
    open(my $fh, '>', $outpath) or die "failed to open $outpath: $!";
    print $fh $content;
    print "Updated $outpath\n";
}

sub exec_git_command {
    my ($cmd) = @_;
    my $out = `$cmd`;
    chomp $out;
    $out;
}
