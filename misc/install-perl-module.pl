#! /usr/bin/perl

use strict;
use warnings;

sub run_cmd {
    my $cmd = shift;
    print "$cmd\n";
    system($cmd) == 0
        or die "aborting..., command failed with $?";
}

sub install_module {
    my $module = shift;
    print "checking if $module is installed...\n";
    if (system("perl -M$module -e '' > /dev/null 2>&1") != 0) {
        run_cmd("cpanm --sudo --notest $module");
    }
}

print "checking if cpanm is installed...\n";
if (system("which cpanm > /dev/null 2>&1") != 0) {
    run_cmd("curl -L http://cpanmin.us | perl - --sudo --notest App::cpanminus");
}

install_module($_)
    for @ARGV;
