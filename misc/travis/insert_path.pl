#!/usr/bin/env perl
use strict;
use warnings;

# NOTE:
# Travis CI requires some path to be placed at first, but
# we want our local bin directories to precede /usr/local/bin and /usr/bin,
# so tweak here.

my @additional_paths = @ARGV;
my @paths = split(/:/, $ENV{PATH});
my @tweaked;
while (@paths) {
    my $path = shift(@paths);
    if ($path eq '/usr/local/bin' || $path eq '/usr/bin') {
        push(@tweaked, @additional_paths, $path, @paths);
        last;
    }
    push(@tweaked, $path);
}
print join(':', @tweaked);
