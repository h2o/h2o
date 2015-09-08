#! /usr/bin/perl

use strict;
use warnings;
use Errno ();
use File::Basename qw(basename);

die "Usage: $0 <https://github.com/user/repo> <commit> <dest-dir>\n"
    unless @ARGV == 3;

my ($repo, $commit, $dest) = @ARGV;

run("rm -rf $dest");
mkdir("$dest")
    or $! == Errno::EEXIST or die "failed to (re)create directory:$dest:$!";
run("curl --silent --show-error --location $repo/archive/$commit.tar.gz | (cd $dest && tar x --strip-components 1 -zf -)") == 0
    or die "failed to extract $repo/archive/$commit.tar.gz to $dest";
run("git add -f `find $dest -type f`") == 0
    or die "failed to add files under $dest";
run("git commit -m 'extract $repo @ $commit at $dest' $dest") == 0
    or die "failed to commit";

sub run {
   my $cmd = shift;
   print "$cmd\n";
   system($cmd);
}
