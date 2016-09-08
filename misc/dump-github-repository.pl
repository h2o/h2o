#! /usr/bin/perl

use strict;
use warnings;
use Errno ();
use File::Basename qw(basename);

die "Usage: $0 <https://github.com/user/repo> <commit> <dest-dir> [<path>]\n"
    if @ARGV < 3;

my ($repo, $commit, $dest, $path) = @ARGV;
my $strip_components = 1;
my ($rm_path, $tar_path);

if (defined $path) {
    $path =~ s|/*$||;
    $strip_components += scalar(split "/", $path) - 1;
    $rm_path = "$dest/" . basename $path;
    $tar_path = "*/$path";
} else {
    $path = "";
    $rm_path = "$dest";
    $tar_path = "";
}

run("rm -rf $rm_path");

mkdir("$dest")
    or $! == Errno::EEXIST or die "failed to (re)create directory:$dest:$!";
run("curl --silent --show-error --location $repo/archive/$commit.tar.gz | (cd $dest && tar x --strip-components $strip_components -zf - $tar_path)") == 0
    or die "failed to extract $repo/archive/$commit.tar.gz to $dest";
run("git add -f `find $rm_path -type f`") == 0
    or die "failed to add files under $dest";
run("git commit --allow-empty -m 'extract $repo @ $commit @{[defined $path ? qq{($path)} : '']} at $dest' $dest") == 0
    or die "failed to commit";

sub run {
   my $cmd = shift;
   print "$cmd\n";
   system($cmd);
}
