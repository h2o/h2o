#!/usr/bin/env perl
use strict;
use warnings;
use feature qw/say/;
use FindBin qw/$Bin/;
use JSON;
use Path::Tiny;

# $ENV{INSTAL_DIR} is define in misc/travis/export_env
my $MANIFEST_FILE = $ENV{INSTALL_DIR} . '/cache_manifest.json';

sub usage_exit {
    die "Usage: $0 <check|save> <libname> <version>\n";
}

sub load_manifest {
    my $path = path($MANIFEST_FILE);
    return +{} unless $path->exists;
    return decode_json(path($MANIFEST_FILE)->slurp);
}

sub save_manifest {
    my ($manifest) = @_;
    path($MANIFEST_FILE)->spew(JSON->new->pretty(1)->encode($manifest));
}

sub check {
    my ($libname, $version) = @_;
    my $manifest = load_manifest();
    if (($manifest->{$libname} || '') ne $version) {
        return 1;
    }
    return 0;
}

sub save {
    my ($libname, $version) = @_;
    my $manifest = load_manifest();
    $manifest->{$libname} = $version;
    save_manifest($manifest);
    return 0;
}

sub main {
    usage_exit() if @ARGV < 3;
    
    my ($command, $libname, $expected_version) = @ARGV;
    
    my $ret;
    if ($command eq 'check') {
        return check($libname, $expected_version);
    } elsif ($command eq 'save') {
        return save($libname, $expected_version);
    } else {
        usage_exit();
    }
}

exit main();
