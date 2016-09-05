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
    die "Usage: $0 <check|save|show> <libname> <version>\n";
}

sub load_file {
    my $path = path($MANIFEST_FILE);
    return undef unless $path->exists;
    return path($MANIFEST_FILE)->slurp;
}

sub load_manifest {
    my $data = load_file();
    return +{} unless $data;
    return decode_json($data);
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

sub show {
    my $content = load_file();
    return 1 unless $content;
    print $content;
    return 0;
}

sub main {
    my $command = shift || '';

    my $ret;
    if ($command eq 'check') {
        usage_exit() if @_ < 2;
        return check(@_);
    } elsif ($command eq 'save') {
        usage_exit() if @_ < 2;
        return save(@_);
    } elsif ($command eq 'show') {
        return show();
    } else {
        usage_exit();
    }
}

exit main(@ARGV);
