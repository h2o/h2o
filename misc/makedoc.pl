#! /usr/bin/env perl

use strict;
use warnings;
no warnings qw(once);

use File::Basename qw(dirname);
use File::Path qw(mkpath);
use Scalar::Util qw(looks_like_number);
use Text::MicroTemplate qw(build_mt render_mt);
use Text::MicroTemplate::File;

my $mt = Text::MicroTemplate::File->new(
    include_path => [ qw(../srcdoc/snippets .) ],
);

die "Usage: $0 <src-file> <dst-file>\n"
    unless @ARGV == 2;

my ($src_file, $dst_file) = @ARGV;

$main::context = {
    filename => $dst_file,
    code     => build_mt(
        '<pre><code><?= $_[0] ?></code></pre>',
    ),
    notes    => [],
    note     => sub {
        my ($note, $index);
        if (looks_like_number($_[0])) {
            $index = $_[0] < 0 ? scalar(@{$main::context->{notes}}) + $_[0] : $_[0];
        } else {
            $index = scalar @{$main::context->{notes}};
            push @{$main::context->{notes}}, $_[0];
        }
        return render_mt(
            '<sup><a href="#note_<?= $_[0] ?>" title="<?= $_[1] ?>"><?= $_[0] ?></sup></a></sup>',
            $index + 1,
            $main::context->{notes}->[$index],
        );
    },
};
my $output = $mt->render_file($src_file);
mkpath(dirname($dst_file));

chmod 0666, $dst_file;
open my $dst_fh, '>:utf8', $dst_file
    or die "failed to open file:$dst_file:$!";
print $dst_fh $output;
close $dst_fh;
