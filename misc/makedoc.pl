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
    include_path => [ qw(srcdoc/snippets .) ],
);

my @src_files = @ARGV || glob "srcdoc/*.mt";

for my $src_file (@src_files) {
    (my $dst_file = $src_file) =~ s|^srcdoc/(.*)\.mt$|doc/$1\.html|
        or die "file name should be \"src/**.mt\", but got: $src_file";
    print "# generate $dst_file from $src_file\n";
    my @notes;
    $main::context = {
        filename => substr($dst_file, 4),
        prettify => build_mt(
            '<pre class="prettyprint"><code class="language-<?= $_[0] ?>"><?= $_[1] ?></code></pre>',
        ),
        note     => sub {
            my ($note, $index);
            if (looks_like_number($_[0])) {
                $index = $_[0] < 0 ? scalar(@notes) + $_[0] : $_[0];
            } else {
                $index = scalar @notes;
                push @notes, $_[0];
            }
            return render_mt(
                '<sup><a href="#note_<?= $_[0] ?>" title="<?= $_[1] ?>"><?= $_[0] ?></sup></a></sup>',
                $index + 1,
                $notes[$index],
            );
        },
        citations => sub {
            my $output = '';
            if (@notes) {
                $output = $mt->render_file("citations.mt", @notes);
                @notes = ();
            }
            return $output;
        },
    };
    my $output = $mt->render_file($src_file);
    mkpath(dirname($dst_file));

    chmod 0666, $dst_file;
    open my $dst_fh, '>:utf8', $dst_file
        or die "failed to open file:$dst_file:$!";
    print $dst_fh $output;
    close $dst_fh;
    chmod 0444, $dst_file;
}
