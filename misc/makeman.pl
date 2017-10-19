#! /usr/bin/env perl

use strict;
use warnings;
no warnings qw(once);

use File::Basename qw(dirname);
use File::Path qw(mkpath);
use Scalar::Util qw(looks_like_number);
use Text::MicroTemplate qw(build_mt render_mt encoded_string);
use Text::MicroTemplate::File;
use HTML::TokeParser::Simple;
use HTML::Entities;

my $mt = Text::MicroTemplate::File->new(
    include_path => [ qw(../srcdoc/man-snippets/h2o.conf.5 .) ],
);

die "Usage: $0 <src-file> <dst-file>\n"
    unless @ARGV == 2;

my ($src_file, $dst_file) = @ARGV;

$main::context = {
    filename => $dst_file,
    code     => build_mt(
        '.PP
.nf
.RS
<?= $_[0] ?>
.RE
.fi
.PP',
    ),
    example => build_mt(<<'EOT',
.PP
.BR Example:\ 
<?= Text::MicroTemplate::encoded_string(decode_entities($_[0])) ?>
.PP
.nf
.RS
<?= Text::MicroTemplate::encoded_string(decode_entities($_[1])) ?>
.RE
.fi
.PP
EOT
    ),
    directive => sub {
        my %args = @_;
        $mt->wrapper_file("directive.mt", \%args);
    },
    mruby_method => sub {
        my %args = @_;
        $mt->wrapper_file("mruby_method.mt", \%args);
    },
    notes    => [],
    note     => sub {
        my ($index, $html);
        if (looks_like_number($_[0])) {
            $index = $_[0] < 0 ? scalar(@{$main::context->{notes}}) + $_[0] : $_[0];
            $html = $main::context->{notes}->[$index];
        } else {
            $index = scalar @{$main::context->{notes}};
            $html = $_[0];
            push @{$main::context->{notes}}, encoded_string($html);
        }
        my $alt = $html;
        $alt =~ s/<.*?>//g;
        return render_mt(
            ' [<?= $_[0] ?>]',
            $index + 1,
            $alt,
        );
    },
    unhtmlize => sub {
        my ($content) = @_;
        my $ret = "";
        my $parser = HTML::TokeParser::Simple->new( string => $content->as_string() );
        while (my $tok = $parser->get_token) {
            next unless $tok->is_text;
            $ret = $ret . $tok->as_is;
        }
        HTML::Entities::decode_entities($ret);
    },
};
my $output = decode_entities($mt->render_file($src_file));
mkpath(dirname($dst_file));

chmod 0666, $dst_file;
open my $dst_fh, '>:utf8', $dst_file
    or die "failed to open file:$dst_file:$!";
print $dst_fh $output;
close $dst_fh;
