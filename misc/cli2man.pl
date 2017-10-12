#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use Getopt::Long;

my $synopsis;
my $options;
GetOptions ("synopsis" => \$synopsis,
	"options"  => \$options)
	or die("Error in command line arguments\n");

if (not defined $synopsis and not defined $options) {
	# define both by default
	$synopsis = 1;
	$options = 1;
}

my $in_options = 0;
my ($cur_opt, $cur_long, $cur_arg, $help, $cur_arg_val, $cur_arg_val_help);
my %opts;
my @opts_order;

{
	package Opt;
	sub add_arg {
		my $self = shift;
		my $arg_name = shift;
		$self->{args}->{$arg_name} = undef;
		push(@{$self->{args_order}}, $arg_name);
	}
	sub append_arg_help {
		my $self = shift;
		my $arg_name = shift;
		if (defined $self->{args}->{$arg_name}) {
			$self->{args}->{$arg_name} .= " ";
		} else {
			$self->{args}->{$arg_name} = "";
		}
		$self->{args}->{$arg_name} .= shift;
	}
	sub new {
		my $opt = {
			short => $1,
			long => $2,
			arg => $3,
			arg_help => $4,
			args => {},
			args_order => [],
		};
		bless $opt;
		return $opt;
	}
}

while(<>) {
	if ($in_options && /^$/) {
		$in_options = 0;
	}
	if ($in_options) {
		if (/^\s+-(\w),\s*--(\w+)\s(\w*)\s+(.*)/) {
			($cur_opt, $cur_long, $cur_arg, $help) =  ($1, $2, $3,$4);
			$cur_arg_val = undef;
			$cur_arg_val_help = undef;
			$opts{$cur_opt} = Opt::new($cur_opt, $cur_long, $cur_arg, $help);
			push(@opts_order, $cur_opt);
		} elsif (/^\s+- (\w+):\s+(.*)/) {
			$cur_arg_val = $1;
			$cur_arg_val_help = $2;
			$opts{$cur_opt}->add_arg($cur_arg_val);
			$opts{$cur_opt}->append_arg_help($cur_arg_val, $cur_arg_val_help);
		} elsif (defined $cur_arg_val) {
			if (/^\s+(.*)/) {
				$opts{$cur_opt}->append_arg_help($cur_arg_val, $1);
			}
		}
	}
	if (/Options:/) {
		$in_options = 1;
	}
}

if ($synopsis) {
	print ".SH SYNOPSIS\n";
	print ".B h2o\n";
	foreach my $ok (@opts_order) {
		my $o = $opts{$ok};
		print "[\\fB\\-$o->{short},\\-\\-$o->{long}\\fR]";
		if ($o->{arg}) {
			print " \\fI$o->{arg}\\fR";
		}
		print "\n";
	}
}
if ($options) {
	print ".SH OPTIONS\n";
	foreach my $ok (@opts_order) {
		my $o = $opts{$ok};
		print ".TP\n";
		print ".BR \\-$o->{short} \", \" \\-\\-$o->{long}";
		if ($o->{arg}) {
			print " =\\fI$o->{arg}\\fR";
		}
		if ($o->{arg}) {
			print "\n$o->{arg_help}";
		}
		if (%{$o->{args}}) {
			print "\n.RS";
			foreach my $arg (@{$o->{args_order}}) {
				print "\n.PP\n.PP\n\\'\\fB$arg\\fR\\' : ";
				print "$o->{args}{$arg}\n";
			}
			print "\n.RE";
		}
		print "\n";
	}

}
