use strict;
use warnings;
use Test::More;
use t::Util;

my $progname = "h2o-httpclient";
my $progpath = bindir() . "/$progname";
plan skip_all => "$progname not found"
    unless -x $progpath;

is(system("$progpath http://kazuhooku.com > /dev/null"), 0);

done_testing;
