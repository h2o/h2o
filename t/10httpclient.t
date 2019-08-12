use strict;
use warnings;
use Test::More;
use t::Util;

my $fn = bindir() . "/examples-httpclient";

plan skip_all => 'http1client not found'
    unless -x $fn;

is(system("$fn http://kazuhooku.com > /dev/null"), 0);

done_testing;
