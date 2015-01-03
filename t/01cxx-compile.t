use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'g++ not found'
    unless prog_exists('g++');

my $ret = system("g++ -I deps/picohttpparser -I include include/h2o.h");
is $ret, 0, "compile h2o.h using g++";

done_testing;
