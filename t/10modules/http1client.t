use strict;
use warnings;
use Test::More;

plan skip_all => 'http1client not found'
    unless -x 'examples/libh2o/http1client';

is(system("examples/libh2o/http1client http://kazuhooku.com > /dev/null"), 0);

done_testing;
