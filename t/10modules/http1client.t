use strict;
use warnings;
use Test::More;

plan skip_all => 'http1client not found'
    unless -x 'examples/http1client';

is(system("examples/http1client http://www.google.com > /dev/null"), 0);

done_testing;
