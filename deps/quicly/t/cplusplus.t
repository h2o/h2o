#! /usr/bin/perl

use strict;
use warnings;
use Test::More;

plan skip_all => "g++ not found"
    unless system("which g++ > /dev/null 2>&1") == 0;

is system(qw(g++ -Iinclude -Ideps/picotls/include --include quicly.h -c -x c++ -Wall /dev/null)), 0;

done_testing;
