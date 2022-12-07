#! /usr/bin/perl

use strict;
use warnings;
use Test::More;

plan skip_all => "c++ not found"
    unless system("which c++ > /dev/null 2>&1") == 0;

is system(qw(c++ -Iinclude -Ideps/picotls/include --include quicly.h -c -x c++ -Wall /dev/null)), 0;

done_testing;
