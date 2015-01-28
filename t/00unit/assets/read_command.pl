#! /bin/sh
exec perl -x $0 "$@"
#! perl

use strict;
use warnings;

die "expected one arg"
    unless @ARGV == 1;

print $ARGV[0];
exit($ENV{READ_COMMAND_EXIT_STATUS} || 0);
