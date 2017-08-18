#!/bin/sh
set -e
TEST=./evptest
if [ -e ./evptest.exe ]; then
	TEST=./evptest.exe
fi
$TEST $srcdir/evptests.txt
