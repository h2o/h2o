#!/bin/sh
set -e
TEST=./aeadtest
if [ -e ./aeadtest.exe ]; then
	TEST=./aeadtest.exe
fi
$TEST $srcdir/aeadtests.txt
