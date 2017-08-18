#!/bin/sh
set -e
TEST=./pq_test
if [ -e ./pq_test.exe ]; then
	TEST=./pq_test.exe
fi
$TEST | diff -b $srcdir/pq_expected.txt -
