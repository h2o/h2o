#!/bin/sh
set -e
TEST=./ocsp_test
if [ -e ./ocsp_test.exe ]; then
	TEST=./ocsp_test.exe
fi
$TEST www.amazon.com 443
$TEST cloudflare.com 443
