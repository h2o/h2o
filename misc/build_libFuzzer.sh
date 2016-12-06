#!/bin/sh

[ -e libFuzzer.a ] && exit 0
[ -d Fuzzer ] || git clone https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
Fuzzer/build.sh
