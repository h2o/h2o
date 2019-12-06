#!/bin/sh

[ -e libFuzzer.a ] && exit 0
[ -d Fuzzer ] || git clone https://github.com/llvm-mirror/compiler-rt.git Fuzzer
#git checkout 29d1659edabe4ba2396f9697915bb7a0880cbd2f
Fuzzer/lib/fuzzer/build.sh
