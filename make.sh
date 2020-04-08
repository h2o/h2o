#!/usr/bin/bash
set -xe

CC=clang CXX=clang++ cmake -H. -Bbuild
make -Cbuild VERBOSE=1
