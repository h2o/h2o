#!/usr/bin/env bash
set -xe

CC=clang CXX=clang++ cmake -H. -Bbuild
make -Cbuild VERBOSE=1
