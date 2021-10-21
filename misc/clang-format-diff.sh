#! /bin/sh

git diff -U0 --no-color master -- '*.c' '*.h' | clang-format-diff.py -i -p1
exit $?
