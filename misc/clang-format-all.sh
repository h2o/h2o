#! /bin/sh

exec clang-format -i $(git ls-files | egrep -v '(^deps/|/_)' | egrep '\.(c|h)$')
exit $?
