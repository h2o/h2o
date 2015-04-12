#! /bin/sh

exec clang-format -i $(git ls-files | egrep -v '(^deps/|/_|^handler/mimemap/defaults\.c\.h)' | egrep '\.(c|h)$')
exit $?
