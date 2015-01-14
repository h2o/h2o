#! /bin/sh

exec clang-format -i $(git ls-files | grep -v '^deps/' | egrep '\.(c|h)$')
exit $?
