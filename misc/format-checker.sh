#!/bin/bash

rev=HEAD^
clang_format=clang-format

while getopts ":f:r:" opt; do
	case $opt in
	f)
		clang_format=$OPTARG
		;;
	r)
		rev=$OPTARG
		;;
	\?)
		echo "Usage: $0 [options]"
		echo ""
		echo "Options:"
		echo "  -f  Specify a command to use as a formatter [default=clang-format]"
		echo "  -r  Specify rev to use as a base commit (any file changed after rev will be checked) [default=HEAD^]"
		exit 1
	esac
done

cd `git rev-parse --show-toplevel`
files=`git diff --cached --name-only ${rev} | egrep -v '(^deps/|/_|^handler/mimemap/defaults\.c\.h)' | grep -e '.*\.[ch]\(\.in\)\?$'`

if [ ! $( command -v ${clang_format} ) ]; then
	echo "Cannot execute ${clang_format}"
	exit 1
fi

tmpdir=`mktemp --tmpdir -d h2o-format-checker.XXXXXX`
if [ $? != 0 ]; then
	echo "Failed to create a temp directory"
    exit 1
fi

# Copy the style file under tmpdir, otherwise clang-format may not pick up the style
# (even though it is located in the current directory)
cp .clang-format ${tmpdir}/

ret=0

# Verify code formatting using clang-format
for f in $files; do
	git checkout-index --prefix=${tmpdir}/ $f
	index=${tmpdir}/$f # File from current index
	correct=$tmpdir/${f}.correct # File with correct format
	${clang_format} -style=file $index > $correct
	diff -u $index $correct
	if [ $? != 0 ]; then
		ret=1
	fi
done

rm -rf $tmpdir

exit $ret
