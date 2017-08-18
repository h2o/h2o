#!/bin/sh
./pidwraptest > pidwraptest.txt
while read a b;
do
	if [ "$a" = "$b" ]; then
		echo "FAIL: $a = $b"
		return 2
	else
		echo "PASS: $a != $b"
	fi
done < pidwraptest.txt
