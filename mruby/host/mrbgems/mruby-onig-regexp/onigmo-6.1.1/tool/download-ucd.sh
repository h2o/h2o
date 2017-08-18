#!/bin/bash

files='Blocks.txt CaseFolding.txt DerivedAge.txt DerivedCoreProperties.txt PropertyAliases.txt PropertyValueAliases.txt PropList.txt Scripts.txt SpecialCasing.txt UnicodeData.txt auxiliary/GraphemeBreakProperty.txt'

if [ -z $1 ]; then
	echo "usage: $0 UNICODE_VERSION"
	exit 1
fi
UNICODE_VERSION=$1

# remove old files
if [ -d $UNICODE_VERSION ]; then
	cd $UNICODE_VERSION
	rm ${files//auxiliary\//}
	cd -
fi

mkdir -p $UNICODE_VERSION
cd $UNICODE_VERSION

for i in $files; do
	echo http://www.unicode.org/Public/${UNICODE_VERSION}/ucd/$i
done | xargs wget
