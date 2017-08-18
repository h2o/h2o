#!/bin/sh

# Convert name2ctype.kwd to name2ctype.h using GNU gperf.
#
# Usage:
#   convert-name2ctype.sh name2ctype.kwd > name2ctype.h

NAME2CTYPE_OPTIONS='-7 -c -j1 -i1 -t -C -P -T -H uniname2ctype_hash -Q uniname2ctype_pool -N uniname2ctype_p'

# undef USE_UNICODE_PROPERTIES
sed '/^#ifdef USE_UNICODE_PROPERTIES/,/^#endif \/\* USE_UNICODE_PROPERTIES \*\//d' $1 | gperf ${NAME2CTYPE_OPTIONS} > name2ctype-1.h
# define USE_UNICODE_PROPERTIES
sed '/^\(#ifdef USE_UNICODE_PROPERTIES\|#endif \/\* USE_UNICODE_PROPERTIES \*\/\)/d' $1 > name2ctype-2.h
# undef USE_UNICODE_AGE_PROPERTIES
sed '/^#ifdef USE_UNICODE_AGE_PROPERTIES/,/^#endif \/\* USE_UNICODE_AGE_PROPERTIES \*\//d' name2ctype-2.h | gperf ${NAME2CTYPE_OPTIONS} > name2ctype-3.h
# define USE_UNICODE_AGE_PROPERTIES
sed '/^\(#ifdef USE_UNICODE_AGE_PROPERTIES\|#endif \/\* USE_UNICODE_AGE_PROPERTIES \*\/\)/d' name2ctype-2.h | gperf ${NAME2CTYPE_OPTIONS} > name2ctype-4.h
# merge them
diff -DUSE_UNICODE_AGE_PROPERTIES name2ctype-3.h name2ctype-4.h > name2ctype-2.h
diff -DUSE_UNICODE_PROPERTIES name2ctype-1.h name2ctype-2.h
rm name2ctype-?.h
