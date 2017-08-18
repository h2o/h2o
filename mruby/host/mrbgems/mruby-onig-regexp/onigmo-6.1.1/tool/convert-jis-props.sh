#!/bin/sh

# Convert props.kwd to props.h using GNU gperf.
#
# Usage:
#   ./tool/convert-jis-props enc/jis/props.kwd enc/jis/props.h

JIS_PROPS_OPTIONS='-k1,3 -7 -c -j1 -i1 -t -C -P -t --ignore-case -H onig_jis_property_hash -Q onig_jis_property_pool -N onig_jis_property'

gperf $JIS_PROPS_OPTIONS $1 | \
    sed 's/(int)(long)&((\([a-zA-Z_0-9 ]*[a-zA-Z_0-9]\) *\*)0)->\([a-zA-Z0-9_]*\),/(char)offsetof(\1, \2),/g' > $2
