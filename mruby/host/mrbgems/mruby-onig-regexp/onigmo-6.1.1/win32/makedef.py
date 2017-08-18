#!/usr/bin/env python

from __future__ import print_function
import re

header_files = (
    "onigmo.h", "regenc.h",
    "onigmognu.h", "onigmoposix.h"
)

exclude_symbols = [
    "OnigEncodingKOI8",

    # USE_UPPER_CASE_TABLE
    "OnigEncAsciiToUpperCaseTable",
    "OnigEncISO_8859_1_ToUpperCaseTable",
]

features = {
    "USE_VARIABLE_META_CHARS": ("onig_set_meta_char",),
    "USE_CAPTURE_HISTORY": ("onig_get_capture_tree",)
}

for v in features.values():
    exclude_symbols += list(v)

# Check if the features are enabled
with open("regint.h", "r") as f:
    e = set()
    for line in f:
        for k, v in features.items():
            if re.match(r"^#define\s+" + k + r"\b", line):
                e |= set(v)
    exclude_symbols = list(set(exclude_symbols) - e)

symbols = set()

rx1 = re.compile("(ONIG_EXTERN.*)$")
rx2 = re.compile(r"(\w+)( +PV?_\(\(.*\)\)|\[.*\])?;\s*(/\*.*\*/)?$")
for filename in header_files:
    with open(filename, "r") as f:
        for line in f:
            m = rx1.match(line)
            if not m:
                continue
            s = m.group(1)
            if s[-1] != ';':
                s += ' ' + next(f)
            m2 = rx2.search(s)
            if m2 and (not m2.group(1) in exclude_symbols):
                symbols.add(m2.group(1))

print('EXPORTS')
for s in sorted(symbols):
    print('\t' + s)
