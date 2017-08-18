#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Usage:
#   $ python update-doc.py UCD_DIR > ../doc/UnicodeProps.txt

from __future__ import print_function
import sys
import os
import re
import datetime

onig_ver = "6.0.0"
ucddir = "."

def print_list(arr, title):
    print()
    print("*", title)
    for i in arr:
        print("    " + i)

def output_header():
    d = datetime.date.today()
    print("Onigmo (Oniguruma-mod) Unicode Properties  Version %s    %04d/%02d/%02d"
            % (onig_ver, d.year, d.month, d.day))

    posix_brackets = [
        "Alpha", "Blank", "Cntrl", "Digit", "Graph", "Lower", "Print",
        "Punct", "Space", "Upper", "XDigit", "Word", "Alnum", "ASCII",
        "XPosixPunct"
        ]
    specials = ["Any", "Assigned"]

    print_list(posix_brackets, "POSIX brackets")
    print_list(specials, "Special")
    return set(posix_brackets) | set(specials)

def output_categories():
    categories = set(["LC", "Cn"])
    pattern = re.compile('^.*?;.*?;(..);')
    with open(ucddir + os.sep + 'UnicodeData.txt', 'r') as f:
        for line in f:
            res = pattern.match(line)
            if not res:
                continue
            categories.add(res.group(1))
            categories.add(res.group(1)[0]) # Major category
    print_list(sorted(categories), "Major and General Categories")
    return categories

def output_scripts(filename, title, add=[]):
    scripts = set(add)
    pattern = re.compile('^.*?; (\w+) # ')
    with open(filename, 'r') as f:
        for line in f:
            res = pattern.match(line)
            if not res:
                continue
            scripts.add(res.group(1))
    print_list(sorted(scripts), title)
    return scripts

def output_aliases(scripts):
    aliases = set()
    pattern = re.compile('^(\w+) *; (\w+)')
    with open(ucddir + os.sep + 'PropertyAliases.txt', 'r') as f:
        for line in f:
            res = pattern.match(line)
            if not res:
                continue
            if (res.group(2) in scripts) and (res.group(1) not in scripts):
                aliases.add(res.group(1))
    print_list(sorted(aliases), "PropertyAliases")
    return aliases

def output_valuealiases(scripts):
    scripts |= set(["cntrl", "digit", "punct"]) # exclude them
    aliases = list()
    aliases_sc = list()
    pattern = re.compile('^(gc|sc) ; (\w+) *; (\w+)(?: *; (\w+))?')
    with open(ucddir + os.sep + 'PropertyValueAliases.txt', 'r') as f:
        for line in f:
            res = pattern.match(line)
            if not res:
                continue
            if (res.group(1) == "gc"):
                if res.group(2) in scripts:
                    if res.group(3) not in scripts:
                        aliases.append(res.group(3))
                    if res.group(4) and (res.group(4) not in scripts):
                        aliases.append(res.group(4))
            else:
                if res.group(3) in scripts:
                    if res.group(2) not in scripts:
                        aliases_sc.append(res.group(2))
                    if res.group(4) and (res.group(4) not in scripts):
                        aliases_sc.append(res.group(4))

    print_list(aliases, "PropertyValueAliases (General_Category)")
    print_list(aliases_sc, "PropertyValueAliases (Script)")
    return set(aliases) | set(aliases_sc)

def output_ages():
    ages = set()
    pattern = re.compile('^[\dA-F.]+ *; ([\d.]+)')
    with open(ucddir + os.sep + 'DerivedAge.txt', 'r') as f:
        for line in f:
            res = pattern.match(line)
            if not res:
                continue
            ages.add("Age=" + res.group(1))
    print_list(sorted(ages), "DerivedAges")
    return ages

def output_blocks():
    blocks = list()
    pattern = re.compile('^[\dA-F.]+ *; ([-\w ]+)')
    with open(ucddir + os.sep + 'Blocks.txt', 'r') as f:
        for line in f:
            res = pattern.match(line)
            if not res:
                continue
            blocks.append("In_" + re.sub('\W', '_', res.group(1)))
    blocks.append("In_No_Block")
    print_list(blocks, "Blocks")
    return set(blocks)

def main():
    global ucddir
    if len(sys.argv) > 1:
        ucddir = sys.argv[1]
    scripts = set()
    scripts |= output_header()
    scripts |= output_categories()
    scripts |= output_scripts(ucddir + os.sep + 'Scripts.txt', 'Scripts', ["Unknown"])
    scripts |= output_scripts(ucddir + os.sep + 'DerivedCoreProperties.txt', 'DerivedCoreProperties')
    scripts |= output_scripts(ucddir + os.sep + 'PropList.txt', 'PropList')
    output_aliases(scripts)
    output_valuealiases(scripts)
    output_ages()
    output_blocks()

if __name__ == '__main__':
    main()
