#!/usr/bin/env python
import sys
import json

if len(sys.argv) != 2:
    print "Usage: find-cids.py inTrace.jsonl"
    sys.exit(1)

cids = {}
f = open(sys.argv[1], 'r')
for line in f:
    event = json.loads(line)
    if event["type"] != "" and event["type"] == "accept":
        cids[event["conn"]] = None

print "Connection IDs:", cids.keys()
f.close()
