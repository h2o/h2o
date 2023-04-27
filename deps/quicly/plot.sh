#!/usr/local/bin/bash

QT="/Users/jiyengar/quic-trace"

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 quicly-trace outputfile"
    exit 1
fi

python quictrace-adapter.py $1 $2.json &&\
$QT/bazel-bin/tools/transform_quic_trace --input_format=json < $2.json > $2.qtr &&\
$QT/bazel-bin/tools/render/render_trace $2.qtr
