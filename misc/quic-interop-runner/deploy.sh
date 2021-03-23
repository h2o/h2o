#!/bin/sh
set -xe
DIRNAME=$(dirname "$0")
docker build -t h2oserver/quicly-interop-runner:latest -f $DIRNAME/Dockerfile . --build-arg CACHEBUST=$(date +%s)
docker push h2oserver/quicly-interop-runner:latest
