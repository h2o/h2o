#!/bin/sh
set -xe
DIRNAME=$(dirname "$0")
TAG=${TAG:=latest}
docker build -t h2oserver/quicly-interop-runner:$TAG -f $DIRNAME/Dockerfile . --build-arg CACHEBUST=$(date +%s)
docker push h2oserver/quicly-interop-runner:$TAG
