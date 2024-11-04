#!/bin/sh
# usage:
#    deploy.sh # build but not publish the image
#    PUBLISH=1 TAG=foo deploy.sh # build and publish the image as `foo`
set -xe
DIRNAME=$(dirname "$0")
TAG=${TAG:=latest}

docker build -t h2oserver/quicly-interop-runner:$TAG -f $DIRNAME/Dockerfile . --build-arg CACHEBUST=$(date +%s)

if [ "$PUBLISH" = "1" ]
then
  docker push h2oserver/quicly-interop-runner:$TAG
fi
