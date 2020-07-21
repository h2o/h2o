#!/bin/bash
# To build Docker images for CI.
# https://hub.docker.com/r/h2oserver/h2o-ci

set -xe

IMAGE_NAME=h2oserver/h2o-ci
REVS="ubuntu1604 ubuntu2004"

PROJECT_ROOT_DIR=$(realpath "$(dirname $0)/../..")
cd $PROJECT_ROOT_DIR

docker login

for rev  in $REVS ; do
    docker build --tag "${IMAGE_NAME}:${rev}" -f "misc/docker-ci/Dockerfile.${rev}" .
    docker push "${IMAGE_NAME}:${rev}"
done
