#!/bin/bash
# To build Docker images for CI and push the artifacts to Docker Hub.
# https://hub.docker.com/r/h2oserver/h2o-ci
#
# usage: build.sh [--build-only] [variants...]
#        variants specifies Docker.$variant (defaults to: ubuntu1604 ubuntu2004)
#        --build-only skips push to Docker Hub.

set -e

DEFAULT_VARIANTS="ubuntu1604 ubuntu2004"

IMAGE_NAME=h2oserver/h2o-ci

SCRIPT_DIR=$(realpath $(dirname $0))
PROJECT_ROOT_DIR=$(realpath "${SCRIPT_DIR}/../..")

# The build directory must be empty to avoid include files which are should not be published.
BUILD_DIR="$TMPDIR/h2o.$$.$(date +%s)"
mkdir -p "$BUILD_DIR"
trap 'rm -rf "${BUILD_DIR}"' 0
cd $BUILD_DIR

variants=""
push_only=0

while [ "$1" != "" ] ; do
    case "$1" in
    --build-only)
        push_only=1
        ;;
    --help)
        echo "Usage: build.sh [--build-only] [variants...]"
        exit 1
        ;;
    --*)
        echo "Unknown option: $1"
        exit 1
        ;;
    *)
        if [ ! -f "${SCRIPT_DIR}/Dockerfile.$1" ] ; then
            echo "No variant defined: $1 (${SCRIPT_DIR}/Dockerfile.$1 not found)"
            exit 1
        fi
        variants="$variants $1"
        ;;
    esac
    shift
done

if [ "$variants" == "" ] ; then
    variants="${DEFAULT_VARIANTS}"
fi

function run_with_echo() {
    echo "> $@"
    "$@"
}

if [ $push_only == 0 ] ; then
    run_with_echo docker login
fi

for variant  in $variants ; do
    run_with_echo docker build --tag "${IMAGE_NAME}:${variant}" -f "${SCRIPT_DIR}/Dockerfile.${variant}" "${PROJECT_ROOT_DIR}"

    if [ $push_only == 0 ] ; then
        run_with_echo docker push "${IMAGE_NAME}:${variant}"
    fi
done
