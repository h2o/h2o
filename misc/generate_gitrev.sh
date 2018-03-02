#!/bin/sh
GITREV=$(git rev-parse --short HEAD)
GITTAG=$(git tag --points-at ${GITREV})
CONTENT=""
if [ -z "$GITTAG" ]; then
    CONTENT="#define H2O_GIT_REVISION $GITREV"
fi
OUTPATH="include/h2o/gitrev.h"
if [ ! -f $OUTPATH ] || [ "$CONTENT" != "$(cat $OUTPATH)" ]; then
    echo "$CONTENT" > $OUTPATH
    echo "Updated gitrev.h"
fi
