#!/bin/sh
GITREV=$(git rev-parse --short HEAD)
CONTENT="#define H2O_GIT_REVISION $GITREV"
OUTPATH="include/h2o/gitrev.h"
if [ ! -f $OUTPATH ] || [ "$CONTENT" != "$(cat $OUTPATH)" ]; then
    echo "$CONTENT" > $OUTPATH
    echo "Updated gitrev.h"
fi
