// (C) 2016 Cybozu.

#include "yrmcds.h"

#include <errno.h>

yrmcds_error yrmcds_text_mode(yrmcds* c) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;

#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    int e = pthread_mutex_lock(&c->lock);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#endif // ! LIBYRMCDS_NO_INTERNAL_LOCK

    yrmcds_error ret = YRMCDS_OK;
    if( c->serial != 0 ) {
        ret = YRMCDS_IN_BINARY;
        goto OUT;
    }

    c->text_mode = 1;

  OUT:
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    pthread_mutex_unlock(&c->lock);
#endif
    return ret;
}
