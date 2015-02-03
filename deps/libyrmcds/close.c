// (C) 2013 Cybozu.

#include "yrmcds.h"

#include <stdlib.h>
#include <unistd.h>

yrmcds_error yrmcds_close(yrmcds* c) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
    if( c->sock == -1 )
        return YRMCDS_OK;

    close(c->sock);
    c->sock = -1;
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    pthread_mutex_destroy(&(c->lock));
#endif
    free(c->recvbuf);
    c->recvbuf = NULL;
    free(c->decompressed);
    c->decompressed = NULL;
    return YRMCDS_OK;
}
