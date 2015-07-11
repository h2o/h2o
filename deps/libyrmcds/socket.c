// (C) 2013 Cybozu et al.

#include "yrmcds.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

yrmcds_error yrmcds_shutdown(yrmcds* c) {
    if( c == NULL )
        return YRMCDS_BAD_ARGUMENT;
    if( shutdown(c->sock, SHUT_RD) == -1 ) {
        return YRMCDS_SYSTEM_ERROR;
    }
    return YRMCDS_OK;
}

int yrmcds_fileno(yrmcds* c) {
    return c->sock;
}

yrmcds_error yrmcds_set_timeout(yrmcds* c, int timeout) {
    if( c == NULL || timeout < 0 )
        return YRMCDS_BAD_ARGUMENT;

    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    if( setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1 )
        return YRMCDS_SYSTEM_ERROR;
    if( setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1 )
        return YRMCDS_SYSTEM_ERROR;
    return YRMCDS_OK;
}
