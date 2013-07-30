// (C) 2013 Cybozu.

#include "yrmcds.h"

#include <endian.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

static const size_t BINARY_HEADER_SIZE = 24;
static const size_t MAX_DATA_SIZE = ((size_t)1) << 30;

static inline void hton64(uint64_t i, char* p) {
    uint64_t n = htobe64(i);
    memcpy(&n, p, sizeof(n));
}

static inline void hton32(uint32_t i, char* p) {
    uint32_t n = htobe32(i);
    memcpy(&n, p, sizeof(n));
}

static inline void hton16(uint16_t i, char* p) {
    uint16_t n = htobe16(i);
    memcpy(&n, p, sizeof(n));
}

static yrmcds_error send_command(
    yrmcds* c, yrmcds_command cmd, uint64_t cas, uint32_t* serial,
    size_t key_len, const char* key,
    size_t extras_len, const char* extras,
    size_t data_len, const char* data) {
    if( cmd < 0 || cmd >= YRMCDS_CMD_BOTTOM ||
        key_len > 65535 || extras_len > 127 || data_len > MAX_DATA_SIZE ||
        (key_len != 0 && key == NULL) ||
        (extras_len != 0 && extras == NULL) ||
        (data_len != 0 && data == NULL) )
        return YRMCDS_BAD_ARGUMENT;

    char h[BINARY_HEADER_SIZE];
    memset(h, 0, sizeof(h));
    h[0] = '\x80';
    h[1] = (char)cmd;
    hton16((uint16_t)key_len, &h[2]);
    h[4] = (char)extras_len;
    uint32_t total_len = key_len + extras_len + data_len;
    hton32(total_len, &h[8]);
    hton64(cas, &h[16]);

    int e = pthread_mutex_lock(&c->lock);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }

    yrmcds_error ret = YRMCDS_OK;
    c->serial = c->serial + 1;
    memcpy(&h[12], &c->serial, 4);
    if( serial != NULL )
        *serial = c->serial;

    struct iovec iov[4];
    int iovcnt = 1;
    iov[0].iov_base = h;
    iov[0].iov_len = sizeof(h);

    if( extras_len > 0 ) {
        iov[iovcnt].iov_base = (void*)extras;
        iov[iovcnt].iov_len = extras_len;
        iovcnt++;
    }
    if( key_len > 0 ) {
        iov[iovcnt].iov_base = (void*)key;
        iov[iovcnt].iov_len = key_len;
        iovcnt++;
    }
    if( data_len > 0 ) {
        iov[iovcnt].iov_base = (void*)data;
        iov[iovcnt].iov_len = data_len;
        iovcnt++;
    }

    while( iovcnt > 0 ) {
        ssize_t n = writev(c->sock, iov, iovcnt);
        if( n == -1 ) {
            if( errno == EINTR ) continue;
            ret = YRMCDS_SYSTEM_ERROR;
            goto OUT;
        }
        while( n > 0 ) {
            if( n < iov[0].iov_len ) {
                iov[0].iov_base = (char*)iov[0].iov_base + n;
                iov[0].iov_len -= n;
                break;
            }
            n -= iov[0].iov_len;
            iovcnt --;
            if( iovcnt == 0 )
                break;

            int i;
            for( i = 0; i < iovcnt; ++i )
                iov[i] = iov[i+1];
        }
    }

  OUT:
    pthread_mutex_unlock(&c->lock);
    return ret;
}

yrmcds_error yrmcds_noop(yrmcds* c, uint32_t* serial) {
    return send_command(c, YRMCDS_CMD_NOOP, 0, serial,
                        0, NULL, 0, NULL, 0, NULL);
}
