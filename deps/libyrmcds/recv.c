// (C) 2013 Cybozu et al.

#include "yrmcds.h"
#include "portability.h"

#ifdef LIBYRMCDS_USE_LZ4
#  include "lz4/lib/lz4.h"
#endif

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static const size_t BINARY_HEADER_SIZE = 24;
static const size_t RECV_SIZE = 256 << 10;
static const size_t MAX_CAPACITY = 50 << 20; // 50 MiB

static inline yrmcds_error recv_data(yrmcds* c) {
    if( (c->capacity - c->used) < RECV_SIZE ) {
        size_t new_capacity = c->capacity * 2;
        char* new_buffer = (char*)realloc(c->recvbuf, new_capacity);
        if( new_buffer == NULL )
            return YRMCDS_OUT_OF_MEMORY;
        c->recvbuf = new_buffer;
        c->capacity = new_capacity;
    }

    ssize_t n;
  AGAIN:
    n = recv(c->sock, c->recvbuf + c->used, RECV_SIZE, 0);
    if( n == -1 ) {
        if( errno == EINTR ) goto AGAIN;
        return YRMCDS_SYSTEM_ERROR;
    }
    if( n == 0 )
        return YRMCDS_DISCONNECTED;
    c->used += (size_t)n;
    return YRMCDS_OK;
}

static inline uint64_t ntoh64(const char* p) {
    uint64_t n;
    memcpy(&n, p, sizeof(n));
    return be64toh(n);
}

static inline uint32_t ntoh32(const char* p) {
    uint32_t n;
    memcpy(&n, p, sizeof(n));
    return be32toh(n);
}

static inline uint16_t ntoh16(const char* p) {
    uint16_t n;
    memcpy(&n, p, sizeof(n));
    return be16toh(n);
}

yrmcds_error yrmcds_recv(yrmcds* c, yrmcds_response* r) {
    if( c == NULL || r == NULL )
        return YRMCDS_BAD_ARGUMENT;
    if( c->invalid )
        return YRMCDS_PROTOCOL_ERROR;

    if( c->last_size > 0 ) {
        size_t remain = c->used - c->last_size;
        if( remain > 0 )
            memmove(c->recvbuf, c->recvbuf + c->last_size, remain);
        c->used = remain;
        c->last_size = 0;
        free(c->decompressed);
        c->decompressed = NULL;
    }

    while( c->used < BINARY_HEADER_SIZE ) {
        yrmcds_error e = recv_data(c);
        if( e != 0 ) return e;
    }

    if( *c->recvbuf != '\x81' ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }
    uint32_t total_len = ntoh32(c->recvbuf + 8);
    if( total_len > MAX_CAPACITY ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }
    while( c->used < (BINARY_HEADER_SIZE + total_len) ) {
        yrmcds_error e = recv_data(c);
        if( e != 0 ) return e;
    }

    uint16_t key_len = ntoh16(c->recvbuf + 2);
    uint8_t extras_len = *(unsigned char*)(c->recvbuf + 4);
    if( total_len < (key_len + extras_len) ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }

    const char* pkey = c->recvbuf + (BINARY_HEADER_SIZE + extras_len);
    r->length = BINARY_HEADER_SIZE + total_len;
    r->command = *(unsigned char*)(c->recvbuf + 1);
    r->key = key_len ? pkey : NULL;
    r->key_len = key_len;
    r->status = ntoh16(c->recvbuf + 6);
    memcpy(&(r->serial), c->recvbuf + 12, 4);
    r->cas_unique = ntoh64(c->recvbuf + 16);
    r->flags = 0;
    if( extras_len > 0 ) {
        if( extras_len != 4 ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->flags = ntoh32(c->recvbuf + BINARY_HEADER_SIZE);
    }

    size_t data_len = total_len - key_len - extras_len;
    const char* pdata = pkey + key_len;

    if( (r->command == YRMCDS_CMD_INCREMENT ||
         r->command == YRMCDS_CMD_DECREMENT) &&
        (r->status == YRMCDS_STATUS_OK) ) {
        r->data = NULL;
        r->data_len = 0;
        if( data_len != 8 ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->value = ntoh64(pdata);
        c->last_size = r->length;
        return YRMCDS_OK;
    }
    r->value = 0;
    r->data = data_len ? pdata : NULL;
    r->data_len = data_len;

#ifdef LIBYRMCDS_USE_LZ4
    if( c->compress_size && (r->flags & YRMCDS_FLAG_COMPRESS) ) {
        if( data_len == 0 ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->flags &= ~(uint32_t)YRMCDS_FLAG_COMPRESS;
        uint32_t decompress_size = ntoh32(pdata);
        if( UINT32_MAX > INT_MAX ) {
            if( decompress_size > INT_MAX ) {
                c->invalid = 1;
                return YRMCDS_PROTOCOL_ERROR;
            }
        }
        c->decompressed = (char*)malloc(decompress_size);
        if( c->decompressed == NULL )
            return YRMCDS_OUT_OF_MEMORY;
        int d = LZ4_decompress_safe(pdata + sizeof(uint32_t),
                                    c->decompressed,
                                    (int)(data_len - sizeof(uint32_t)),
                                    (int)decompress_size);
        if( d != decompress_size ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->data = c->decompressed;
        r->data_len = decompress_size;
    }
#endif // LIBYRMCDS_USE_LZ4

    c->last_size = r->length;
    return YRMCDS_OK;
}
