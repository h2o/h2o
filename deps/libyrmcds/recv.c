// (C) 2013 Cybozu et al.

#include "yrmcds.h"
#include "yrmcds_portability.h"

#ifdef LIBYRMCDS_USE_LZ4
#  include "lz4/lib/lz4.h"
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
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

static yrmcds_error text_recv(yrmcds* c, yrmcds_response* r);

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

    if( c->text_mode ) {
        return text_recv(c, r);
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


// text protocol
#define PARSE_UINT(name)                        \
    uint64_t name = 0;                          \
    while( *p == ' ' ) p++;                     \
    while( '0' <= *p && *p <= '9' ) {           \
        name *= 10;                             \
        name += (uint64_t)(*p - '0');           \
        p++;                                    \
    }

static yrmcds_error text_recv(yrmcds* c, yrmcds_response* r) {
    char* pos;
    while( c->used == 0 ||
           (pos = (char*)memchr(c->recvbuf, '\n', c->used)) == NULL ) {
        yrmcds_error e = recv_data(c);
        if( e != 0 ) return e;
    }
    // make sure the buffer contains CRLF.
    if( (pos - c->recvbuf) < 2 || *(pos-1) != '\r' ) {
        c->invalid = 1;
        return YRMCDS_PROTOCOL_ERROR;
    }
    pos--;
    size_t resp_len = (size_t)(pos - c->recvbuf);

    memset(r, 0, sizeof(yrmcds_response));
    r->serial = ++c->rserial;
    r->length = resp_len + 2;
    r->status = YRMCDS_STATUS_OK;
    r->command = YRMCDS_CMD_BOTTOM;  // dummy for emulating binary protocol

    if( resp_len == 2 && memcmp(c->recvbuf, "OK", 2) == 0 ) {
        // successful response for flush_all
        goto FINISH;
    }
    if( resp_len == 3 && memcmp(c->recvbuf, "END", 3) == 0 ) {
        // get failed for non-existing object.
        r->status = YRMCDS_STATUS_NOTFOUND;
        goto FINISH;
    }
    if( resp_len == 5 && memcmp(c->recvbuf, "ERROR", 5) == 0 ) {
        r->status = YRMCDS_STATUS_UNKNOWNCOMMAND;
        goto FINISH;
    }
    if( resp_len == 6 ) {
        if( memcmp(c->recvbuf, "STORED", 6) == 0 ) {
            // successful response for storage commands.
            goto FINISH;
        }
        if( memcmp(c->recvbuf, "EXISTS", 6) == 0 ) {
            // failure response for cas.
            r->status = YRMCDS_STATUS_EXISTS;
            goto FINISH;
        }
    }
    if( resp_len == 7 ) {
        if( memcmp(c->recvbuf, "DELETED", 7) == 0 )
            // successful response for delete.
            goto FINISH;
        if( memcmp(c->recvbuf, "TOUCHED", 7) == 0 )
            // successful response for touch.
            goto FINISH;
    }
    if( resp_len == 9 && memcmp(c->recvbuf, "NOT_FOUND", 9) == 0 ) {
        // failure response for cas, delete, incr, decr, or touch.
        r->status = YRMCDS_STATUS_NOTFOUND;
        goto FINISH;
    }
    if( resp_len == 10 && memcmp(c->recvbuf, "NOT_STORED", 10) == 0 ) {
        // failure response for add, replace, append, or prepend.
        r->status = YRMCDS_STATUS_NOTSTORED;
        goto FINISH;
    }
    if( resp_len > 0 && '0' <= c->recvbuf[0] && c->recvbuf[0] <= '9' ) {
        // successful response for incr or decr.
        const char* p = c->recvbuf;
        PARSE_UINT(value);
        r->value = value;
        goto FINISH;
    }
    if( resp_len > 8 && memcmp(c->recvbuf, "VERSION ", 8) == 0 ) {
        // successful response for version.
        r->data_len = resp_len - 8;
        r->data = c->recvbuf + 8;
        goto FINISH;
    }
    if( resp_len > 6 && memcmp(c->recvbuf, "VALUE ", 6) == 0 ) {
        // successful response for gets.
        const char* p = c->recvbuf + 6;
        while( *p == ' ' ) p++;
        if( p == pos ) goto UNKNOWN;

        const char* key_end = memchr(p, ' ', (size_t)(pos - p));
        if( key_end == NULL ) goto UNKNOWN;
        r->key = p;
        r->key_len = (size_t)(key_end - p);

        p = key_end;
        PARSE_UINT(flags);
        if( *p != ' ' ) goto UNKNOWN;
        r->flags = (uint32_t)flags;

        PARSE_UINT(bytes);
        if( bytes > MAX_CAPACITY ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        size_t data_len = (size_t)bytes;

        while( *p == ' ' ) p++;
        if( *p < '0' || '9' < *p ) goto UNKNOWN;
        PARSE_UINT(cas);

        size_t required = resp_len + 2 + data_len + 7; // CRLF "END" CRLF
        while( c->used < required ) {
            yrmcds_error e = recv_data(c);
            if( e != 0 ) return e;
        }

        const char* data = c->recvbuf + (resp_len + 2);
        if( memcmp(data + data_len, "\r\nEND\r\n", 7) != 0 ) {
            c->invalid = 1;
            return YRMCDS_PROTOCOL_ERROR;
        }
        r->length = required;
        r->flags = (uint32_t)flags;

#ifdef LIBYRMCDS_USE_LZ4
        if( c->compress_size && (r->flags & YRMCDS_FLAG_COMPRESS) ) {
            if( data_len == 0 ) {
                c->invalid = 1;
                return YRMCDS_PROTOCOL_ERROR;
            }
            r->flags &= ~(uint32_t)YRMCDS_FLAG_COMPRESS;
            uint32_t decompress_size = ntoh32(data);
            if( UINT32_MAX > INT_MAX ) {
                if( decompress_size > INT_MAX ) {
                    c->invalid = 1;
                    return YRMCDS_PROTOCOL_ERROR;
                }
            }
            c->decompressed = (char*)malloc(decompress_size);
            if( c->decompressed == NULL )
                return YRMCDS_OUT_OF_MEMORY;
            int d = LZ4_decompress_safe(data + sizeof(uint32_t),
                                        c->decompressed,
                                        (int)(data_len - sizeof(uint32_t)),
                                        (int)decompress_size);
            if( d != decompress_size ) {
                c->invalid = 1;
                return YRMCDS_PROTOCOL_ERROR;
            }
            data = c->decompressed;
            data_len = (size_t)decompress_size;
        }
#endif // LIBYRMCDS_USE_LZ4
        r->data = data;
        r->data_len = data_len;
        r->cas_unique = cas;
        goto FINISH;
    }

  UNKNOWN:
    r->status = YRMCDS_STATUS_OTHER;
    fprintf(stderr, "[libyrmcds] unknown response: %.*s\n",
            (int)resp_len, c->recvbuf);

  FINISH:
    c->last_size = r->length;
    return YRMCDS_OK;
}

