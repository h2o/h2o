// (C) 2016 Cybozu

#include "yrmcds_text.h"
#include "yrmcds_portability.h"

#ifdef LIBYRMCDS_USE_LZ4
#  include "lz4/lib/lz4.h"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAX_KEY_LENGTH 250  // from memcached spec.
#define TEXTBUF_SIZE  1000  // enough for any command & parameters.
#define EXPAND_STR(s) (s), (sizeof(s) - 1)
static const char CRLF[2] = {'\r', '\n'};

#ifdef LIBYRMCDS_USE_LZ4
static inline void
hton32(uint32_t i, char* p) {
    uint32_t n = htobe32(i);
    memcpy(p, &n, sizeof(n));
}
#endif

static inline yrmcds_error
check_key(const char* key, size_t key_len) {
    if( key_len > MAX_KEY_LENGTH )
        return YRMCDS_BAD_KEY;

    size_t i;
    for( i = 0; i < key_len; i++ ) {
        char c = key[i];
        if( c <= ' ' ) return YRMCDS_BAD_KEY;  // SPC and control chars
        if( c == 127 ) return YRMCDS_BAD_KEY;  // DEL
    }

    return YRMCDS_OK;
}

typedef struct {
    char* pos;
    char buffer[TEXTBUF_SIZE];
} textbuf_t;

static inline size_t
textbuf_length(const textbuf_t* buf) {
    return (size_t)(buf->pos - buf->buffer);
}

static inline void
textbuf_init(textbuf_t* buf) {
    buf->pos = buf->buffer;
}

static inline void
textbuf_append_char(textbuf_t* buf, char c) {
    *buf->pos = c;
    ++buf->pos;
}

static inline void
textbuf_append_string(textbuf_t* buf, const char* s, size_t len) {
    memcpy(buf->pos, s, len);
    buf->pos += len;
}

#define textbuf_append_const_string(b, s)       \
    textbuf_append_string(b, s, sizeof(s) - 1)

static void
textbuf_append_uint64(textbuf_t* buf, uint64_t n) {
    // UINT64_MAX = 18446744073709551615 -> char[20]
    char nbuf[20];
    char* pos = (nbuf) + 20;

    do {
        pos--;
        uint64_t m = n % 10;
        n /= 10;
        *pos = (char)('0' + m);
    } while( n != 0 );

    textbuf_append_string(buf, pos, (size_t)(nbuf - pos + 20));
}


static yrmcds_error
send_command(yrmcds* c, textbuf_t* buf, uint32_t* serial) {
    memcpy(buf->pos, CRLF, sizeof(CRLF));
    buf->pos += sizeof(CRLF);
    const char* p = buf->buffer;
    size_t len = textbuf_length(buf);

#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    int e = pthread_mutex_lock(&c->lock);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#endif // ! LIBYRMCDS_NO_INTERNAL_LOCK

    c->serial = c->serial + 1;
    if( serial != NULL )
        *serial = c->serial;

    yrmcds_error ret = YRMCDS_OK;
    while( len > 0 ) {
        ssize_t n = send(c->sock, p, len, 0);
        if( n == -1 ) {
            if( errno == EINTR ) continue;
            ret = YRMCDS_SYSTEM_ERROR;
            goto OUT;
        }
        size_t n2 = (size_t)n;
        p += n2;
        len -= n2;
    }

  OUT:
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    pthread_mutex_unlock(&c->lock);
#endif
    return ret;
}

static yrmcds_error
send_data(yrmcds* c, const char* cmd, size_t cmd_len,
          const char* key, size_t key_len,
          const char* data, size_t data_len,
          uint32_t flags, uint32_t expire, uint64_t cas,
          int quiet, uint32_t* serial) {
    if( key == NULL || key_len == 0 || data == NULL || data_len == 0 || quiet )
        return YRMCDS_BAD_ARGUMENT;

    yrmcds_error ret;
    ret = check_key(key, key_len);
    if( ret != YRMCDS_OK ) return ret;

    if( cas != 0 ) {
        cmd = "cas";
        cmd_len = 3;
    }

    int compressed = 0;
#ifdef LIBYRMCDS_USE_LZ4
    if( (c->compress_size > 0) && (data_len > c->compress_size) ) {
        if( flags & YRMCDS_FLAG_COMPRESS )
            return YRMCDS_BAD_ARGUMENT;

        size_t bound = (size_t)LZ4_compressBound((int)data_len);
        char* new_data = (char*)malloc(bound + sizeof(uint32_t));
        if( new_data == NULL )
            return YRMCDS_OUT_OF_MEMORY;
        uint32_t new_size =
            (uint32_t)LZ4_compress(data, new_data + sizeof(uint32_t),
                                   (int)data_len);
        if( new_size == 0 ) {
            free(new_data);
            return YRMCDS_COMPRESS_FAILED;
        }
        hton32((uint32_t)data_len, new_data);
        flags |= YRMCDS_FLAG_COMPRESS;
        data_len = sizeof(uint32_t) + new_size;
        data = new_data;
        compressed = 1;
    }
#endif // LIBYRMCDS_USE_LZ4

    textbuf_t buf[1];
    textbuf_init(buf);

    // "cmd key flags expire bytes (cas)"
    textbuf_append_string(buf, cmd, cmd_len);
    textbuf_append_char(buf, ' ');
    textbuf_append_string(buf, key, key_len);
    textbuf_append_char(buf, ' ');
    textbuf_append_uint64(buf, flags);
    textbuf_append_char(buf, ' ');
    textbuf_append_uint64(buf, expire);
    textbuf_append_char(buf, ' ');
    textbuf_append_uint64(buf, (uint64_t)data_len);
    if( cas != 0 ) {
        textbuf_append_char(buf, ' ');
        textbuf_append_uint64(buf, cas);
    }
    textbuf_append_string(buf, CRLF, sizeof(CRLF));

    struct iovec iov[3];
    int iovcnt = 3;
    iov[0].iov_base = buf[0].buffer;
    iov[0].iov_len = textbuf_length(buf);
    iov[1].iov_base = (void*)data;
    iov[1].iov_len = data_len;
    iov[2].iov_base = (void*)CRLF;
    iov[2].iov_len = sizeof(CRLF);

#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    int e = pthread_mutex_lock(&c->lock);
    if( e != 0 ) {
        errno = e;
        return YRMCDS_SYSTEM_ERROR;
    }
#endif // ! LIBYRMCDS_NO_INTERNAL_LOCK

    c->serial = c->serial + 1;
    if( serial != NULL )
        *serial = c->serial;

    while( iovcnt > 0 ) {
        ssize_t n = writev(c->sock, iov, iovcnt);
        if( n == -1 ) {
            if( errno == EINTR ) continue;
            ret = YRMCDS_SYSTEM_ERROR;
            goto OUT;
        }
        size_t n2 = (size_t)n;
        while( n2 > 0 ) {
            if( n2 < iov[0].iov_len ) {
                iov[0].iov_base = (char*)iov[0].iov_base + n2;
                iov[0].iov_len -= n2;
                break;
            }
            n2 -= iov[0].iov_len;
            iovcnt --;
            if( iovcnt == 0 )
                break;

            int i;
            for( i = 0; i < iovcnt; ++i )
                iov[i] = iov[i+1];
        }
    }

  OUT:
#ifndef LIBYRMCDS_NO_INTERNAL_LOCK
    pthread_mutex_unlock(&c->lock);
#endif
    if( compressed )
        free((void*)data);
    return ret;
}


// public functions.
yrmcds_error yrmcds_text_get(yrmcds* c, const char* key, size_t key_len,
                             int quiet, uint32_t* serial) {
    if( key == NULL || key_len == 0 || quiet )
        return YRMCDS_BAD_ARGUMENT;

    yrmcds_error ret;
    ret = check_key(key, key_len);
    if( ret != YRMCDS_OK ) return ret;

    textbuf_t buf[1];
    textbuf_init(buf);

    textbuf_append_const_string(buf, "gets ");
    textbuf_append_string(buf, key, key_len);

    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_touch(yrmcds* c, const char* key, size_t key_len,
                               uint32_t expire, int quiet, uint32_t* serial) {
    if( key == NULL || key_len == 0 || quiet )
        return YRMCDS_BAD_ARGUMENT;

    yrmcds_error ret;
    ret = check_key(key, key_len);
    if( ret != YRMCDS_OK ) return ret;

    textbuf_t buf[1];
    textbuf_init(buf);

    textbuf_append_const_string(buf, "touch ");
    textbuf_append_string(buf, key, key_len);
    textbuf_append_char(buf, ' ');
    textbuf_append_uint64(buf, expire);

    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_set(yrmcds* c, const char* key, size_t key_len,
                             const char* data, size_t data_len,
                             uint32_t flags, uint32_t expire, uint64_t cas,
                             int quiet, uint32_t* serial) {
    return send_data(c, EXPAND_STR("set"), key, key_len, data, data_len,
                     flags, expire, cas, quiet, serial);
}

yrmcds_error yrmcds_text_replace(yrmcds* c, const char* key, size_t key_len,
                                 const char* data, size_t data_len,
                                 uint32_t flags, uint32_t expire, uint64_t cas,
                                 int quiet, uint32_t* serial) {
    return send_data(c, EXPAND_STR("replace"), key, key_len, data, data_len,
                     flags, expire, cas, quiet, serial);
}

yrmcds_error yrmcds_text_add(yrmcds* c, const char* key, size_t key_len,
                             const char* data, size_t data_len,
                             uint32_t flags, uint32_t expire, uint64_t cas,
                             int quiet, uint32_t* serial) {
    return send_data(c, EXPAND_STR("add"), key, key_len, data, data_len,
                     flags, expire, cas, quiet, serial);
}

yrmcds_error yrmcds_text_append(yrmcds* c, const char* key, size_t key_len,
                                const char* data, size_t data_len,
                                int quiet, uint32_t* serial) {
    return send_data(c, EXPAND_STR("append"), key, key_len, data, data_len,
                     0, 0, 0, quiet, serial);
}

yrmcds_error yrmcds_text_prepend(yrmcds* c, const char* key, size_t key_len,
                                 const char* data, size_t data_len,
                                 int quiet, uint32_t* serial) {
    return send_data(c, EXPAND_STR("prepend"), key, key_len, data, data_len,
                     0, 0, 0, quiet, serial);
}

yrmcds_error yrmcds_text_incr(yrmcds* c, const char* key, size_t key_len,
                              uint64_t value, int quiet, uint32_t* serial) {
    if( key == NULL || key_len == 0 || quiet )
        return YRMCDS_BAD_ARGUMENT;

    yrmcds_error ret;
    ret = check_key(key, key_len);
    if( ret != YRMCDS_OK ) return ret;

    textbuf_t buf[1];
    textbuf_init(buf);

    textbuf_append_const_string(buf, "incr ");
    textbuf_append_string(buf, key, key_len);
    textbuf_append_char(buf, ' ');
    textbuf_append_uint64(buf, value);

    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_decr(yrmcds* c, const char* key, size_t key_len,
                              uint64_t value, int quiet, uint32_t* serial) {
    if( key == NULL || key_len == 0 || quiet )
        return YRMCDS_BAD_ARGUMENT;

    yrmcds_error ret;
    ret = check_key(key, key_len);
    if( ret != YRMCDS_OK ) return ret;

    textbuf_t buf[1];
    textbuf_init(buf);

    textbuf_append_const_string(buf, "decr ");
    textbuf_append_string(buf, key, key_len);
    textbuf_append_char(buf, ' ');
    textbuf_append_uint64(buf, value);

    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_remove(yrmcds* c, const char* key, size_t key_len,
                                int quiet, uint32_t* serial) {
    if( key == NULL || key_len == 0 || quiet )
        return YRMCDS_BAD_ARGUMENT;

    yrmcds_error ret;
    ret = check_key(key, key_len);
    if( ret != YRMCDS_OK ) return ret;

    textbuf_t buf[1];
    textbuf_init(buf);

    textbuf_append_const_string(buf, "delete ");
    textbuf_append_string(buf, key, key_len);

    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_flush(yrmcds* c, uint32_t delay,
                               int quiet, uint32_t* serial) {
    if( quiet )
        return YRMCDS_BAD_ARGUMENT;

    textbuf_t buf[1];
    textbuf_init(buf);

    textbuf_append_const_string(buf, "flush_all");
    if( delay != 0 ) {
        textbuf_append_char(buf, ' ');
        textbuf_append_uint64(buf, delay);
    }

    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_version(yrmcds* c, uint32_t* serial) {
    textbuf_t buf[1];
    textbuf_init(buf);
    textbuf_append_const_string(buf, "version");
    return send_command(c, buf, serial);
}

yrmcds_error yrmcds_text_quit(yrmcds* c, uint32_t* serial) {
    textbuf_t buf[1];
    textbuf_init(buf);
    textbuf_append_const_string(buf, "quit");
    return send_command(c, buf, serial);
}
