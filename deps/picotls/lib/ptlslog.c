/*
 * Copyright (c) 2022 Fastly, Inc., Goro Fuji, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "picotls.h"
#include "picotls/ptlslog.h"

ptlslog_context_t ptlslog = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

size_t ptlslog_num_lost(void)
{
    return ptlslog.num_lost;
}

int ptlslog_add_fd(int fd)
{
    pthread_mutex_lock(&ptlslog.mutex);

    ptlslog.fds = realloc(ptlslog.fds, sizeof(ptlslog.fds[0]) * (ptlslog.num_fds + 1));
    ptlslog.fds[ptlslog.num_fds] = fd;
    ptlslog.num_fds++;

    pthread_mutex_unlock(&ptlslog.mutex);
    return 1;
}

/**
 * Builds a JSON-safe string without double quotes. Supplied buffer MUST be 6x + 1 bytes larger than the input.
 */
static size_t escape_json_unsafe_string(char *buf, const void *unsafe_str, size_t len)
{
    char *dst = buf;
    const uint8_t *src = unsafe_str, *end = src + len;

    for (; src != end; ++src) {
        switch (*src) {
#define MAP(ch, escaped)                                                                                                           \
    case ch: {                                                                                                                     \
        memcpy(dst, (escaped), sizeof(escaped) - 1);                                                                               \
        dst += sizeof(escaped) - 1;                                                                                                \
    } break;

            MAP('"', "\\\"");
            MAP('\\', "\\\\");
            MAP('/', "\\/");
            MAP('\b', "\\b");
            MAP('\f', "\\f");
            MAP('\n', "\\n");
            MAP('\r', "\\r");
            MAP('\t', "\\t");

#undef MAP

        default:
            if (*src < 0x20 || *src == 0x7f) {
                *dst++ = '\\';
                *dst++ = 'u';
                *dst++ = '0';
                *dst++ = '0';
                ptls_byte_to_hex(dst, *src);
                dst += 2;
            } else {
                *dst++ = *src;
            }
            break;
        }
    }
    *dst = '\0';

    return (size_t)(dst - buf);
}

void ptlslog__do_write(const ptls_buffer_t *buf)
{
    pthread_mutex_lock(&ptlslog.mutex);
    for (size_t i = 0; i < ptlslog.num_fds; ++i) {
        ssize_t ret;
        while ((ret = write(ptlslog.fds[i], buf->base, buf->off)) == -1 && errno == EINTR)
            ;
        if (ret == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ptlslog.num_lost++;
            } else {
                // close fd and remove the entry of it from the array
                // ptlslog.fds is released by realloc(ptlslog.fds, 0) when ptlslog.num_fds is 1.
                close(ptlslog.fds[i]);
                memmove(ptlslog.fds + i, ptlslog.fds + i + 1, sizeof(ptlslog.fds[0]) * (ptlslog.num_fds - i - 1));
                ptlslog.fds = realloc(ptlslog.fds, sizeof(ptlslog.fds[0]) * (ptlslog.num_fds - 1));
                --ptlslog.num_fds;
            }
        }
    }
    pthread_mutex_unlock(&ptlslog.mutex);
}

int ptlslog__do_pushv(ptls_buffer_t *buf, const void *p, size_t l)
{
    if (ptls_buffer_reserve(buf, l) != 0)
        return 0;

    memcpy(buf->base + buf->off, p, l);
    buf->off += l;
    return 1;
}

int ptlslog__do_push_unsafestr(ptls_buffer_t *buf, const char *s, size_t l)
{
    if (ptls_buffer_reserve(buf, l * strlen("\\u0000") + 1) != 0)
        return 0;

    buf->off += escape_json_unsafe_string((char *)(buf->base + buf->off), s, l);
    return 1;
}

int ptlslog__do_push_hexdump(ptls_buffer_t *buf, const void *s, size_t l)
{
    if (ptls_buffer_reserve(buf, l * strlen("ff") + 1) != 0)
        return 0;

    ptls_hexdump((char *)(buf->base + buf->off), s, l);
    buf->off += l * strlen("ff");
    return 1;
}

int ptlslog__do_push_signed32(ptls_buffer_t *buf, int32_t v)
{
    /* TODO optimize */
    char s[sizeof("-2147483648")];
    int len = sprintf(s, "%" PRId32, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}

int ptlslog__do_push_signed64(ptls_buffer_t *buf, int64_t v)
{
    /* TODO optimize */
    char s[sizeof("-9223372036854775808")];
    int len = sprintf(s, "%" PRId64, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}

int ptlslog__do_push_unsigned32(ptls_buffer_t *buf, uint32_t v)
{
    /* TODO optimize */
    char s[sizeof("4294967295")];
    int len = sprintf(s, "%" PRIu32, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}

int ptlslog__do_push_unsigned64(ptls_buffer_t *buf, uint64_t v)
{
    /* TODO optimize */
    char s[sizeof("18446744073709551615")];
    int len = sprintf(s, "%" PRIu64, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}
