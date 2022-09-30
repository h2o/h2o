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
#ifndef picotls_ptlslog_h
#define picotls_ptlslog_h

#if PICOTLS_USE_PTLSLOG

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <pthread.h>

#include "picotls.h"

typedef struct st_ptlslog_context_t {
    int *fds;
    size_t num_fds;

    size_t num_lost;
    pthread_mutex_t mutex;
} ptlslog_context_t;

extern ptlslog_context_t ptlslog;


#define PTLSLOG(module, type, block)                                                                                               \
    do {                                                                                                                           \
        if (!ptlslog_is_active())                                                                                                  \
            break;                                                                                                                 \
        int ptlslog_skip = 0;                                                                                                      \
        char smallbuf[128];                                                                                                        \
        ptls_buffer_t ptlslogbuf;                                                                                                  \
        ptls_buffer_init(&ptlslogbuf, smallbuf, sizeof(smallbuf));                                                                 \
        PTLSLOG__DO_PUSH_SAFESTR("{\"module\":\"" PTLS_TO_STR(module) "\",\"type\":\"" PTLS_TO_STR(type) "\"");                    \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        PTLSLOG__DO_PUSH_SAFESTR("}\n");                                                                                           \
        if (!ptlslog_skip)                                                                                                         \
            ptlslog__do_write(&ptlslogbuf);                                                                                        \
        ptls_buffer_dispose(&ptlslogbuf);                                                                                          \
    } while (0)

#define PTLSLOG_CONN(type, tls, block)                                                                                             \
    do {                                                                                                                           \
        ptls_t *_tls = (tls);                                                                                                      \
        if (ptls_skip_tracing(_tls))                                                                                               \
            break;                                                                                                                 \
        PTLSLOG(picotls, type, {                                                                                                   \
            PTLSLOG_ELEMENT_PTR(tls, _tls);                                                                                        \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
        });                                                                                                                        \
    } while (0)

#define PTLSLOG_ELEMENT_SAFESTR(name, value)                                                                                       \
    do {                                                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR(",\"" PTLS_TO_STR(name) "\":\"");                                                                 \
        PTLSLOG__DO_PUSH_SAFESTR(value);                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR("\"");                                                                                            \
    } while (0)

#define PTLSLOG_ELEMENT_UNSAFESTR(name, value, value_len)                                                                          \
    do {                                                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR(",\"" PTLS_TO_STR(name) "\":\"");                                                                 \
        PTLSLOG__DO_PUSH_UNSAFESTR(value, value_len);                                                                              \
        PTLSLOG__DO_PUSH_SAFESTR("\"");                                                                                            \
    } while (0)
#define PTLSLOG_ELEMENT_HEXDUMP(name, value, value_len)                                                                            \
    do {                                                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR(",\"" PTLS_TO_STR(name) "\":\"");                                                                 \
        PTLSLOG__DO_PUSH_HEXDUMP(value, value_len);                                                                                \
        PTLSLOG__DO_PUSH_SAFESTR("\"");                                                                                            \
    } while (0)

#define PTLSLOG_ELEMENT_PTR(name, value) PTLSLOG_ELEMENT_UNSIGNED(name, (uint64_t)(value))

#define PTLSLOG_ELEMENT_SIGNED(name, value)                                                                                        \
    do {                                                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR(",\"" PTLS_TO_STR(name) "\":");                                                                   \
        PTLSLOG__DO_PUSH_SIGNED(value);                                                                                            \
    } while (0)
#define PTLSLOG_ELEMENT_UNSIGNED(name, value)                                                                                      \
    do {                                                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR(",\"" PTLS_TO_STR(name) "\":");                                                                   \
        PTLSLOG__DO_PUSH_UNSIGNED(value);                                                                                          \
    } while (0)
#define PTLSLOG_ELEMENT_BOOL(name, value)                                                                                          \
    do {                                                                                                                           \
        PTLSLOG__DO_PUSH_SAFESTR(",\"" PTLS_TO_STR(name) "\":");                                                                   \
        PTLSLOG__DO_PUSH_SAFESTR(value ? "true" : "false");                                                                        \
    } while (0)

#define PTLSLOG__DO_PUSH_SAFESTR(v)                                                                                                \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(!ptlslog_skip && !ptlslog__do_push_safestr(&ptlslogbuf, (v))))                                           \
            ptlslog_skip = 1;                                                                                                      \
    } while (0)
#define PTLSLOG__DO_PUSH_UNSAFESTR(v, l)                                                                                           \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(!ptlslog_skip && !ptlslog__do_push_unsafestr(&ptlslogbuf, (v), (l))))                                    \
            ptlslog_skip = 1;                                                                                                      \
    } while (0)
#define PTLSLOG__DO_PUSH_HEXDUMP(v, l)                                                                                             \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(!ptlslog_skip && !ptlslog__do_push_hexdump(&ptlslogbuf, (v), (l))))                                      \
            ptlslog_skip = 1;                                                                                                      \
    } while (0)
#define PTLSLOG__DO_PUSH_SIGNED(v)                                                                                                 \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(!ptlslog_skip)) {                                                                                        \
            if (sizeof(v) <= sizeof(int32_t)) {                                                                                    \
                if (PTLS_UNLIKELY(!ptlslog__do_push_signed32(&ptlslogbuf, (v))))                                                   \
                    ptlslog_skip = 1;                                                                                              \
            } else {                                                                                                               \
                if (PTLS_UNLIKELY(!ptlslog__do_push_signed64(&ptlslogbuf, (v))))                                                   \
                    ptlslog_skip = 1;                                                                                              \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)
#define PTLSLOG__DO_PUSH_UNSIGNED(v)                                                                                               \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(!ptlslog_skip)) {                                                                                        \
            if (sizeof(v) <= sizeof(uint32_t)) {                                                                                   \
                if (PTLS_UNLIKELY(!ptlslog__do_push_unsigned32(&ptlslogbuf, (v))))                                                 \
                    ptlslog_skip = 1;                                                                                              \
            } else {                                                                                                               \
                if (PTLS_UNLIKELY(!ptlslog__do_push_unsigned64(&ptlslogbuf, (v))))                                                 \
                    ptlslog_skip = 1;                                                                                              \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

/**
 * Retrusn true if one has installed an fd to the ptlslog context with `ptlslog_add_fd()`.
 */
static int ptlslog_is_active(void);

/**
 * Returns the number of lost events.
 */
size_t ptlslog_num_lost(void);

/**
 * Registers an fd for ptslog. A registered fd is automatically closed and removed if it is invalidated.
 */
int ptlslog_add_fd(int fd);


static int ptlslog__do_push_safestr(ptls_buffer_t *buf, const char *s);
int ptlslog__do_push_unsafestr(ptls_buffer_t *buf, const char *s, size_t l);
int ptlslog__do_push_hexdump(ptls_buffer_t *buf, const void *s, size_t l);
int ptlslog__do_pushv(ptls_buffer_t *buf, const void *p, size_t l);
int ptlslog__do_push_signed32(ptls_buffer_t *buf, int32_t v);
int ptlslog__do_push_signed64(ptls_buffer_t *buf, int64_t v);
int ptlslog__do_push_unsigned32(ptls_buffer_t *buf, uint32_t v);
int ptlslog__do_push_unsigned64(ptls_buffer_t *buf, uint64_t v);
void ptlslog__do_write(const ptls_buffer_t *buf);

/* inline functions */

inline int ptlslog_is_active(void)
{
    return ptlslog.fds != NULL;
}

inline int ptlslog__do_push_safestr(ptls_buffer_t *buf, const char *s)
{
    return ptlslog__do_pushv(buf, s, strlen(s));
}

#ifdef __cplusplus
}
#endif

#else /* !PICOTLS_USE_PTLSLOG */

#define PTLSLOG(...) ((void)0)
#define PTLSLOG_CONN(...) ((void)0)


static inline int ptlslog_is_active(void)
{
    return 0;
}

static inline size_t ptlslog_num_lost(void)
{
    return 0;
}

static inline int ptlslog_add_fd(int fd)
{
    return 0;
}

#endif /* PICOTLS_USE_PTLSLOG */

#endif
