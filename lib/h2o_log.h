#ifndef H2O_LOG_H
#define H2O_LOG_H

#include "h2o/memory.h"
#include "picotls.h"

extern int h2o_log_fd;

#define H2O_LOG(type, block)                                                                                                       \
    do {                                                                                                                           \
        if (h2o_log_fd == -1)                                                                                                      \
            break;                                                                                                                 \
        char smallbuf[128];                                                                                                        \
        ptls_buffer_t logbuf;                                                                                                      \
        ptls_buffer_init(&logbuf, smallbuf, sizeof(smallbuf));                                                                     \
        int h2o_log_skip = 0;                                                                                                      \
        H2O_LOG__DO_PUSH_SAFESTR("{\"type\":\"" H2O_TO_STR(type) "\"");                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        H2O_LOG__DO_PUSH_SAFESTR("}\n");                                                                                           \
        if (!h2o_log_skip)                                                                                                         \
            write(h2o_log_fd, logbuf.base, logbuf.off);                                                                            \
        ptls_buffer_dispose(&logbuf);                                                                                              \
    } while (0)

#define H2O_LOG_ELEMENT_PTR(name, value)                                                                                           \
    do {                                                                                                                           \
        H2O_LOG__DO_PUSH_SAFESTR(",\"" H2O_TO_STR(name) "\":");                                                                   \
        H2O_LOG__DO_PUSH_HEX((uint64_t)value);                                                                                     \
    } while (0)

#define H2O_LOG_ELEMENT_SAFESTR(name, value)                                                                                       \
    do {                                                                                                                           \
        H2O_LOG__DO_PUSH_SAFESTR(",\"" H2O_TO_STR(name) "\":\"");                                                                 \
        H2O_LOG__DO_PUSH_SAFESTR(value);                                                                                           \
        H2O_LOG__DO_PUSH_SAFESTR("\"");                                                                                            \
    } while (0)

#define H2O_LOG_CONN(type, conn, block)                                                                                           \
    H2O_LOG(type, {                                                                                                               \
        h2o_log_skip = (conn)->callbacks->skip_tracing(conn);                                                                      \
        H2O_LOG_ELEMENT_SIGNED(conn_id, (conn)->id);                                                                                 \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
    })

#define H2O_LOG_ELEMENT_SIGNED(name, value)                                                                                        \
    do {                                                                                                                           \
        H2O_LOG__DO_PUSH_SAFESTR(",\"" H2O_TO_STR(name) "\":");                                                                   \
        H2O_LOG__DO_PUSH_SIGNED(value);                                                                                            \
    } while (0)

#define H2O_LOG__DO_PUSH_SAFESTR(v)                                                                                                \
    do {                                                                                                                           \
        if (!h2o_log_skip && !h2o_log__do_push_safestr(h2o_log_skip ? NULL : &logbuf, (v)))                                        \
            h2o_log_skip = 1;                                                                                                      \
    } while (0)
#define H2O_LOG__DO_PUSH_HEX(v)                                                                                                    \
    do {                                                                                                                           \
        if (!h2o_log_skip && !h2o_log__do_push_hex(h2o_log_skip ? NULL : &logbuf, (v)))                                            \
            h2o_log_skip = 1;                                                                                                      \
    } while (0)
#define H2O_LOG__DO_PUSH_SIGNED(v)                                                                                                 \
    do {                                                                                                                           \
        if (!h2o_log_skip && !h2o_log__do_push_signed(h2o_log_skip ? NULL : &logbuf, (v)))                                         \
            h2o_log_skip = 1;                                                                                                      \
    } while (0)

static int h2o_log__do_push_safestr(ptls_buffer_t *buf, const char *s);
int h2o_log__do_pushv(ptls_buffer_t *buf, const void *p, size_t l);
int h2o_log__do_push_hex(ptls_buffer_t *buf, uint64_t v);
int h2o_log__do_push_signed(ptls_buffer_t *buf, int64_t v);

inline int h2o_log__do_push_safestr(ptls_buffer_t *buf, const char *s)
{
    return h2o_log__do_pushv(buf, s, strlen(s));
}

#endif
