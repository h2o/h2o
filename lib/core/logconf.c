/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

enum {
    ELEMENT_TYPE_EMPTY,                         /* empty element (with suffix only) */
    ELEMENT_TYPE_LOCAL_ADDR,                    /* %A */
    ELEMENT_TYPE_BYTES_SENT,                    /* %b */
    ELEMENT_TYPE_PROTOCOL,                      /* %H */
    ELEMENT_TYPE_REMOTE_ADDR,                   /* %h */
    ELEMENT_TYPE_LOGNAME,                       /* %l */
    ELEMENT_TYPE_METHOD,                        /* %m */
    ELEMENT_TYPE_LOCAL_PORT,                    /* %p, %{local}p */
    ELEMENT_TYPE_REMOTE_PORT,                   /* %{remote}p */
    ELEMENT_TYPE_ENV_VAR,                       /* %{..}e */
    ELEMENT_TYPE_QUERY,                         /* %q */
    ELEMENT_TYPE_REQUEST_LINE,                  /* %r */
    ELEMENT_TYPE_STATUS,                        /* %s */
    ELEMENT_TYPE_TIMESTAMP,                     /* %t */
    ELEMENT_TYPE_TIMESTAMP_STRFTIME,            /* %{...}t */
    ELEMENT_TYPE_TIMESTAMP_SEC_SINCE_EPOCH,     /* %{sec}t */
    ELEMENT_TYPE_TIMESTAMP_MSEC_SINCE_EPOCH,    /* %{msec}t */
    ELEMENT_TYPE_TIMESTAMP_USEC_SINCE_EPOCH,    /* %{usec}t */
    ELEMENT_TYPE_TIMESTAMP_MSEC_FRAC,           /* %{msec_frac}t */
    ELEMENT_TYPE_TIMESTAMP_USEC_FRAC,           /* %{usec_frac}t */
    ELEMENT_TYPE_URL_PATH,                      /* %U */
    ELEMENT_TYPE_REMOTE_USER,                   /* %u */
    ELEMENT_TYPE_AUTHORITY,                     /* %V */
    ELEMENT_TYPE_HOSTCONF,                      /* %v */
    ELEMENT_TYPE_IN_HEADER_TOKEN,               /* %{data.header_token}i */
    ELEMENT_TYPE_IN_HEADER_STRING,              /* %{data.name}i */
    ELEMENT_TYPE_OUT_HEADER_TOKEN,              /* %{data.header_token}o */
    ELEMENT_TYPE_OUT_HEADER_STRING,             /* %{data.name}o */
    ELEMENT_TYPE_OUT_HEADER_TOKEN_CONCATENATED, /* %{data.header_token}o */
    ELEMENT_TYPE_EXTENDED_VAR,                  /* %{data.name}x */
    ELEMENT_TYPE_CONNECTION_ID,                 /* %{connection-id}x */
    ELEMENT_TYPE_CONNECT_TIME,                  /* %{connect-time}x */
    ELEMENT_TYPE_REQUEST_HEADER_TIME,           /* %{request-header-time}x */
    ELEMENT_TYPE_REQUEST_BODY_TIME,             /* %{request-body-time}x */
    ELEMENT_TYPE_REQUEST_TOTAL_TIME,            /* %{request-total-time}x */
    ELEMENT_TYPE_PROCESS_TIME,                  /* %{process-time}x */
    ELEMENT_TYPE_RESPONSE_TIME,                 /* %{response-total-time}x */
    ELEMENT_TYPE_DURATION,                      /* %{duration}x */
    ELEMENT_TYPE_ERROR,                         /* %{error}x */
    ELEMENT_TYPE_PROTOCOL_SPECIFIC,             /* %{protocol-specific...}x */
    NUM_ELEMENT_TYPES
};

struct log_element_t {
    unsigned type;
    h2o_iovec_t suffix;
    union {
        const h2o_token_t *header_token;
        h2o_iovec_t name;
        size_t protocol_specific_callback_index;
    } data;
    unsigned magically_quoted_json : 1; /* whether to omit surrounding doublequotes when the output is null */
    unsigned original_response : 1;
};

struct st_h2o_logconf_t {
    H2O_VECTOR(struct log_element_t) elements;
    int escape;
};

static h2o_iovec_t strdup_lowercased(const char *s, size_t len)
{
    h2o_iovec_t v = h2o_strdup(NULL, s, len);
    h2o_strtolower(v.base, v.len);
    return v;
}

static int determine_magicquote_nodes(h2o_logconf_t *logconf, char *errbuf)
{
    size_t element_index;
    int quote_char = '\0'; /* the quote char being used if the state machine is within a string literal */
    int just_in = 0;       /* if we just went into the string literal */

    for (element_index = 0; element_index < logconf->elements.size; ++element_index) {
        h2o_iovec_t suffix = logconf->elements.entries[element_index].suffix;
        logconf->elements.entries[element_index].magically_quoted_json = just_in && suffix.len != 0 && suffix.base[0] == quote_char;

        just_in = 0;

        size_t i;
        for (i = 0; i < suffix.len; ++i) {
            just_in = 0;
            if (quote_char != '\0') {
                if (quote_char == suffix.base[i]) {
                    /* out of quote? */
                    size_t j, num_bs = 0;
                    for (j = i; j != 0; ++num_bs)
                        if (suffix.base[--j] != '\\')
                            break;
                    if (num_bs % 2 == 0)
                        quote_char = '\0';
                }
            } else {
                if (suffix.base[i] == '"' || suffix.base[i] == '\'') {
                    quote_char = suffix.base[i];
                    just_in = 1;
                }
            }
        }
    }

    return 1;
}

h2o_logconf_t *h2o_logconf_compile(const char *fmt, int escape, char *errbuf)
{
    h2o_logconf_t *logconf = h2o_mem_alloc(sizeof(*logconf));
    const char *pt = fmt;
    size_t fmt_len = strlen(fmt);

    *logconf = (h2o_logconf_t){{NULL}, escape};

#define LAST_ELEMENT() (logconf->elements.entries + logconf->elements.size - 1)
/* suffix buffer is always guaranteed to be larger than the fmt + (sizeof('\n') - 1) (so that they would be no buffer overruns) */
#define NEW_ELEMENT(ty)                                                                                                            \
    do {                                                                                                                           \
        h2o_vector_reserve(NULL, &logconf->elements, logconf->elements.size + 1);                                                  \
        logconf->elements.size++;                                                                                                  \
        *LAST_ELEMENT() = (struct log_element_t){0};                                                                               \
        LAST_ELEMENT()->type = ty;                                                                                                 \
        LAST_ELEMENT()->suffix.base = h2o_mem_alloc(fmt_len + 1);                                                                  \
    } while (0)

    while (*pt != '\0') {
        if (memcmp(pt, "%%", 2) == 0) {
            ++pt; /* emit % */
        } else if (*pt == '%') {
            ++pt;
            /* handle < and > */
            int log_original = 0;
            for (;; ++pt) {
                if (*pt == '<') {
                    log_original = 1;
                } else if (*pt == '>') {
                    log_original = 0;
                } else {
                    break;
                }
            }
            /* handle {...}n */
            if (*pt == '{') {
                const h2o_token_t *token;
                const char *quote_end = strchr(++pt, '}');
                if (quote_end == NULL) {
                    sprintf(errbuf, "failed to compile log format: unterminated header name starting at: \"%16s\"", pt);
                    goto Error;
                }
                const char modifier = quote_end[1];
                switch (modifier) {
                case 'i':
                case 'o': {
                    h2o_iovec_t name = strdup_lowercased(pt, quote_end - pt);
                    token = h2o_lookup_token(name.base, name.len);
                    if (token != NULL) {
                        free(name.base);
                        if (modifier == 'o' && token == H2O_TOKEN_SET_COOKIE) {
                            NEW_ELEMENT(ELEMENT_TYPE_OUT_HEADER_TOKEN_CONCATENATED);
                            LAST_ELEMENT()->data.header_token = token;
                        } else {
                            NEW_ELEMENT(modifier == 'i' ? ELEMENT_TYPE_IN_HEADER_TOKEN : ELEMENT_TYPE_OUT_HEADER_TOKEN);
                            LAST_ELEMENT()->data.header_token = token;
                        }
                    } else {
                        NEW_ELEMENT(modifier == 'i' ? ELEMENT_TYPE_IN_HEADER_STRING : ELEMENT_TYPE_OUT_HEADER_STRING);
                        LAST_ELEMENT()->data.name = name;
                    }
                    LAST_ELEMENT()->original_response = log_original;
                } break;
                case 'p':
                    if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("local"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_LOCAL_PORT);
                    } else if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("remote"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_REMOTE_PORT);
                    } else {
                        sprintf(errbuf, "failed to compile log format: unknown specifier for %%{...}p");
                        goto Error;
                    }
                    break;
                case 'e':
                    {
                        h2o_iovec_t name = h2o_strdup(NULL, pt, quote_end - pt);
                        NEW_ELEMENT(ELEMENT_TYPE_ENV_VAR);
                        LAST_ELEMENT()->data.name = name;
                    }
                    break;
                case 't':
                    if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("sec"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_TIMESTAMP_SEC_SINCE_EPOCH);
                    } else if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("msec"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_TIMESTAMP_MSEC_SINCE_EPOCH);
                    } else if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("usec"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_TIMESTAMP_USEC_SINCE_EPOCH);
                    } else if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("msec_frac"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_TIMESTAMP_MSEC_FRAC);
                    } else if (h2o_memis(pt, quote_end - pt, H2O_STRLIT("usec_frac"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_TIMESTAMP_USEC_FRAC);
                    } else {
                        h2o_iovec_t name = h2o_strdup(NULL, pt, quote_end - pt);
                        NEW_ELEMENT(ELEMENT_TYPE_TIMESTAMP_STRFTIME);
                        LAST_ELEMENT()->data.name = name;
                    }
                    break;
                case 'x':
#define MAP_EXT_TO_TYPE(name, id)                                                                                                  \
    if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT(name))) {                                                                       \
        NEW_ELEMENT(id);                                                                                                           \
        goto MAP_EXT_Found;                                                                                                        \
    }
#define MAP_EXT_TO_PROTO(name, cb)                                                                                                 \
    if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT(name))) {                                                                       \
        h2o_conn_callbacks_t dummy_;                                                                                               \
        NEW_ELEMENT(ELEMENT_TYPE_PROTOCOL_SPECIFIC);                                                                               \
        LAST_ELEMENT()->data.protocol_specific_callback_index =                                                                    \
            &dummy_.log_.cb - dummy_.log_.callbacks;                                                                               \
        goto MAP_EXT_Found;                                                                                                        \
    }
                    MAP_EXT_TO_TYPE("connection-id", ELEMENT_TYPE_CONNECTION_ID);
                    MAP_EXT_TO_TYPE("connect-time", ELEMENT_TYPE_CONNECT_TIME);
                    MAP_EXT_TO_TYPE("request-total-time", ELEMENT_TYPE_REQUEST_TOTAL_TIME);
                    MAP_EXT_TO_TYPE("request-header-time", ELEMENT_TYPE_REQUEST_HEADER_TIME);
                    MAP_EXT_TO_TYPE("request-body-time", ELEMENT_TYPE_REQUEST_BODY_TIME);
                    MAP_EXT_TO_TYPE("process-time", ELEMENT_TYPE_PROCESS_TIME);
                    MAP_EXT_TO_TYPE("response-time", ELEMENT_TYPE_RESPONSE_TIME);
                    MAP_EXT_TO_TYPE("duration", ELEMENT_TYPE_DURATION);
                    MAP_EXT_TO_TYPE("error", ELEMENT_TYPE_ERROR);
                    MAP_EXT_TO_PROTO("http1.request-index", http1.request_index);
                    MAP_EXT_TO_PROTO("http2.stream-id", http2.stream_id);
                    MAP_EXT_TO_PROTO("http2.priority.received", http2.priority_received);
                    MAP_EXT_TO_PROTO("http2.priority.received.exclusive", http2.priority_received_exclusive);
                    MAP_EXT_TO_PROTO("http2.priority.received.parent", http2.priority_received_parent);
                    MAP_EXT_TO_PROTO("http2.priority.received.weight", http2.priority_received_weight);
                    MAP_EXT_TO_PROTO("http2.priority.actual", http2.priority_actual);
                    MAP_EXT_TO_PROTO("http2.priority.actual.parent", http2.priority_actual_parent);
                    MAP_EXT_TO_PROTO("http2.priority.actual.weight", http2.priority_actual_weight);
                    MAP_EXT_TO_PROTO("ssl.protocol-version", ssl.protocol_version);
                    MAP_EXT_TO_PROTO("ssl.session-reused", ssl.session_reused);
                    MAP_EXT_TO_PROTO("ssl.cipher", ssl.cipher);
                    MAP_EXT_TO_PROTO("ssl.cipher-bits", ssl.cipher_bits);
                    MAP_EXT_TO_PROTO("ssl.session-id", ssl.session_id);
                    { /* not found */
                        h2o_iovec_t name = strdup_lowercased(pt, quote_end - pt);
                        NEW_ELEMENT(ELEMENT_TYPE_EXTENDED_VAR);
                        LAST_ELEMENT()->data.name = name;
                    }
                MAP_EXT_Found:
#undef MAP_EXT_TO_TYPE
#undef MAP_EXT_TO_PROTO
                    break;
                default:
                    sprintf(errbuf, "failed to compile log format: header name is not followed by either `i`, `o`, `x`, `e`");
                    goto Error;
                }
                pt = quote_end + 2;
                continue;
            } else {
                unsigned type = NUM_ELEMENT_TYPES;
                switch (*pt++) {
#define TYPE_MAP(ch, ty)                                                                                                           \
    case ch:                                                                                                                       \
        type = ty;                                                                                                                 \
        break
                    TYPE_MAP('A', ELEMENT_TYPE_LOCAL_ADDR);
                    TYPE_MAP('b', ELEMENT_TYPE_BYTES_SENT);
                    TYPE_MAP('H', ELEMENT_TYPE_PROTOCOL);
                    TYPE_MAP('h', ELEMENT_TYPE_REMOTE_ADDR);
                    TYPE_MAP('l', ELEMENT_TYPE_LOGNAME);
                    TYPE_MAP('m', ELEMENT_TYPE_METHOD);
                    TYPE_MAP('p', ELEMENT_TYPE_LOCAL_PORT);
                    TYPE_MAP('e', ELEMENT_TYPE_ENV_VAR);
                    TYPE_MAP('q', ELEMENT_TYPE_QUERY);
                    TYPE_MAP('r', ELEMENT_TYPE_REQUEST_LINE);
                    TYPE_MAP('s', ELEMENT_TYPE_STATUS);
                    TYPE_MAP('t', ELEMENT_TYPE_TIMESTAMP);
                    TYPE_MAP('U', ELEMENT_TYPE_URL_PATH);
                    TYPE_MAP('u', ELEMENT_TYPE_REMOTE_USER);
                    TYPE_MAP('V', ELEMENT_TYPE_AUTHORITY);
                    TYPE_MAP('v', ELEMENT_TYPE_HOSTCONF);
#undef TYPE_MAP
                default:
                    sprintf(errbuf, "failed to compile log format: unknown escape sequence: %%%c", pt[-1]);
                    goto Error;
                }
                NEW_ELEMENT(type);
                LAST_ELEMENT()->original_response = log_original;
                continue;
            }
        }
        /* emit current char */
        if (logconf->elements.size == 0)
            NEW_ELEMENT(ELEMENT_TYPE_EMPTY);
        LAST_ELEMENT()->suffix.base[LAST_ELEMENT()->suffix.len++] = *pt++;
    }

    /* emit end-of-line */
    if (logconf->elements.size == 0)
        NEW_ELEMENT(ELEMENT_TYPE_EMPTY);
    LAST_ELEMENT()->suffix.base[LAST_ELEMENT()->suffix.len++] = '\n';

#undef NEW_ELEMENT
#undef LAST_ELEMENT

    if (escape == H2O_LOGCONF_ESCAPE_JSON) {
        if (!determine_magicquote_nodes(logconf, errbuf))
            goto Error;
    }

    return logconf;

Error:
    h2o_logconf_dispose(logconf);
    return NULL;
}

void h2o_logconf_dispose(h2o_logconf_t *logconf)
{
    size_t i;

    for (i = 0; i != logconf->elements.size; ++i) {
        free(logconf->elements.entries[i].suffix.base);
        switch (logconf->elements.entries[i].type) {
        case ELEMENT_TYPE_EXTENDED_VAR:
        case ELEMENT_TYPE_IN_HEADER_STRING:
        case ELEMENT_TYPE_OUT_HEADER_STRING:
        case ELEMENT_TYPE_TIMESTAMP_STRFTIME:
            free(logconf->elements.entries[i].data.name.base);
            break;
        default:
            break;
        }
    }
    free(logconf->elements.entries);
    free(logconf);
}

static inline char *append_safe_string(char *pos, const char *src, size_t len)
{
    memcpy(pos, src, len);
    return pos + len;
}

static char *append_unsafe_string_apache(char *pos, const char *src, size_t len)
{
    const char *src_end = src + len;

    for (; src != src_end; ++src) {
        if (' ' <= *src && *src < 0x7d && *src != '"') {
            *pos++ = *src;
        } else {
            *pos++ = '\\';
            *pos++ = 'x';
            *pos++ = ("0123456789abcdef")[(*src >> 4) & 0xf];
            *pos++ = ("0123456789abcdef")[*src & 0xf];
        }
    }

    return pos;
}

static char *append_unsafe_string_json(char *pos, const char *src, size_t len)
{
    const char *src_end = src + len;

    for (; src != src_end; ++src) {
        if (' ' <= *src && *src < 0x7e) {
            if (*src == '"' || *src == '\\')
                *pos++ = '\\';
            *pos++ = *src;
        } else {
            *pos++ = '\\';
            *pos++ = 'u';
            *pos++ = '0';
            *pos++ = '0';
            *pos++ = ("0123456789abcdef")[(*src >> 4) & 0xf];
            *pos++ = ("0123456789abcdef")[*src & 0xf];
        }
    }

    return pos;
}

static char *append_addr(char *pos, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *sa), h2o_conn_t *conn, h2o_iovec_t nullexpr)
{
    struct sockaddr_storage ss;
    socklen_t sslen;

    if ((sslen = cb(conn, (void *)&ss)) == 0)
        goto Fail;
    size_t l = h2o_socket_getnumerichost((void *)&ss, sslen, pos);
    if (l == SIZE_MAX)
        goto Fail;
    pos += l;
    return pos;

Fail:
    memcpy(pos, nullexpr.base, nullexpr.len);
    pos += nullexpr.len;
    return pos;
}

static char *append_port(char *pos, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *sa), h2o_conn_t *conn, h2o_iovec_t nullexpr)
{
    struct sockaddr_storage ss;
    socklen_t sslen;

    if ((sslen = cb(conn, (void *)&ss)) == 0)
        goto Fail;
    int32_t port = h2o_socket_getport((void *)&ss);
    if (port == -1)
        goto Fail;
    pos += sprintf(pos, "%" PRIu16, (uint16_t)port);
    return pos;

Fail:
    memcpy(pos, nullexpr.base, nullexpr.len);
    pos += nullexpr.len;
    return pos;
}

#define APPEND_DURATION(pos, name)                                                                                                 \
    do {                                                                                                                           \
        int64_t delta_usec;                                                                                                        \
        if (!h2o_time_compute_##name(req, &delta_usec))                                                                            \
            goto EmitNull;                                                                                                         \
        int32_t delta_sec = (int32_t)(delta_usec / (1000 * 1000));                                                                 \
        delta_usec -= ((int64_t)delta_sec * (1000 * 1000));                                                                        \
        RESERVE(sizeof(H2O_INT32_LONGEST_STR ".999999") - 1);                                                                      \
        pos += sprintf(pos, "%" PRId32, delta_sec);                                                                                \
        if (delta_usec != 0) {                                                                                                     \
            int i;                                                                                                                 \
            *pos++ = '.';                                                                                                          \
            for (i = 5; i >= 0; --i) {                                                                                             \
                pos[i] = '0' + delta_usec % 10;                                                                                    \
                delta_usec /= 10;                                                                                                  \
            }                                                                                                                      \
            pos += 6;                                                                                                              \
        }                                                                                                                          \
    } while (0);

static char *expand_line_buf(char *line, size_t *cur_size, size_t required, int should_realloc)
{
    size_t new_size = *cur_size;

    /* determine the new size */
    do {
        new_size *= 2;
    } while (new_size < required);

    /* reallocate */
    if (!should_realloc) {
        char *newpt = h2o_mem_alloc(new_size);
        memcpy(newpt, line, *cur_size);
        line = newpt;
    } else {
        line = h2o_mem_realloc(line, new_size);
    }
    *cur_size = new_size;

    return line;
}

char *h2o_log_request(h2o_logconf_t *logconf, h2o_req_t *req, size_t *len, char *buf)
{
    char *line = buf, *pos = line, *line_end = line + *len;
    h2o_iovec_t nullexpr;
    char *(*append_unsafe_string)(char *pos, const char *src, size_t len);
    size_t element_index, unsafe_factor;
    struct tm localt = {0};
    int should_realloc_on_expand = 0;

    switch (logconf->escape) {
    case H2O_LOGCONF_ESCAPE_APACHE:
        nullexpr = h2o_iovec_init(H2O_STRLIT("-"));
        append_unsafe_string = append_unsafe_string_apache;
        unsafe_factor = 4;
        break;
    case H2O_LOGCONF_ESCAPE_JSON:
        nullexpr = h2o_iovec_init(H2O_STRLIT("null"));
        append_unsafe_string = append_unsafe_string_json;
        unsafe_factor = 6;
        break;
    default:
        h2o_fatal("unexpected escape mode");
        break;
    }

    for (element_index = 0; element_index != logconf->elements.size; ++element_index) {
        struct log_element_t *element = logconf->elements.entries + element_index;

/* reserve capacity + suffix.len */
#define RESERVE(capacity)                                                                                                          \
    do {                                                                                                                           \
        if ((capacity) + element->suffix.len > line_end - pos) {                                                                   \
            size_t off = pos - line;                                                                                               \
            size_t size = line_end - line;                                                                                         \
            line = expand_line_buf(line, &size, off + (capacity) + element->suffix.len, should_realloc_on_expand);                 \
            pos = line + off;                                                                                                      \
            line_end = line + size;                                                                                                \
            should_realloc_on_expand = 1;                                                                                          \
        }                                                                                                                          \
    } while (0)

        switch (element->type) {
        case ELEMENT_TYPE_EMPTY:
            RESERVE(0);
            break;
        case ELEMENT_TYPE_LOCAL_ADDR: /* %A */
            RESERVE(NI_MAXHOST);
            pos = append_addr(pos, req->conn->callbacks->get_sockname, req->conn, nullexpr);
            break;
        case ELEMENT_TYPE_BYTES_SENT: /* %b */
            RESERVE(sizeof(H2O_UINT64_LONGEST_STR) - 1);
            pos += sprintf(pos, "%" PRIu64, (uint64_t)req->bytes_sent);
            break;
        case ELEMENT_TYPE_PROTOCOL: /* %H */
            RESERVE(sizeof("HTTP/1.1"));
            pos += h2o_stringify_protocol_version(pos, req->version);
            break;
        case ELEMENT_TYPE_REMOTE_ADDR: /* %h */
            RESERVE(NI_MAXHOST);
            pos = append_addr(pos, req->conn->callbacks->get_peername, req->conn, nullexpr);
            break;
        case ELEMENT_TYPE_METHOD: /* %m */
            RESERVE(req->input.method.len * unsafe_factor);
            pos = append_unsafe_string(pos, req->input.method.base, req->input.method.len);
            break;
        case ELEMENT_TYPE_LOCAL_PORT: /* %p */
            RESERVE(sizeof(H2O_UINT16_LONGEST_STR) - 1);
            pos = append_port(pos, req->conn->callbacks->get_sockname, req->conn, nullexpr);
            break;
        case ELEMENT_TYPE_REMOTE_PORT: /* %{remote}p */
            RESERVE(sizeof(H2O_UINT16_LONGEST_STR) - 1);
            pos = append_port(pos, req->conn->callbacks->get_peername, req->conn, nullexpr);
            break;
        case ELEMENT_TYPE_ENV_VAR:  /* %{..}e */  {
            h2o_iovec_t *env_var = h2o_req_getenv(req, element->data.name.base, element->data.name.len, 0);
            if (env_var == NULL)
                goto EmitNull;
            RESERVE(env_var->len * unsafe_factor);
            pos = append_safe_string(pos, env_var->base, env_var->len);
            } break;
        case ELEMENT_TYPE_QUERY: /* %q */
            if (req->input.query_at != SIZE_MAX) {
                size_t len = req->input.path.len - req->input.query_at;
                RESERVE(len * unsafe_factor);
                pos = append_unsafe_string(pos, req->input.path.base + req->input.query_at, len);
            }
            break;
        case ELEMENT_TYPE_REQUEST_LINE: /* %r */
            RESERVE((req->input.method.len + req->input.path.len) * unsafe_factor + sizeof("  HTTP/1.1"));
            pos = append_unsafe_string(pos, req->input.method.base, req->input.method.len);
            *pos++ = ' ';
            pos = append_unsafe_string(pos, req->input.path.base, req->input.path.len);
            *pos++ = ' ';
            pos += h2o_stringify_protocol_version(pos, req->version);
            break;
        case ELEMENT_TYPE_STATUS: /* %s */
            RESERVE(sizeof(H2O_INT32_LONGEST_STR) - 1);
            pos += sprintf(pos, "%" PRId32, (int32_t)(element->original_response ? req->res.original.status : req->res.status));
            break;
        case ELEMENT_TYPE_TIMESTAMP: /* %t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            RESERVE(H2O_TIMESTR_LOG_LEN + 2);
            *pos++ = '[';
            pos = append_safe_string(pos, req->processed_at.str->log, H2O_TIMESTR_LOG_LEN);
            *pos++ = ']';
            break;
        case ELEMENT_TYPE_TIMESTAMP_STRFTIME: /* %{...}t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            {
                size_t bufsz, len;
                if (localt.tm_year == 0)
                    localtime_r(&req->processed_at.at.tv_sec, &localt);
                for (bufsz = 128;; bufsz *= 2) {
                    RESERVE(bufsz);
                    if ((len = strftime(pos, bufsz, element->data.name.base, &localt)) != 0)
                        break;
                }
                pos += len;
            }
            break;
        case ELEMENT_TYPE_TIMESTAMP_SEC_SINCE_EPOCH: /* %{sec}t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            RESERVE(sizeof(H2O_UINT32_LONGEST_STR) - 1);
            pos += sprintf(pos, "%" PRIu32, (uint32_t)req->processed_at.at.tv_sec);
            break;
        case ELEMENT_TYPE_TIMESTAMP_MSEC_SINCE_EPOCH: /* %{msec}t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            RESERVE(sizeof(H2O_UINT64_LONGEST_STR) - 1);
            pos += sprintf(pos, "%" PRIu64,
                           (uint64_t)req->processed_at.at.tv_sec * 1000 + (uint64_t)req->processed_at.at.tv_usec / 1000);
            break;
        case ELEMENT_TYPE_TIMESTAMP_USEC_SINCE_EPOCH: /* %{usec}t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            RESERVE(sizeof(H2O_UINT64_LONGEST_STR) - 1);
            pos +=
                sprintf(pos, "%" PRIu64, (uint64_t)req->processed_at.at.tv_sec * 1000000 + (uint64_t)req->processed_at.at.tv_usec);
            break;
        case ELEMENT_TYPE_TIMESTAMP_MSEC_FRAC: /* %{msec_frac}t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            RESERVE(3);
            pos += sprintf(pos, "%03u", (unsigned)(req->processed_at.at.tv_usec / 1000));
            break;
        case ELEMENT_TYPE_TIMESTAMP_USEC_FRAC: /* %{usec_frac}t */
            if (h2o_timeval_is_null(&req->processed_at.at))
                goto EmitNull;
            RESERVE(6);
            pos += sprintf(pos, "%06u", (unsigned)req->processed_at.at.tv_usec);
            break;
        case ELEMENT_TYPE_URL_PATH: /* %U */ {
            size_t path_len = req->input.query_at == SIZE_MAX ? req->input.path.len : req->input.query_at;
            RESERVE(path_len * unsafe_factor);
            pos = append_unsafe_string(pos, req->input.path.base, path_len);
        } break;
        case ELEMENT_TYPE_REMOTE_USER: /* %u */ {
            h2o_iovec_t *remote_user = h2o_req_getenv(req, H2O_STRLIT("REMOTE_USER"), 0);
            if (remote_user == NULL)
                goto EmitNull;
            RESERVE(remote_user->len * unsafe_factor);
            pos = append_unsafe_string(pos, remote_user->base, remote_user->len);
        } break;
        case ELEMENT_TYPE_AUTHORITY: /* %V */
            RESERVE(req->input.authority.len * unsafe_factor);
            pos = append_unsafe_string(pos, req->input.authority.base, req->input.authority.len);
            break;
        case ELEMENT_TYPE_HOSTCONF: /* %v */
            RESERVE(req->hostconf->authority.hostport.len * unsafe_factor);
            pos = append_unsafe_string(pos, req->hostconf->authority.hostport.base, req->hostconf->authority.hostport.len);
            break;

#define EMIT_HEADER(__headers, concat, findfunc, ...)                                                                              \
    do {                                                                                                                           \
        h2o_headers_t *headers = (__headers);                                                                                      \
        ssize_t index = -1;                                                                                                        \
        int found = 0;                                                                                                             \
        while ((index = (findfunc)(headers, __VA_ARGS__, index)) != -1) {                                                          \
            if (found) {                                                                                                           \
                RESERVE(2);                                                                                                        \
                *pos++ = ',';                                                                                                      \
                *pos++ = ' ';                                                                                                      \
            } else {                                                                                                               \
                found = 1;                                                                                                         \
            }                                                                                                                      \
            const h2o_header_t *header = headers->entries + index;                                                                 \
            RESERVE(header->value.len *unsafe_factor);                                                                             \
            pos = append_unsafe_string(pos, header->value.base, header->value.len);                                                \
            if (!concat)                                                                                                           \
                break;                                                                                                             \
        }                                                                                                                          \
        if (!found)                                                                                                                \
            goto EmitNull;                                                                                                         \
    } while (0)

        case ELEMENT_TYPE_IN_HEADER_TOKEN:
            EMIT_HEADER(&req->headers, 0, h2o_find_header, element->data.header_token);
            break;
        case ELEMENT_TYPE_IN_HEADER_STRING:
            EMIT_HEADER(&req->headers, 0, h2o_find_header_by_str, element->data.name.base, element->data.name.len);
            break;
        case ELEMENT_TYPE_OUT_HEADER_TOKEN:
            EMIT_HEADER(element->original_response ? &req->res.original.headers : &req->res.headers, 0, h2o_find_header,
                        element->data.header_token);
            break;
        case ELEMENT_TYPE_OUT_HEADER_STRING:
            EMIT_HEADER(element->original_response ? &req->res.original.headers : &req->res.headers, 0, h2o_find_header_by_str,
                        element->data.name.base, element->data.name.len);
            break;
        case ELEMENT_TYPE_OUT_HEADER_TOKEN_CONCATENATED:
            EMIT_HEADER(element->original_response ? &req->res.original.headers : &req->res.headers, 1, h2o_find_header,
                        element->data.header_token);
            break;

#undef EMIT_HEADER

        case ELEMENT_TYPE_CONNECTION_ID:
            RESERVE(sizeof(H2O_UINT64_LONGEST_STR) - 1);
            pos += sprintf(pos, "%" PRIu64, req->conn->id);
            break;

        case ELEMENT_TYPE_CONNECT_TIME:
            APPEND_DURATION(pos, connect_time);
            break;

        case ELEMENT_TYPE_REQUEST_HEADER_TIME:
            APPEND_DURATION(pos, header_time);
            break;

        case ELEMENT_TYPE_REQUEST_BODY_TIME:
            APPEND_DURATION(pos, body_time);
            break;

        case ELEMENT_TYPE_REQUEST_TOTAL_TIME:
            APPEND_DURATION(pos, request_total_time);
            break;

        case ELEMENT_TYPE_PROCESS_TIME:
            APPEND_DURATION(pos, process_time);
            break;

        case ELEMENT_TYPE_RESPONSE_TIME:
            APPEND_DURATION(pos, response_time);
            break;

        case ELEMENT_TYPE_DURATION:
            APPEND_DURATION(pos, duration);
            break;

        case ELEMENT_TYPE_ERROR: {
            size_t i;
            for (i = 0; i != req->error_logs.size; ++i) {
                h2o_req_error_log_t *log = req->error_logs.entries + i;
                size_t module_len = strlen(log->module);
                RESERVE(sizeof("[] ") - 1 + module_len + log->msg.len * unsafe_factor);
                *pos++ = '[';
                pos = append_safe_string(pos, log->module, module_len);
                *pos++ = ']';
                *pos++ = ' ';
                pos = append_unsafe_string(pos, log->msg.base, log->msg.len);
            }
        } break;

        case ELEMENT_TYPE_PROTOCOL_SPECIFIC: {
            h2o_iovec_t (*cb)(h2o_req_t *) = req->conn->callbacks->log_.callbacks[element->data.protocol_specific_callback_index];
            if (cb != NULL) {
                h2o_iovec_t s = cb(req);
                if (s.base == NULL)
                    goto EmitNull;
                RESERVE(s.len);
                pos = append_safe_string(pos, s.base, s.len);
            } else {
                goto EmitNull;
            }
        } break;

        case ELEMENT_TYPE_LOGNAME:      /* %l */
        case ELEMENT_TYPE_EXTENDED_VAR: /* %{...}x */
        EmitNull:
            RESERVE(nullexpr.len);
            /* special case that trims surrounding quotes */
            if (element->magically_quoted_json) {
                --pos;
                pos = append_safe_string(pos, nullexpr.base, nullexpr.len);
                pos = append_safe_string(pos, element->suffix.base + 1, element->suffix.len - 1);
                continue;
            }
            pos = append_safe_string(pos, nullexpr.base, nullexpr.len);
            break;

        default:
            assert(!"unknown type");
            break;
        }

#undef RESERVE

        pos = append_safe_string(pos, element->suffix.base, element->suffix.len);
    }

    *len = pos - line;
    return line;
}
