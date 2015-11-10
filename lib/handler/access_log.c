/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o.h"
#include "h2o/serverutil.h"

#define LOG_ALLOCA_SIZE 4096

enum {
    ELEMENT_TYPE_EMPTY,               /* empty element (with suffix only) */
    ELEMENT_TYPE_LOCAL_ADDR,          /* %A */
    ELEMENT_TYPE_BYTES_SENT,          /* %b */
    ELEMENT_TYPE_PROTOCOL,            /* %H */
    ELEMENT_TYPE_REMOTE_ADDR,         /* %h */
    ELEMENT_TYPE_LOGNAME,             /* %l */
    ELEMENT_TYPE_METHOD,              /* %m */
    ELEMENT_TYPE_LOCAL_PORT,          /* %p */
    ELEMENT_TYPE_QUERY,               /* %q */
    ELEMENT_TYPE_REQUEST_LINE,        /* %r */
    ELEMENT_TYPE_STATUS,              /* %s */
    ELEMENT_TYPE_TIMESTAMP,           /* %t */
    ELEMENT_TYPE_URL_PATH,            /* %U */
    ELEMENT_TYPE_REMOTE_USER,         /* %u */
    ELEMENT_TYPE_AUTHORITY,           /* %V */
    ELEMENT_TYPE_HOSTCONF,            /* %v */
    ELEMENT_TYPE_IN_HEADER_TOKEN,     /* %{data.header_token}i */
    ELEMENT_TYPE_IN_HEADER_STRING,    /* %{data.name}i */
    ELEMENT_TYPE_OUT_HEADER_TOKEN,    /* %{data.header_token}o */
    ELEMENT_TYPE_OUT_HEADER_STRING,   /* %{data.name}o */
    ELEMENT_TYPE_EXTENDED_VAR,        /* %{data.name}x */
    ELEMENT_TYPE_CONNECT_TIME,        /* %{connect-time}x */
    ELEMENT_TYPE_REQUEST_HEADER_TIME, /* %{request-header-time}x */
    ELEMENT_TYPE_REQUEST_BODY_TIME,   /* %{request-body-time}x */
    ELEMENT_TYPE_REQUEST_TOTAL_TIME,  /* %{request-total-time}x */
    ELEMENT_TYPE_PROCESS_TIME,        /* %{process-time}x */
    ELEMENT_TYPE_RESPONSE_TIME,       /* %{response-total-time}x */
    ELEMENT_TYPE_DURATION,            /* %{duration}x */
    NUM_ELEMENT_TYPES
};

struct log_element_t {
    unsigned type;
    h2o_iovec_t suffix;
    union {
        const h2o_token_t *header_token;
        h2o_iovec_t name;
    } data;
};

struct st_h2o_access_log_filehandle_t {
    struct log_element_t *elements;
    size_t num_elements;
    int fd;
};

struct st_h2o_access_logger_t {
    h2o_logger_t super;
    h2o_access_log_filehandle_t *fh;
};

static h2o_iovec_t strdup_lowercased(const char *s, size_t len)
{
    h2o_iovec_t v = h2o_strdup(NULL, s, len);
    h2o_strtolower(v.base, v.len);
    return v;
}

static struct log_element_t *compile_log_format(const char *fmt, size_t *_num_elements)
{
    struct log_element_t *elements = NULL;
    size_t fmt_len = strlen(fmt), num_elements = 0;
    const char *pt = fmt;

/* suffix buffer is always guaranteed to be larger than the fmt + (sizeof('\n') - 1) (so that they would be no buffer overruns) */
#define NEW_ELEMENT(ty)                                                                                                            \
    do {                                                                                                                           \
        elements = h2o_mem_realloc(elements, sizeof(*elements) * (num_elements + 1));                                              \
        elements[num_elements].type = ty;                                                                                          \
        elements[num_elements].suffix = h2o_iovec_init(h2o_mem_alloc(fmt_len + 1), 0);                                             \
        ++num_elements;                                                                                                            \
    } while (0)

    while (*pt != '\0') {
        if (*pt == '%') {
            ++pt;
            if (*pt == '%') {
                /* skip */
            } else if (*pt == '{') {
                const h2o_token_t *token;
                const char *quote_end = strchr(++pt, '}');
                if (quote_end == NULL) {
                    fprintf(stderr, "failed to compile log format: unterminated header name starting at: \"%16s\"\n", pt);
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
                        NEW_ELEMENT(modifier == 'i' ? ELEMENT_TYPE_IN_HEADER_TOKEN : ELEMENT_TYPE_OUT_HEADER_TOKEN);
                        elements[num_elements - 1].data.header_token = token;
                    } else {
                        NEW_ELEMENT(modifier == 'i' ? ELEMENT_TYPE_IN_HEADER_STRING : ELEMENT_TYPE_OUT_HEADER_STRING);
                        elements[num_elements - 1].data.name = name;
                    }
                } break;
                case 'x':
                    if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("connect-time"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_CONNECT_TIME);
                    } else if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("request-total-time"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_REQUEST_TOTAL_TIME);
                    } else if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("request-header-time"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_REQUEST_HEADER_TIME);
                    } else if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("request-body-time"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_REQUEST_BODY_TIME);
                    } else if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("process-time"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_PROCESS_TIME);
                    } else if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("response-time"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_RESPONSE_TIME);
                    } else if (h2o_lcstris(pt, quote_end - pt, H2O_STRLIT("duration"))) {
                        NEW_ELEMENT(ELEMENT_TYPE_DURATION);
                    } else {
                        h2o_iovec_t name = strdup_lowercased(pt, quote_end - pt);
                        NEW_ELEMENT(ELEMENT_TYPE_EXTENDED_VAR);
                        elements[num_elements - 1].data.name = name;
                    }
                    break;
                default:
                    fprintf(stderr, "failed to compile log format: header name is not followed by either `i`, `o`, `x`\n");
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
                    fprintf(stderr, "failed to compile log format: unknown escape sequence: %%%c\n", pt[-1]);
                    goto Error;
                }
                NEW_ELEMENT(type);
                continue;
            }
        }
        /* emit current char */
        if (elements == NULL)
            NEW_ELEMENT(ELEMENT_TYPE_EMPTY);
        elements[num_elements - 1].suffix.base[elements[num_elements - 1].suffix.len++] = *pt++;
    }

    /* emit end-of-line */
    if (elements == NULL)
        NEW_ELEMENT(ELEMENT_TYPE_EMPTY);
    elements[num_elements - 1].suffix.base[elements[num_elements - 1].suffix.len++] = '\n';

#undef NEW_ELEMENT

    *_num_elements = num_elements;
    return elements;

Error:
    free(elements);
    return NULL;
}

static inline char *append_safe_string(char *pos, const char *src, size_t len)
{
    memcpy(pos, src, len);
    return pos + len;
}

static char *append_unsafe_string(char *pos, const char *src, size_t len)
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

static char *append_addr(char *pos, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *sa), h2o_conn_t *conn)
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
    *pos++ = '-';
    return pos;
}

static char *append_port(char *pos, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *sa), h2o_conn_t *conn)
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
    *pos++ = '-';
    return pos;
}

static inline int timeval_is_null(struct timeval *tv)
{
    return tv->tv_sec == 0;
}

#define DURATION_MAX_LEN (sizeof("-2147483648.999999") - 1)

static char *append_duration(char *pos, struct timeval *from, struct timeval *until)
{
    if (timeval_is_null(from) || timeval_is_null(until)) {
        *pos++ = '-';
    } else {
        int32_t delta_sec = (int32_t)until->tv_sec - (int32_t)from->tv_sec;
        int32_t delta_usec = (int32_t)until->tv_usec - (int32_t)from->tv_usec;
        if (delta_usec < 0) {
            delta_sec -= 1;
            delta_usec += 1000000;
        }
        pos += sprintf(pos, "%" PRId32, delta_sec);
        if (delta_usec != 0) {
            int i;
            *pos++ = '.';
            for (i = 5; i >= 0; --i) {
                pos[i] = '0' + delta_usec % 10;
                delta_usec /= 10;
            }
            pos += 6;
        }
    }
    return pos;
}

static char *expand_line_buf(char *line, size_t cur_size, size_t required)
{
    size_t new_size = cur_size;

    /* determine the new size */
    do {
        new_size *= 2;
    } while (new_size < required);

    /* reallocate */
    if (cur_size == LOG_ALLOCA_SIZE) {
        char *newpt = h2o_mem_alloc(new_size);
        memcpy(newpt, line, cur_size);
        line = newpt;
    } else {
        line = h2o_mem_realloc(line, new_size);
    }

    return line;
}

static void log_access(h2o_logger_t *_self, h2o_req_t *req)
{
    struct st_h2o_access_logger_t *self = (struct st_h2o_access_logger_t *)_self;
    h2o_access_log_filehandle_t *fh = self->fh;
    char *line, *pos, *line_end;
    size_t element_index;

    /* note: LOG_ALLOCA_SIZE should be much greater than NI_MAXHOST to avoid unnecessary reallocations */
    line = alloca(LOG_ALLOCA_SIZE);
    pos = line;
    line_end = line + LOG_ALLOCA_SIZE;

    for (element_index = 0; element_index != fh->num_elements; ++element_index) {
        struct log_element_t *element = fh->elements + element_index;

/* reserve capacity + suffix.len */
#define RESERVE(capacity)                                                                                                          \
    do {                                                                                                                           \
        if ((capacity) + element->suffix.len > line_end - pos) {                                                                   \
            size_t off = pos - line;                                                                                               \
            line = expand_line_buf(line, line_end - line, off + (capacity) + element->suffix.len);                                 \
            pos = line + off;                                                                                                      \
        }                                                                                                                          \
    } while (0)

        switch (element->type) {
        case ELEMENT_TYPE_EMPTY:
            RESERVE(0);
            break;
        case ELEMENT_TYPE_LOCAL_ADDR: /* %A */
            RESERVE(NI_MAXHOST);
            pos = append_addr(pos, req->conn->get_sockname, req->conn);
            break;
        case ELEMENT_TYPE_BYTES_SENT: /* %b */
            RESERVE(sizeof("18446744073709551615") - 1);
            pos += sprintf(pos, "%llu", (unsigned long long)req->bytes_sent);
            break;
        case ELEMENT_TYPE_PROTOCOL: /* %H */
            RESERVE(sizeof("HTTP/1.1"));
            pos += h2o_stringify_protocol_version(pos, req->version);
            break;
        case ELEMENT_TYPE_REMOTE_ADDR: /* %h */
            RESERVE(NI_MAXHOST);
            pos = append_addr(pos, req->conn->get_peername, req->conn);
            break;
        case ELEMENT_TYPE_METHOD: /* %m */
            RESERVE(req->input.method.len * 4);
            pos = append_unsafe_string(pos, req->input.method.base, req->input.method.len);
            break;
        case ELEMENT_TYPE_LOCAL_PORT: /* %p */
            RESERVE(sizeof("65535") - 1);
            pos = append_port(pos, req->conn->get_sockname, req->conn);
            break;
        case ELEMENT_TYPE_QUERY: /* %q */
            if (req->input.query_at != SIZE_MAX) {
                size_t len = req->input.path.len - req->input.query_at;
                RESERVE(len * 4);
                pos = append_unsafe_string(pos, req->input.path.base + req->input.query_at, len);
            }
            break;
        case ELEMENT_TYPE_REQUEST_LINE: /* %r */
            RESERVE((req->input.method.len + req->input.path.len) * 4 + sizeof("  HTTP/1.1"));
            pos = append_unsafe_string(pos, req->input.method.base, req->input.method.len);
            *pos++ = ' ';
            pos = append_unsafe_string(pos, req->input.path.base, req->input.path.len);
            *pos++ = ' ';
            pos += h2o_stringify_protocol_version(pos, req->version);
            break;
        case ELEMENT_TYPE_STATUS: /* %s */
            RESERVE(sizeof("2147483647") - 1);
            pos += sprintf(pos, "%d", req->res.status);
            break;
        case ELEMENT_TYPE_TIMESTAMP: /* %t */
            RESERVE(H2O_TIMESTR_LOG_LEN + 2);
            *pos++ = '[';
            pos = append_safe_string(pos, req->processed_at.str->log, H2O_TIMESTR_LOG_LEN);
            *pos++ = ']';
            break;
        case ELEMENT_TYPE_URL_PATH: /* %U */
        {
            size_t path_len = req->input.query_at == SIZE_MAX ? req->input.path.len : req->input.query_at;
            RESERVE(req->input.scheme->name.len + (sizeof("://") - 1) + (req->input.authority.len + path_len) * 4);
            pos = append_safe_string(pos, req->input.scheme->name.base, req->input.scheme->name.len);
            pos = append_safe_string(pos, H2O_STRLIT("://"));
            pos = append_unsafe_string(pos, req->input.authority.base, req->input.authority.len);
            pos = append_unsafe_string(pos, req->input.path.base, path_len);
        } break;
        case ELEMENT_TYPE_AUTHORITY: /* %V */
            RESERVE(req->input.authority.len * 4);
            pos = append_unsafe_string(pos, req->input.authority.base, req->input.authority.len);
            break;
        case ELEMENT_TYPE_HOSTCONF: /* %v */
            RESERVE(req->hostconf->authority.hostport.len * 4);
            pos = append_unsafe_string(pos, req->hostconf->authority.hostport.base, req->hostconf->authority.hostport.len);
            break;

        case ELEMENT_TYPE_LOGNAME:     /* %l */
        case ELEMENT_TYPE_REMOTE_USER: /* %u */
        case ELEMENT_TYPE_EXTENDED_VAR: /* %{...}x */
            RESERVE(1);
            *pos++ = '-';
            break;

#define EMIT_HEADER(headers, _index)                                                                                               \
    do {                                                                                                                           \
        ssize_t index = (_index);                                                                                                  \
        if (index != -1) {                                                                                                         \
            const h2o_header_t *header = (headers)->entries + index;                                                               \
            RESERVE(header->value.len * 4);                                                                                        \
            pos = append_unsafe_string(pos, header->value.base, header->value.len);                                                \
        } else {                                                                                                                   \
            RESERVE(1);                                                                                                            \
            *pos++ = '-';                                                                                                          \
        }                                                                                                                          \
    } while (0)
        case ELEMENT_TYPE_IN_HEADER_TOKEN:
            EMIT_HEADER(&req->headers, h2o_find_header(&req->headers, element->data.header_token, SIZE_MAX));
            break;
        case ELEMENT_TYPE_IN_HEADER_STRING:
            EMIT_HEADER(&req->headers,
                        h2o_find_header_by_str(&req->headers, element->data.name.base, element->data.name.len, SIZE_MAX));
            break;
        case ELEMENT_TYPE_OUT_HEADER_TOKEN:
            EMIT_HEADER(&req->res.headers, h2o_find_header(&req->res.headers, element->data.header_token, SIZE_MAX));
            break;
        case ELEMENT_TYPE_OUT_HEADER_STRING:
            EMIT_HEADER(&req->res.headers,
                        h2o_find_header_by_str(&req->res.headers, element->data.name.base, element->data.name.len, SIZE_MAX));
            break;
#undef EMIT_HEADER

        case ELEMENT_TYPE_CONNECT_TIME:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->conn->connected_at, &req->timestamps.request_begin_at);
            break;

        case ELEMENT_TYPE_REQUEST_HEADER_TIME:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->timestamps.request_begin_at, timeval_is_null(&req->timestamps.request_body_begin_at)
                                                                              ? &req->processed_at.at
                                                                              : &req->timestamps.request_body_begin_at);
            break;

        case ELEMENT_TYPE_REQUEST_BODY_TIME:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->timestamps.request_body_begin_at, &req->processed_at.at);
            break;

        case ELEMENT_TYPE_REQUEST_TOTAL_TIME:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->timestamps.request_begin_at, &req->processed_at.at);
            break;

        case ELEMENT_TYPE_PROCESS_TIME:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->processed_at.at, &req->timestamps.response_start_at);
            break;

        case ELEMENT_TYPE_RESPONSE_TIME:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->timestamps.response_start_at, &req->timestamps.response_end_at);
            break;

        case ELEMENT_TYPE_DURATION:
            RESERVE(DURATION_MAX_LEN);
            pos = append_duration(pos, &req->timestamps.request_begin_at, &req->timestamps.response_end_at);
            break;

        default:
            assert(!"unknown type");
            break;
        }

#undef RESERVE

        pos = append_safe_string(pos, element->suffix.base, element->suffix.len);
    }

    write(fh->fd, line, pos - line);

    if (line_end - line != LOG_ALLOCA_SIZE)
        free(line);
}

void on_dispose_handle(void *_fh)
{
    h2o_access_log_filehandle_t *fh = _fh;
    size_t i;

    for (i = 0; i != fh->num_elements; ++i)
        free(fh->elements[i].suffix.base);
    free(fh->elements);
    close(fh->fd);
}

int h2o_access_log_open_log(const char *path)
{
    int fd;

    if (path[0] == '|') {
        int pipefds[2];
        pid_t pid;
        char *argv[4] = {"/bin/sh", "-c", (char *)(path + 1), NULL};
        /* create pipe */
        if (pipe(pipefds) != 0) {
            perror("pipe failed");
            return -1;
        }
        if (fcntl(pipefds[1], F_SETFD, FD_CLOEXEC) == -1) {
            perror("failed to set FD_CLOEXEC on pipefds[1]");
            return -1;
        }
        /* spawn the logger */
        int mapped_fds[] = {pipefds[0], 0, /* map pipefds[0] to stdin */
                            -1};
        if ((pid = h2o_spawnp(argv[0], argv, mapped_fds, 0)) == -1) {
            fprintf(stderr, "failed to open logger: %s:%s\n", path + 1, strerror(errno));
            return -1;
        }
        /* close the read side of the pipefds and return the write side */
        close(pipefds[0]);
        fd = pipefds[1];
    } else {
        if ((fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644)) == -1) {
            fprintf(stderr, "failed to open log file:%s:%s\n", path, strerror(errno));
            return -1;
        }
    }

    return fd;
}

h2o_access_log_filehandle_t *h2o_access_log_open_handle(const char *path, const char *fmt)
{
    struct log_element_t *elements;
    size_t num_elements;
    int fd;
    h2o_access_log_filehandle_t *fh;

    /* default to combined log format */
    if (fmt == NULL)
        fmt = "%h %l %u %t \"%r\" %s %b \"%{Referer}i\" \"%{User-agent}i\"";
    if ((elements = compile_log_format(fmt, &num_elements)) == NULL)
        return NULL;

    /* open log file */
    if ((fd = h2o_access_log_open_log(path)) == -1)
        return NULL;

    fh = h2o_mem_alloc_shared(NULL, sizeof(*fh), on_dispose_handle);
    fh->elements = elements;
    fh->num_elements = num_elements;
    fh->fd = fd;

    return fh;
}

static void dispose(h2o_logger_t *_self)
{
    struct st_h2o_access_logger_t *self = (void *)_self;

    h2o_mem_release_shared(self->fh);
}

h2o_logger_t *h2o_access_log_register(h2o_pathconf_t *pathconf, h2o_access_log_filehandle_t *fh)
{
    struct st_h2o_access_logger_t *self = (void *)h2o_create_logger(pathconf, sizeof(*self));

    self->super.dispose = dispose;
    self->super.log_access = log_access;
    self->fh = fh;
    h2o_mem_addref_shared(fh);

    return &self->super;
}
