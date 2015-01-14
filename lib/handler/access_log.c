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
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o.h"

#define LOG_ALLOCA_SIZE 4096

enum {
    ELEMENT_TYPE_EMPTY,             /* empty element (with suffix only) */
    ELEMENT_TYPE_REMOTE_ADDR,       /* %h */
    ELEMENT_TYPE_LOGNAME,           /* %l */
    ELEMENT_TYPE_REMOTE_USER,       /* %u */
    ELEMENT_TYPE_TIMESTAMP,         /* %t */
    ELEMENT_TYPE_REQUEST_LINE,      /* %r */
    ELEMENT_TYPE_STATUS,            /* %s */
    ELEMENT_TYPE_BYTES_SENT,        /* %b */
    ELEMENT_TYPE_IN_HEADER_TOKEN,   /* %{data.header_token}i */
    ELEMENT_TYPE_IN_HEADER_STRING,  /* %{data.header_string}i */
    ELEMENT_TYPE_OUT_HEADER_TOKEN,  /* %{data.header_token}o */
    ELEMENT_TYPE_OUT_HEADER_STRING, /* %{data.header_string}i */
    NUM_ELEMENT_TYPES
};

struct log_element_t {
    unsigned type;
    h2o_iovec_t suffix;
    union {
        const h2o_token_t *header_token;
        h2o_iovec_t header_string;
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
                token = h2o_lookup_token(pt, quote_end - pt);
                switch (quote_end[1]) {
                case 'i':
                    if (token != NULL) {
                        NEW_ELEMENT(ELEMENT_TYPE_IN_HEADER_TOKEN);
                        elements[num_elements - 1].data.header_token = token;
                    } else {
                        NEW_ELEMENT(ELEMENT_TYPE_IN_HEADER_STRING);
                        elements[num_elements - 1].data.header_string = h2o_strdup(NULL, pt, quote_end - pt);
                    }
                    break;
                case 'o':
                    if (token != NULL) {
                        NEW_ELEMENT(ELEMENT_TYPE_OUT_HEADER_TOKEN);
                        elements[num_elements - 1].data.header_token = token;
                    } else {
                        NEW_ELEMENT(ELEMENT_TYPE_OUT_HEADER_STRING);
                        elements[num_elements - 1].data.header_string = h2o_strdup(NULL, pt, quote_end - pt);
                    }
                    break;
                default:
                    fprintf(stderr, "failed to compile log format: header name is not followed by either `i` or `o`\n");
                    goto Error;
                }
                pt = quote_end + 2;
            } else {
                unsigned type = NUM_ELEMENT_TYPES;
                switch (*pt++) {
#define TYPE_MAP(ch, ty)                                                                                                           \
    case ch:                                                                                                                       \
        type = ty;                                                                                                                 \
        break
                    TYPE_MAP('h', ELEMENT_TYPE_REMOTE_ADDR);
                    TYPE_MAP('l', ELEMENT_TYPE_LOGNAME);
                    TYPE_MAP('u', ELEMENT_TYPE_REMOTE_USER);
                    TYPE_MAP('t', ELEMENT_TYPE_TIMESTAMP);
                    TYPE_MAP('r', ELEMENT_TYPE_REQUEST_LINE);
                    TYPE_MAP('s', ELEMENT_TYPE_STATUS);
                    TYPE_MAP('b', ELEMENT_TYPE_BYTES_SENT);
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
        case ELEMENT_TYPE_REMOTE_ADDR: {
            char hostname[NI_MAXHOST];
            if (req->conn->peername.addr != NULL && req->conn->peername.addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (void *)req->conn->peername.addr;
                uint32_t addr;
                RESERVE(sizeof("255.255.255.255") - 1);
                addr = htonl(sin->sin_addr.s_addr);
                pos += sprintf(pos, "%d.%d.%d.%d", addr >> 24, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255);
            } else if (req->conn->peername.addr != NULL &&
                       getnameinfo(req->conn->peername.addr, req->conn->peername.len, hostname, sizeof(hostname), NULL, 0,
                                   NI_NUMERICHOST) == 0) {
                size_t len = strlen(hostname);
                RESERVE(len);
                pos = append_safe_string(pos, hostname, len);
            } else {
                RESERVE(1);
                *pos++ = '-';
            }
        } break;
        case ELEMENT_TYPE_LOGNAME:
        case ELEMENT_TYPE_REMOTE_USER:
            RESERVE(1);
            *pos++ = '-';
            break;
        case ELEMENT_TYPE_TIMESTAMP:
            RESERVE(H2O_TIMESTR_LOG_LEN + 2);
            *pos++ = '[';
            pos = append_safe_string(pos, req->processed_at.str->log, H2O_TIMESTR_LOG_LEN);
            *pos++ = ']';
            break;
        case ELEMENT_TYPE_REQUEST_LINE:
            RESERVE((req->method.len + req->path.len) * 4 + sizeof("  HTTP/1.2147483647") - 1);
            pos = append_unsafe_string(pos, req->method.base, req->method.len);
            *pos++ = ' ';
            pos = append_unsafe_string(pos, req->path.base, req->path.len);
            *pos++ = ' ';
            if (req->version < 0x200) {
                pos = append_safe_string(pos, H2O_STRLIT("HTTP/1."));
                if ((req->version & 0xff) <= 9) {
                    *pos++ = '0' + (req->version & 0xff);
                } else {
                    pos += sprintf(pos, "%d", req->version);
                }
            } else {
                pos = append_safe_string(pos, H2O_STRLIT("HTTP/2"));
            }
            break;
        case ELEMENT_TYPE_STATUS:
            RESERVE(sizeof("2147483647") - 1);
            pos += sprintf(pos, "%d", req->res.status);
            break;
        case ELEMENT_TYPE_BYTES_SENT:
            RESERVE(sizeof("18446744073709551615") - 1);
            pos += sprintf(pos, "%llu", (unsigned long long)req->bytes_sent);
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
            EMIT_HEADER(&req->headers, h2o_find_header_by_str(&req->headers, element->data.header_string.base,
                                                              element->data.header_string.len, SIZE_MAX));
            break;
        case ELEMENT_TYPE_OUT_HEADER_TOKEN:
            EMIT_HEADER(&req->res.headers, h2o_find_header(&req->res.headers, element->data.header_token, SIZE_MAX));
            break;
        case ELEMENT_TYPE_OUT_HEADER_STRING:
            EMIT_HEADER(&req->res.headers, h2o_find_header_by_str(&req->res.headers, element->data.header_string.base,
                                                                  element->data.header_string.len, SIZE_MAX));
            break;
#undef EMIT_HEADER

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
    if (path[0] == '|') {
        FILE *fp;
        if ((fp = popen(path + 1, "w")) == NULL) {
            fprintf(stderr, "failed to open log pipe to command:%s\n", path + 1);
            return NULL;
        }
        fd = dup(fileno(fp));
        fclose(fp);
        if (fd == -1) {
            fprintf(stderr, "failed to dup pipe fd:%s\n", strerror(errno));
            return NULL;
        }
    } else {
        if ((fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644)) == -1) {
            fprintf(stderr, "failed to open log file:%s:%s\n", path, strerror(errno));
            return NULL;
        }
    }

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
