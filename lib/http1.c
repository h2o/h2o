/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Shota Fukumori,
 *                         Fastly, Inc.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "picohttpparser.h"
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

#define MAX_PULL_BUF_SZ 65536

struct st_h2o_http1_finalostream_t {
    h2o_ostream_t super;
    int sent_headers;
    struct {
        void *buf;
        h2o_ostream_pull_cb cb;
    } pull;
};

struct st_h2o_http1_conn_t {
    h2o_conn_t super;
    h2o_socket_t *sock;
    /* internal structure */
    h2o_linklist_t _conns;
    h2o_timeout_t *_timeout;
    h2o_timeout_entry_t _timeout_entry;
    uint64_t _req_index;
    size_t _prevreqlen;
    size_t _reqsize;
    struct st_h2o_http1_req_entity_reader *_req_entity_reader;
    struct st_h2o_http1_finalostream_t _ostr_final;
    struct {
        void *data;
        h2o_http1_upgrade_cb cb;
    } upgrade;
    /* the HTTP request / response (intentionally placed at the last, since it is a large structure and has it's own ctor) */
    h2o_req_t req;
};

struct st_h2o_http1_req_entity_reader {
    void (*handle_incoming_entity)(struct st_h2o_http1_conn_t *conn);
};

struct st_h2o_http1_content_length_entity_reader {
    struct st_h2o_http1_req_entity_reader super;
    size_t content_length;
};

struct st_h2o_http1_chunked_entity_reader {
    struct st_h2o_http1_req_entity_reader super;
    struct phr_chunked_decoder decoder;
    size_t prev_input_size;
};

static void proceed_pull(struct st_h2o_http1_conn_t *conn, size_t nfilled);
static void finalostream_start_pull(h2o_ostream_t *_self, h2o_ostream_pull_cb cb);
static void finalostream_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state);
static void reqread_on_read(h2o_socket_t *sock, const char *err);
static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata);

const h2o_protocol_callbacks_t H2O_HTTP1_CALLBACKS = {
    NULL, /* graceful_shutdown (note: nothing special needs to be done for handling graceful shutdown) */
    foreach_request};

static int is_msie(h2o_req_t *req)
{
    ssize_t cursor = h2o_find_header(&req->headers, H2O_TOKEN_USER_AGENT, -1);
    if (cursor == -1)
        return 0;
    if (h2o_strstr(req->headers.entries[cursor].value.base, req->headers.entries[cursor].value.len, H2O_STRLIT("; MSIE ")) ==
        SIZE_MAX)
        return 0;
    return 1;
}

static void init_request(struct st_h2o_http1_conn_t *conn, int reinit)
{
    if (reinit)
        h2o_dispose_request(&conn->req);
    h2o_init_request(&conn->req, &conn->super, NULL);

    ++conn->_req_index;
    conn->req._ostr_top = &conn->_ostr_final.super;
    conn->_ostr_final.super.do_send = finalostream_send;
    conn->_ostr_final.super.start_pull = finalostream_start_pull;
    conn->_ostr_final.sent_headers = 0;
}

static void close_connection(struct st_h2o_http1_conn_t *conn, int close_socket)
{
    h2o_timeout_unlink(&conn->_timeout_entry);
    h2o_dispose_request(&conn->req);
    if (conn->sock != NULL && close_socket)
        h2o_socket_close(conn->sock);
    h2o_linklist_unlink(&conn->_conns);
    free(conn);
}

static void set_timeout(struct st_h2o_http1_conn_t *conn, h2o_timeout_t *timeout, h2o_timeout_cb cb)
{
    if (conn->_timeout != NULL) {
        h2o_timeout_unlink(&conn->_timeout_entry);
        conn->_timeout_entry.cb = NULL;
    }
    conn->_timeout = timeout;
    if (timeout != NULL) {
        h2o_timeout_link(conn->super.ctx->loop, timeout, &conn->_timeout_entry);
        conn->_timeout_entry.cb = cb;
    }
}

static void process_request(struct st_h2o_http1_conn_t *conn)
{
    if (conn->sock->ssl == NULL && conn->req.upgrade.base != NULL && conn->super.ctx->globalconf->http1.upgrade_to_http2 &&
        conn->req.upgrade.len >= 3 && h2o_lcstris(conn->req.upgrade.base, 3, H2O_STRLIT("h2c")) &&
        (conn->req.upgrade.len == 3 ||
         (conn->req.upgrade.len == 6 && (memcmp(conn->req.upgrade.base + 3, H2O_STRLIT("-14")) == 0 ||
                                         memcmp(conn->req.upgrade.base + 3, H2O_STRLIT("-16")) == 0)))) {
        if (h2o_http2_handle_upgrade(&conn->req, conn->super.connected_at) == 0) {
            return;
        }
    }
    h2o_process_request(&conn->req);
}

#define DECL_ENTITY_READ_SEND_ERROR_XXX(status_)                                                                                   \
    static void entity_read_send_error_##status_(struct st_h2o_http1_conn_t *conn, const char *reason, const char *body)           \
    {                                                                                                                              \
        conn->_req_entity_reader = NULL;                                                                                           \
        set_timeout(conn, NULL, NULL);                                                                                             \
        h2o_socket_read_stop(conn->sock);                                                                                          \
        conn->req.http1_is_persistent = 0;                                                                                         \
        conn->super.ctx->emitted_error_status[H2O_STATUS_ERROR_##status_]++;                                                       \
        h2o_send_error_generic(&conn->req, status_, reason, body, H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION);                          \
    }

DECL_ENTITY_READ_SEND_ERROR_XXX(400)
DECL_ENTITY_READ_SEND_ERROR_XXX(413)

static void on_entity_read_complete(struct st_h2o_http1_conn_t *conn)
{
    conn->_req_entity_reader = NULL;
    set_timeout(conn, NULL, NULL);
    h2o_socket_read_stop(conn->sock);
    process_request(conn);
}

static void handle_chunked_entity_read(struct st_h2o_http1_conn_t *conn)
{
    struct st_h2o_http1_chunked_entity_reader *reader = (void *)conn->_req_entity_reader;
    h2o_buffer_t *inbuf = conn->sock->input;
    size_t bufsz;
    ssize_t ret;

    /* decode the incoming data */
    if ((bufsz = inbuf->size - reader->prev_input_size) == 0)
        return;
    ret = phr_decode_chunked(&reader->decoder, inbuf->bytes + reader->prev_input_size, &bufsz);
    inbuf->size = reader->prev_input_size + bufsz;
    reader->prev_input_size = inbuf->size;
    if (ret != -1 && inbuf->size - conn->_reqsize >= conn->super.ctx->globalconf->max_request_entity_size) {
        entity_read_send_error_413(conn, "Request Entity Too Large", "request entity is too large");
        return;
    }
    if (ret < 0) {
        if (ret == -2) {
            /* incomplete */
            return;
        }
        /* error */
        entity_read_send_error_400(conn, "Invalid Request", "broken chunked-encoding");
        return;
    }
    /* complete */
    conn->req.entity = h2o_iovec_init(inbuf->bytes + conn->_reqsize, inbuf->size - conn->_reqsize);
    conn->_reqsize = inbuf->size;
    inbuf->size += ret; /* restore the number of extra bytes */

    on_entity_read_complete(conn);
}

static int create_chunked_entity_reader(struct st_h2o_http1_conn_t *conn)
{
    struct st_h2o_http1_chunked_entity_reader *reader = h2o_mem_alloc_pool(&conn->req.pool, sizeof(*reader));
    conn->_req_entity_reader = &reader->super;

    reader->super.handle_incoming_entity = handle_chunked_entity_read;
    memset(&reader->decoder, 0, sizeof(reader->decoder));
    reader->decoder.consume_trailer = 1;
    reader->prev_input_size = conn->_reqsize;

    return 0;
}

static void handle_content_length_entity_read(struct st_h2o_http1_conn_t *conn)
{
    struct st_h2o_http1_content_length_entity_reader *reader = (void *)conn->_req_entity_reader;

    /* wait until: reqsize == conn->_input.size */
    if (conn->sock->input->size < conn->_reqsize)
        return;

    /* all input has arrived */
    conn->req.entity = h2o_iovec_init(conn->sock->input->bytes + conn->_reqsize - reader->content_length, reader->content_length);
    on_entity_read_complete(conn);
}

static int create_content_length_entity_reader(struct st_h2o_http1_conn_t *conn, size_t content_length)
{
    struct st_h2o_http1_content_length_entity_reader *reader = h2o_mem_alloc_pool(&conn->req.pool, sizeof(*reader));
    conn->_req_entity_reader = &reader->super;

    reader->super.handle_incoming_entity = handle_content_length_entity_read;
    reader->content_length = content_length;
    conn->_reqsize += content_length;

    return 0;
}

static int create_entity_reader(struct st_h2o_http1_conn_t *conn, const struct phr_header *entity_header)
{
    /* strlen("content-length") is unequal to sizeof("transfer-encoding"), and thus checking the length only is sufficient */
    if (entity_header->name_len == sizeof("transfer-encoding") - 1) {
        /* transfer-encoding */
        if (!h2o_lcstris(entity_header->value, entity_header->value_len, H2O_STRLIT("chunked"))) {
            entity_read_send_error_400(conn, "Invalid Request", "unknown transfer-encoding");
            return -1;
        }
        return create_chunked_entity_reader(conn);
    } else {
        /* content-length */
        size_t content_length = h2o_strtosize(entity_header->value, entity_header->value_len);
        if (content_length == SIZE_MAX) {
            entity_read_send_error_400(conn, "Invalid Request", "broken content-length header");
            return -1;
        }
        if (content_length > conn->super.ctx->globalconf->max_request_entity_size) {
            entity_read_send_error_413(conn, "Request Entity Too Large", "request entity is too large");
            return -1;
        }
        return create_content_length_entity_reader(conn, (size_t)content_length);
    }
    /* failed */
    return -1;
}

static ssize_t init_headers(h2o_mem_pool_t *pool, h2o_headers_t *headers, const struct phr_header *src, size_t len,
                            h2o_iovec_t *connection, h2o_iovec_t *host, h2o_iovec_t *upgrade, h2o_iovec_t *expect)
{
    ssize_t entity_header_index = -1;

    assert(headers->size == 0);

    /* setup */
    if (len != 0) {
        size_t i;
        h2o_vector_reserve(pool, headers, len);
        for (i = 0; i != len; ++i) {
            const h2o_token_t *name_token;
            /* convert to lower-case in-place */
            h2o_strtolower((char *)src[i].name, src[i].name_len);
            if ((name_token = h2o_lookup_token(src[i].name, src[i].name_len)) != NULL) {
                if (name_token->is_init_header_special) {
                    if (name_token == H2O_TOKEN_HOST) {
                        host->base = (char *)src[i].value;
                        host->len = src[i].value_len;
                    } else if (name_token == H2O_TOKEN_CONTENT_LENGTH) {
                        if (entity_header_index == -1)
                            entity_header_index = i;
                    } else if (name_token == H2O_TOKEN_TRANSFER_ENCODING) {
                        entity_header_index = i;
                    } else if (name_token == H2O_TOKEN_EXPECT) {
                        expect->base = (char *)src[i].value;
                        expect->len = src[i].value_len;
                    } else if (name_token == H2O_TOKEN_UPGRADE) {
                        upgrade->base = (char *)src[i].value;
                        upgrade->len = src[i].value_len;
                    } else {
                        assert(!"logic flaw");
                    }
                } else {
                    h2o_add_header(pool, headers, name_token, src[i].value, src[i].value_len);
                    if (name_token == H2O_TOKEN_CONNECTION)
                        *connection = headers->entries[headers->size - 1].value;
                }
            } else {
                h2o_add_header_by_str(pool, headers, src[i].name, src[i].name_len, 0, src[i].value, src[i].value_len);
            }
        }
    }

    return entity_header_index;
}

static ssize_t fixup_request(struct st_h2o_http1_conn_t *conn, struct phr_header *headers, size_t num_headers, int minor_version,
                             h2o_iovec_t *expect)
{
    ssize_t entity_header_index;
    h2o_iovec_t connection = {NULL, 0}, host = {NULL, 0}, upgrade = {NULL, 0};

    expect->base = NULL;
    expect->len = 0;

    conn->req.input.scheme = conn->sock->ssl != NULL ? &H2O_URL_SCHEME_HTTPS : &H2O_URL_SCHEME_HTTP;
    conn->req.version = 0x100 | (minor_version != 0);

    /* init headers */
    entity_header_index =
        init_headers(&conn->req.pool, &conn->req.headers, headers, num_headers, &connection, &host, &upgrade, expect);

    /* copy the values to pool, since the buffer pointed by the headers may get realloced */
    if (entity_header_index != -1) {
        size_t i;
        conn->req.input.method = h2o_strdup(&conn->req.pool, conn->req.input.method.base, conn->req.input.method.len);
        conn->req.input.path = h2o_strdup(&conn->req.pool, conn->req.input.path.base, conn->req.input.path.len);
        for (i = 0; i != conn->req.headers.size; ++i) {
            h2o_header_t *header = conn->req.headers.entries + i;
            if (!h2o_iovec_is_token(header->name)) {
                *header->name = h2o_strdup(&conn->req.pool, header->name->base, header->name->len);
            }
            header->value = h2o_strdup(&conn->req.pool, header->value.base, header->value.len);
        }
        if (host.base != NULL)
            host = h2o_strdup(&conn->req.pool, host.base, host.len);
        if (upgrade.base != NULL)
            upgrade = h2o_strdup(&conn->req.pool, upgrade.base, upgrade.len);
    }

    /* move host header to req->authority */
    if (host.base != NULL)
        conn->req.input.authority = host;

    /* setup persistent flag (and upgrade info) */
    if (connection.base != NULL) {
        /* TODO contains_token function can be faster */
        if (h2o_contains_token(connection.base, connection.len, H2O_STRLIT("keep-alive"), ',')) {
            conn->req.http1_is_persistent = 1;
        }
        if (upgrade.base != NULL && h2o_contains_token(connection.base, connection.len, H2O_STRLIT("upgrade"), ',')) {
            conn->req.upgrade = upgrade;
        }
    } else if (conn->req.version >= 0x101) {
        /* defaults to keep-alive if >= HTTP/1.1 */
        conn->req.http1_is_persistent = 1;
    }
    /* disable keep-alive if shutdown is requested */
    if (conn->req.http1_is_persistent && conn->super.ctx->shutdown_requested)
        conn->req.http1_is_persistent = 0;

    return entity_header_index;
}

static void on_continue_sent(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection(conn, 1);
        return;
    }

    h2o_socket_read_start(sock, reqread_on_read);
    conn->_req_entity_reader->handle_incoming_entity(conn);
}

static int contains_crlf_only(const char *s, size_t len)
{
    for (; len != 0; ++s, --len)
        if (!(*s == '\r' || *s == '\n'))
            return 0;
    return 1;
}

static void send_bad_request_on_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1_conn_t *conn = sock->data;
    close_connection(conn, 1);
}

static void send_bad_request(struct st_h2o_http1_conn_t *conn)
{
    const static h2o_iovec_t resp = {H2O_STRLIT("HTTP/1.1 400 Bad Request\r\n"
                                                "Content-Type: text/plain; charset=utf-8\r\n"
                                                "Connection: close\r\n"
                                                "Content-Length: 11\r\n"
                                                "\r\n"
                                                "Bad Request")};

    assert(conn->req.version == 0 && "request has not been parsed successfully");
    h2o_socket_write(conn->sock, (h2o_iovec_t *)&resp, 1, send_bad_request_on_complete);
}

static void handle_incoming_request(struct st_h2o_http1_conn_t *conn)
{
    size_t inreqlen = conn->sock->input->size < H2O_MAX_REQLEN ? conn->sock->input->size : H2O_MAX_REQLEN;
    int reqlen, minor_version;
    struct phr_header headers[H2O_MAX_HEADERS];
    size_t num_headers = H2O_MAX_HEADERS;
    ssize_t entity_body_header_index;
    h2o_iovec_t expect;

    /* need to set request_begin_at here for keep-alive connection */
    if (conn->req.timestamps.request_begin_at.tv_sec == 0)
        conn->req.timestamps.request_begin_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);

    reqlen = phr_parse_request(conn->sock->input->bytes, inreqlen, (const char **)&conn->req.input.method.base,
                               &conn->req.input.method.len, (const char **)&conn->req.input.path.base, &conn->req.input.path.len,
                               &minor_version, headers, &num_headers, conn->_prevreqlen);
    conn->_prevreqlen = inreqlen;

    switch (reqlen) {
    default: // parse complete
        conn->_reqsize = reqlen;
        if ((entity_body_header_index = fixup_request(conn, headers, num_headers, minor_version, &expect)) != -1) {
            conn->req.timestamps.request_body_begin_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);
            if (expect.base != NULL) {
                if (!h2o_lcstris(expect.base, expect.len, H2O_STRLIT("100-continue"))) {
                    set_timeout(conn, NULL, NULL);
                    h2o_socket_read_stop(conn->sock);
                    h2o_send_error_417(&conn->req, "Expectation Failed", "unknown expectation",
                                       H2O_SEND_ERROR_HTTP1_CLOSE_CONNECTION);
                    return;
                }
                static const h2o_iovec_t res = {H2O_STRLIT("HTTP/1.1 100 Continue\r\n\r\n")};
                h2o_socket_write(conn->sock, (void *)&res, 1, on_continue_sent);
            }
            if (create_entity_reader(conn, headers + entity_body_header_index) != 0) {
                return;
            }
            if (expect.base != NULL) {
                /* processing of the incoming entity is postponed until the 100 response is sent */
                h2o_socket_read_stop(conn->sock);
                return;
            }
            conn->_req_entity_reader->handle_incoming_entity(conn);
        } else {
            set_timeout(conn, NULL, NULL);
            h2o_socket_read_stop(conn->sock);
            process_request(conn);
        }
        return;
    case -2: // incomplete
        if (inreqlen == H2O_MAX_REQLEN) {
            send_bad_request(conn);
        }
        return;
    case -1: // error
        /* upgrade to HTTP/2 if the request starts with: PRI * HTTP/2 */
        if (conn->super.ctx->globalconf->http1.upgrade_to_http2) {
            /* should check up to the first octet that phr_parse_request returns an error */
            static const h2o_iovec_t HTTP2_SIG = {H2O_STRLIT("PRI * HTTP/2")};
            if (conn->sock->input->size >= HTTP2_SIG.len && memcmp(conn->sock->input->bytes, HTTP2_SIG.base, HTTP2_SIG.len) == 0) {
                h2o_accept_ctx_t accept_ctx = {conn->super.ctx, conn->super.hosts};
                h2o_socket_t *sock = conn->sock;
                struct timeval connected_at = conn->super.connected_at;
                /* destruct the connection after detatching the socket */
                conn->sock = NULL;
                close_connection(conn, 1);
                /* and accept as http2 connection */
                h2o_http2_accept(&accept_ctx, sock, connected_at);
                return;
            }
        }
        if (inreqlen <= 4 && contains_crlf_only(conn->sock->input->bytes, inreqlen)) {
            close_connection(conn, 1);
        } else {
            send_bad_request(conn);
        }
        return;
    }
}

void reqread_on_read(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1_conn_t *conn = sock->data;

    if (err != NULL) {
        close_connection(conn, 1);
        return;
    }

    if (conn->_req_entity_reader == NULL)
        handle_incoming_request(conn);
    else
        conn->_req_entity_reader->handle_incoming_entity(conn);
}

static void reqread_on_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1_conn_t, _timeout_entry, entry);

    /* TODO log */
    conn->req.http1_is_persistent = 0;
    close_connection(conn, 1);
}

static inline void reqread_start(struct st_h2o_http1_conn_t *conn)
{
    set_timeout(conn, &conn->super.ctx->http1.req_timeout, reqread_on_timeout);
    h2o_socket_read_start(conn->sock, reqread_on_read);
    if (conn->sock->input->size != 0)
        handle_incoming_request(conn);
}

static void on_send_next_push(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1_conn_t *conn = sock->data;

    if (err != NULL)
        close_connection(conn, 1);
    else
        h2o_proceed_response(&conn->req);
}

static void on_send_next_pull(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1_conn_t *conn = sock->data;

    if (err != NULL)
        close_connection(conn, 1);
    else
        proceed_pull(conn, 0);
}

static void on_send_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1_conn_t *conn = sock->data;

    assert(conn->req._ostr_top == &conn->_ostr_final.super);

    conn->req.timestamps.response_end_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);

    if (!conn->req.http1_is_persistent) {
        /* TODO use lingering close */
        close_connection(conn, 1);
        return;
    }

    /* handle next request */
    init_request(conn, 1);
    h2o_buffer_consume(&conn->sock->input, conn->_reqsize);
    conn->_prevreqlen = 0;
    conn->_reqsize = 0;
    reqread_start(conn);
}

static void on_upgrade_complete(h2o_socket_t *socket, const char *err)
{
    struct st_h2o_http1_conn_t *conn = socket->data;
    h2o_http1_upgrade_cb cb = conn->upgrade.cb;
    void *data = conn->upgrade.data;
    h2o_socket_t *sock = NULL;
    size_t reqsize = 0;

    /* destruct the connection (after detaching the socket) */
    if (err == 0) {
        sock = conn->sock;
        reqsize = conn->_reqsize;
    }
    close_connection(conn, 0);

    cb(data, sock, reqsize);
}

static size_t flatten_headers_estimate_size(h2o_req_t *req, size_t server_name_and_connection_len)
{
    size_t len = sizeof("HTTP/1.1  \r\ndate: \r\nserver: \r\nconnection: \r\ncontent-length: \r\n\r\n") + 3 +
                 strlen(req->res.reason) + H2O_TIMESTR_RFC1123_LEN + server_name_and_connection_len +
                 sizeof(H2O_UINT64_LONGEST_STR) - 1 + sizeof("cache-control: private") - 1;
    const h2o_header_t *header, *end;

    for (header = req->res.headers.entries, end = header + req->res.headers.size; header != end; ++header)
        len += header->name->len + header->value.len + 4;

    return len;
}

static size_t flatten_headers(char *buf, h2o_req_t *req, const char *connection)
{
    h2o_context_t *ctx = req->conn->ctx;
    h2o_timestamp_t ts;
    char *dst = buf;

    h2o_get_timestamp(ctx, &req->pool, &ts);

    assert(req->res.status <= 999);

    /* send essential headers with the first chars uppercased for max. interoperability (#72) */
    if (req->res.content_length != SIZE_MAX) {
        dst += sprintf(dst, "HTTP/1.1 %d %s\r\nDate: %s\r\nConnection: %s\r\nContent-Length: %zu\r\n", req->res.status,
                       req->res.reason, ts.str->rfc1123, connection, req->res.content_length);
    } else {
        dst += sprintf(dst, "HTTP/1.1 %d %s\r\nDate: %s\r\nConnection: %s\r\n", req->res.status, req->res.reason, ts.str->rfc1123,
                       connection);
    }
    if (ctx->globalconf->server_name.len) {
        dst += sprintf(dst, "Server: %s\r\n", ctx->globalconf->server_name.base);
    }

    { /* flatten the normal headers */
        size_t i;
        for (i = 0; i != req->res.headers.size; ++i) {
            const h2o_header_t *header = req->res.headers.entries + i;
            if (header->name == &H2O_TOKEN_VARY->buf) {
                /* replace Vary with Cache-Control: private; see the following URLs to understand why this is necessary
                 * - http://blogs.msdn.com/b/ieinternals/archive/2009/06/17/vary-header-prevents-caching-in-ie.aspx
                 * - https://www.igvita.com/2013/05/01/deploying-webp-via-accept-content-negotiation/
                 */
                if (is_msie(req)) {
                    static h2o_header_t cache_control_private = {&H2O_TOKEN_CACHE_CONTROL->buf, {H2O_STRLIT("private")}};
                    header = &cache_control_private;
                }
            }
            memcpy(dst, header->name->base, header->name->len);
            dst += header->name->len;
            *dst++ = ':';
            *dst++ = ' ';
            memcpy(dst, header->value.base, header->value.len);
            dst += header->value.len;
            *dst++ = '\r';
            *dst++ = '\n';
        }
        *dst++ = '\r';
        *dst++ = '\n';
    }

    return dst - buf;
}

static void proceed_pull(struct st_h2o_http1_conn_t *conn, size_t nfilled)
{
    h2o_iovec_t buf = {conn->_ostr_final.pull.buf, nfilled};
    h2o_send_state_t send_state;

    if (buf.len < MAX_PULL_BUF_SZ) {
        h2o_iovec_t cbuf = {buf.base + buf.len, MAX_PULL_BUF_SZ - buf.len};
        send_state = h2o_pull(&conn->req, conn->_ostr_final.pull.cb, &cbuf);
        if (send_state == H2O_SEND_STATE_ERROR) {
            conn->req.http1_is_persistent = 0;
        }
        buf.len += cbuf.len;
    } else {
        send_state = H2O_SEND_STATE_IN_PROGRESS;
    }

    /* write */
    h2o_socket_write(conn->sock, &buf, 1, h2o_send_state_is_in_progress(send_state) ? on_send_next_pull : on_send_complete);
}

static void finalostream_start_pull(h2o_ostream_t *_self, h2o_ostream_pull_cb cb)
{
    struct st_h2o_http1_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1_conn_t, _ostr_final.super, _self);
    const char *connection = conn->req.http1_is_persistent ? "keep-alive" : "close";
    size_t bufsz, headers_len;

    assert(conn->req._ostr_top == &conn->_ostr_final.super);
    assert(!conn->_ostr_final.sent_headers);

    conn->req.timestamps.response_start_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);

    /* register the pull callback */
    conn->_ostr_final.pull.cb = cb;

    /* setup the buffer */
    bufsz = flatten_headers_estimate_size(&conn->req, conn->super.ctx->globalconf->server_name.len + strlen(connection));
    if (bufsz < MAX_PULL_BUF_SZ) {
        if (MAX_PULL_BUF_SZ - bufsz < conn->req.res.content_length) {
            bufsz = MAX_PULL_BUF_SZ;
        } else {
            bufsz += conn->req.res.content_length;
        }
    }
    conn->_ostr_final.pull.buf = h2o_mem_alloc_pool(&conn->req.pool, bufsz);

    /* fill-in the header */
    headers_len = flatten_headers(conn->_ostr_final.pull.buf, &conn->req, connection);
    conn->_ostr_final.sent_headers = 1;

    proceed_pull(conn, headers_len);
}

void finalostream_send(h2o_ostream_t *_self, h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t send_state)
{
    struct st_h2o_http1_finalostream_t *self = (void *)_self;
    struct st_h2o_http1_conn_t *conn = (struct st_h2o_http1_conn_t *)req->conn;
    h2o_iovec_t *bufs = alloca(sizeof(h2o_iovec_t) * (inbufcnt + 1));
    int bufcnt = 0;

    assert(self == &conn->_ostr_final);

    if (!self->sent_headers) {
        conn->req.timestamps.response_start_at = *h2o_get_timestamp(conn->super.ctx, NULL, NULL);
        /* build headers and send */
        const char *connection = req->http1_is_persistent ? "keep-alive" : "close";
        bufs[bufcnt].base = h2o_mem_alloc_pool(
            &req->pool, flatten_headers_estimate_size(req, conn->super.ctx->globalconf->server_name.len + strlen(connection)));
        bufs[bufcnt].len = flatten_headers(bufs[bufcnt].base, req, connection);
        ++bufcnt;
        self->sent_headers = 1;
    }
    memcpy(bufs + bufcnt, inbufs, sizeof(h2o_iovec_t) * inbufcnt);
    bufcnt += inbufcnt;

    if (send_state == H2O_SEND_STATE_ERROR) {
        conn->req.http1_is_persistent = 0;
    }

    if (bufcnt != 0) {
        h2o_socket_write(conn->sock, bufs, bufcnt,
                         h2o_send_state_is_in_progress(send_state) ? on_send_next_push : on_send_complete);
    } else {
        on_send_complete(conn->sock, 0);
    }
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http1_conn_t *conn = (void *)_conn;
    return h2o_socket_getsockname(conn->sock, sa);
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http1_conn_t *conn = (void *)_conn;
    return h2o_socket_getpeername(conn->sock, sa);
}

static h2o_socket_t *get_socket(h2o_conn_t *_conn)
{
    struct st_h2o_http1_conn_t *conn = (void *)_conn;
    return conn->sock;
}

#define DEFINE_TLS_LOGGER(name)                                                                                                    \
    static h2o_iovec_t log_##name(h2o_req_t *req)                                                                                  \
    {                                                                                                                              \
        struct st_h2o_http1_conn_t *conn = (void *)req->conn;                                                                      \
        return h2o_socket_log_ssl_##name(conn->sock, &req->pool);                                                                  \
    }

DEFINE_TLS_LOGGER(protocol_version)
DEFINE_TLS_LOGGER(session_reused)
DEFINE_TLS_LOGGER(cipher)
DEFINE_TLS_LOGGER(cipher_bits)

#undef DEFINE_TLS_LOGGER

static h2o_iovec_t log_request_index(h2o_req_t *req)
{
    struct st_h2o_http1_conn_t *conn = (void *)req->conn;
    char *s = h2o_mem_alloc_pool(&req->pool, sizeof(H2O_UINT64_LONGEST_STR));
    size_t len = sprintf(s, "%" PRIu64, conn->_req_index);
    return h2o_iovec_init(s, len);
}

static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    h2o_linklist_t *node;

    for (node = ctx->http1._conns.next; node != &ctx->http1._conns; node = node->next) {
        struct st_h2o_http1_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1_conn_t, _conns, node);
        int ret = cb(&conn->req, cbdata);
        if (ret != 0)
            return ret;
    }
    return 0;
}

void h2o_http1_accept(h2o_accept_ctx_t *ctx, h2o_socket_t *sock, struct timeval connected_at)
{
    static const h2o_conn_callbacks_t callbacks = {
        get_sockname, /* stringify address */
        get_peername, /* ditto */
        NULL,         /* push */
        get_socket,   /* get underlying socket */
        NULL,         /* get debug state */
        {{
            {log_protocol_version, log_session_reused, log_cipher, log_cipher_bits}, /* ssl */
            {log_request_index},                                                     /* http1 */
            {NULL}                                                                   /* http2 */
        }}};
    struct st_h2o_http1_conn_t *conn = (void *)h2o_create_connection(sizeof(*conn), ctx->ctx, ctx->hosts, connected_at, &callbacks);

    /* zero-fill all properties expect req */
    memset((char *)conn + sizeof(conn->super), 0, offsetof(struct st_h2o_http1_conn_t, req) - sizeof(conn->super));

    /* init properties that need to be non-zero */
    conn->super.ctx = ctx->ctx;
    conn->super.hosts = ctx->hosts;
    conn->super.connected_at = connected_at;
    conn->super.callbacks = &callbacks;
    conn->sock = sock;
    sock->data = conn;
    h2o_linklist_insert(&ctx->ctx->http1._conns, &conn->_conns);

    init_request(conn, 0);
    reqread_start(conn);
}

void h2o_http1_upgrade(h2o_req_t *req, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_http1_upgrade_cb on_complete, void *user_data)
{
    struct st_h2o_http1_conn_t *conn = (void *)req->conn;

    assert(req->version <= 0x200); /* TODO find a better way to assert instanceof(req->conn) == struct st_h2o_http1_conn_t */

    h2o_iovec_t *bufs = alloca(sizeof(h2o_iovec_t) * (inbufcnt + 1));

    conn->upgrade.data = user_data;
    conn->upgrade.cb = on_complete;

    bufs[0].base =
        h2o_mem_alloc_pool(&conn->req.pool, flatten_headers_estimate_size(&conn->req, conn->super.ctx->globalconf->server_name.len +
                                                                                          sizeof("upgrade") - 1));
    bufs[0].len = flatten_headers(bufs[0].base, &conn->req, "upgrade");
    memcpy(bufs + 1, inbufs, sizeof(h2o_iovec_t) * inbufcnt);

    h2o_socket_write(conn->sock, bufs, inbufcnt + 1, on_upgrade_complete);
}
