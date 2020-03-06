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
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "picohttpparser.h"
#include "h2o/httpclient.h"
#include "h2o/token.h"

enum enum_h2o_http1client_stream_state {
    STREAM_STATE_HEAD,
    STREAM_STATE_BODY,
    STREAM_STATE_CLOSED,
};

struct st_h2o_http1client_t {
    h2o_httpclient_t super;
    h2o_socket_t *sock;
    struct {
        enum enum_h2o_http1client_stream_state req;
        enum enum_h2o_http1client_stream_state res;
    } state;
    h2o_url_t *_origin;
    int _method_is_head;
    int _do_keepalive;
    int bytes_to_consume;
    union {
        struct {
            size_t bytesleft;
        } content_length;
        struct {
            struct phr_chunked_decoder decoder;
            size_t bytes_decoded_in_buf;
        } chunked;
    } _body_decoder;
    h2o_socket_cb reader;
    h2o_httpclient_proceed_req_cb proceed_req;
    char _chunk_len_str[(sizeof(H2O_UINT64_LONGEST_HEX_STR) - 1) + 2 + 1]; /* SIZE_MAX in hex + CRLF + '\0' */
    h2o_buffer_t *_body_buf;
    h2o_buffer_t *_body_buf_in_flight;
    /**
     * maintain the number of bytes being already processed on the associated socket
     */
    uint64_t _socket_bytes_processed;
    unsigned _is_chunked : 1;
    unsigned _body_buf_is_done : 1;
    unsigned _seen_at_least_one_chunk : 1;
};

static void close_client(struct st_h2o_http1client_t *client)
{
    if (client->sock != NULL) {
        if (client->super.connpool != NULL && client->_do_keepalive && client->super.connpool->socketpool->timeout > 0) {
            /* we do not send pipelined requests, and thus can trash all the received input at the end of the request */
            h2o_buffer_consume(&client->sock->input, client->sock->input->size);
            h2o_socketpool_return(client->super.connpool->socketpool, client->sock);
        } else {
            h2o_socket_close(client->sock);
        }
    }
    if (h2o_timer_is_linked(&client->super._timeout))
        h2o_timer_unlink(&client->super._timeout);
    if (client->_body_buf != NULL)
        h2o_buffer_dispose(&client->_body_buf);
    if (client->_body_buf_in_flight != NULL)
        h2o_buffer_dispose(&client->_body_buf_in_flight);
    free(client);
}

static void close_response(struct st_h2o_http1client_t *client)
{
    assert(client->state.res == STREAM_STATE_CLOSED);
    if (client->state.req == STREAM_STATE_CLOSED) {
        close_client(client);
    } else {
        h2o_socket_read_stop(client->sock);
    }
}

static void on_error(struct st_h2o_http1client_t *client, const char *errstr)
{
    client->_do_keepalive = 0;
    switch (client->state.res) {
    case STREAM_STATE_HEAD:
        client->super._cb.on_head(&client->super, errstr, 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0);
        break;
    case STREAM_STATE_BODY:
        client->super._cb.on_body(&client->super, errstr);
        break;
    case STREAM_STATE_CLOSED:
        if (client->proceed_req != NULL) {
            client->proceed_req(&client->super, 0, H2O_SEND_STATE_ERROR);
        }
        break;
    }
    close_client(client);
}

static void on_body_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, super._timeout, entry);
    on_error(client, h2o_httpclient_error_io_timeout);
}

static void do_update_window(h2o_httpclient_t *_client);
static void on_body_until_close(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        client->state.res = STREAM_STATE_CLOSED;
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
        client->super._cb.on_body(&client->super, h2o_httpclient_error_is_eos);
        close_response(client);
        return;
    }
    uint64_t size = sock->bytes_read - client->_socket_bytes_processed;
    client->_socket_bytes_processed = sock->bytes_read;

    client->super.bytes_read.body += size;
    client->super.bytes_read.total += size;

    if (size != 0) {
        if (client->super._cb.on_body(&client->super, NULL) != 0) {
            close_client(client);
            return;
        }
        do_update_window(&client->super);
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
}

static void on_body_content_length(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        on_error(client, h2o_httpclient_error_io);
        return;
    }
    uint64_t size = sock->bytes_read - client->_socket_bytes_processed;
    client->_socket_bytes_processed = sock->bytes_read;

    client->super.bytes_read.body += size;
    client->super.bytes_read.total += size;

    if (size != 0 || client->_body_decoder.content_length.bytesleft == 0) {
        int ret;
        if (client->_body_decoder.content_length.bytesleft <= size) {
            if (client->_body_decoder.content_length.bytesleft < size) {
                /* remove the trailing garbage from buf, and disable keepalive */
                client->sock->input->size -= size - client->_body_decoder.content_length.bytesleft;
                client->_do_keepalive = 0;
            }
            client->_body_decoder.content_length.bytesleft = 0;
            client->state.res = STREAM_STATE_CLOSED;
            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
        } else {
            client->_body_decoder.content_length.bytesleft -= size;
        }
        ret = client->super._cb.on_body(&client->super,
                                        client->state.res == STREAM_STATE_CLOSED ? h2o_httpclient_error_is_eos : NULL);
        if (client->state.res == STREAM_STATE_CLOSED) {
            close_response(client);
            return;
        } else if (ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
        do_update_window(&client->super);
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
}

static void on_body_chunked(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;
    h2o_buffer_t *inbuf;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        if (err == h2o_socket_error_closed && !phr_decode_chunked_is_in_data(&client->_body_decoder.chunked.decoder) &&
            client->_seen_at_least_one_chunk) {
            /*
             * if the peer closed after a full chunk, treat this
             * as if the transfer had complete, browsers appear to ignore
             * a missing 0\r\n chunk
             */
            client->_do_keepalive = 0;
            client->state.res = STREAM_STATE_CLOSED;
            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
            client->super._cb.on_body(&client->super, h2o_httpclient_error_is_eos);
            close_response(client);
        } else {
            on_error(client, h2o_httpclient_error_io);
        }
        return;
    }
    uint64_t size = sock->bytes_read - client->_socket_bytes_processed;
    client->_socket_bytes_processed = sock->bytes_read;

    client->super.bytes_read.body += size;
    client->super.bytes_read.total += size;

    inbuf = client->sock->input;
    if (size != 0) {
        const char *errstr;
        int cb_ret;
        size_t newsz = size;

        switch (phr_decode_chunked(&client->_body_decoder.chunked.decoder, inbuf->bytes + inbuf->size - newsz, &newsz)) {
        case -1: /* error */
            newsz = size;
            client->_do_keepalive = 0;
            errstr = h2o_httpclient_error_http1_parse_failed;
            break;
        case -2: /* incomplete */
            errstr = NULL;
            break;
        default: /* complete, with garbage on tail; should disable keepalive */
            client->_do_keepalive = 0;
        /* fallthru */
        case 0: /* complete */
            client->state.res = STREAM_STATE_CLOSED;
            errstr = h2o_httpclient_error_is_eos;
            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
            break;
        }
        inbuf->size -= size - newsz;
        if (inbuf->size > 0)
            client->_seen_at_least_one_chunk = 1;
        cb_ret = client->super._cb.on_body(&client->super, errstr);
        if (client->state.res == STREAM_STATE_CLOSED) {
            close_response(client);
            return;
        } else if (errstr != NULL) {
            close_client(client);
            return;
        } else if (cb_ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
        do_update_window(&client->super);
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
}

static void on_head_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, super._timeout, entry);
    on_error(client, h2o_httpclient_error_io_timeout);
}

static void on_head(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;
    int minor_version, version, http_status, rlen;
    const char *msg;
#define MAX_HEADERS 100
    h2o_header_t *headers;
    h2o_iovec_t *header_names;
    size_t msg_len, num_headers, i;
    h2o_socket_cb reader;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        on_error(client, h2o_httpclient_error_io);
        return;
    }

    client->super._timeout.cb = on_head_timeout;

    headers = h2o_mem_alloc_pool(client->super.pool, *headers, MAX_HEADERS);
    header_names = h2o_mem_alloc_pool(client->super.pool, *header_names, MAX_HEADERS);

    /* continue parsing the responses until we see a final one */
    while (1) {
        /* parse response */
        struct phr_header src_headers[MAX_HEADERS];
        num_headers = MAX_HEADERS;
        rlen = phr_parse_response(sock->input->bytes, sock->input->size, &minor_version, &http_status, &msg, &msg_len, src_headers,
                                  &num_headers, 0);
        switch (rlen) {
        case -1: /* error */
            on_error(client, h2o_httpclient_error_http1_parse_failed);
            return;
        case -2: /* incomplete */
            h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
            return;
        }

        client->super.bytes_read.header += rlen;
        client->super.bytes_read.total += rlen;

        version = 0x100 | (minor_version != 0);

        /* fill-in the headers */
        for (i = 0; i != num_headers; ++i) {
            if (src_headers[i].name_len == 0) {
                /* reject multiline header */
                on_error(client, h2o_httpclient_error_http1_line_folding);
                return;
            }
            const h2o_token_t *token;
            char *orig_name = h2o_strdup(client->super.pool, src_headers[i].name, src_headers[i].name_len).base;
            h2o_strtolower((char *)src_headers[i].name, src_headers[i].name_len);
            token = h2o_lookup_token(src_headers[i].name, src_headers[i].name_len);
            if (token != NULL) {
                headers[i].name = (h2o_iovec_t *)&token->buf;
            } else {
                header_names[i] = h2o_iovec_init(src_headers[i].name, src_headers[i].name_len);
                headers[i].name = &header_names[i];
            }
            headers[i].value = h2o_iovec_init(src_headers[i].value, src_headers[i].value_len);
            headers[i].orig_name = orig_name;
            headers[i].flags = (h2o_header_flags_t){0};
        }

        if (!(100 <= http_status && http_status <= 199 && http_status != 101))
            break;

        if (client->super.informational_cb != NULL &&
            client->super.informational_cb(&client->super, version, http_status, h2o_iovec_init(msg, msg_len), headers,
                                           num_headers) != 0) {
            close_client(client);
            return;
        }
        h2o_buffer_consume(&client->sock->input, rlen);
        if (client->sock->input->size == 0) {
            h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
            return;
        }
    }

    /* parse the headers */
    reader = on_body_until_close;
    client->_do_keepalive = minor_version >= 1;
    for (i = 0; i != num_headers; ++i) {
        if (headers[i].name == &H2O_TOKEN_CONNECTION->buf) {
            if (h2o_contains_token(headers[i].value.base, headers[i].value.len, H2O_STRLIT("keep-alive"), ',')) {
                client->_do_keepalive = 1;
            } else {
                client->_do_keepalive = 0;
            }
        } else if (headers[i].name == &H2O_TOKEN_TRANSFER_ENCODING->buf) {
            if (h2o_memis(headers[i].value.base, headers[i].value.len, H2O_STRLIT("chunked"))) {
                /* precond: _body_decoder.chunked is zero-filled */
                client->_body_decoder.chunked.decoder.consume_trailer = 1;
                reader = on_body_chunked;
            } else if (h2o_memis(headers[i].value.base, headers[i].value.len, H2O_STRLIT("identity"))) {
                /* continue */
            } else {
                on_error(client, h2o_httpclient_error_http1_unexpected_transfer_encoding);
                return;
            }
        } else if (headers[i].name == &H2O_TOKEN_CONTENT_LENGTH->buf) {
            if ((client->_body_decoder.content_length.bytesleft = h2o_strtosize(headers[i].value.base, headers[i].value.len)) ==
                SIZE_MAX) {
                on_error(client, h2o_httpclient_error_invalid_content_length);
                return;
            }
            if (reader != on_body_chunked)
                reader = on_body_content_length;
        }
    }

    client->state.res = STREAM_STATE_BODY;
    client->super.timings.response_start_at = h2o_gettimeofday(client->super.ctx->loop);

    /* RFC 2616 4.4 */
    if (client->_method_is_head || http_status == 101 || http_status == 204 || http_status == 304) {
        client->state.res = STREAM_STATE_CLOSED;
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
    } else {
        /* close the connection if impossible to determine the end of the response (RFC 7230 3.3.3) */
        if (reader == on_body_until_close)
            client->_do_keepalive = 0;
    }

    /* call the callback. sock may be stealed */
    client->bytes_to_consume = rlen;
    client->super._cb.on_body =
        client->super._cb.on_head(&client->super, client->state.res == STREAM_STATE_CLOSED ? h2o_httpclient_error_is_eos : NULL,
                                  version, http_status, h2o_iovec_init(msg, msg_len), headers, num_headers, 1);

    if (client->state.res == STREAM_STATE_CLOSED) {
        close_response(client);
        return;
    } else if (client->super._cb.on_body == NULL) {
        client->_do_keepalive = 0;
        close_client(client);
        return;
    }

    h2o_buffer_consume(&sock->input, client->bytes_to_consume);
    client->bytes_to_consume = 0;
    client->_socket_bytes_processed = client->sock->bytes_read - client->sock->input->size;

    client->super._timeout.cb = on_body_timeout;
    h2o_socket_read_start(sock, reader);
    reader(client->sock, 0);

#undef MAX_HEADERS
}

static void on_head_first_byte_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, super._timeout, entry);
    on_error(client, h2o_httpclient_error_first_byte_timeout);
}

static void on_whole_request_sent(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        on_error(client, h2o_httpclient_error_io);
        return;
    }

    if (client->_is_chunked) {
        client->_is_chunked = 0;
        h2o_iovec_t last = h2o_iovec_init(H2O_STRLIT("0\r\n\r\n"));
        client->super.bytes_written.body += last.len;
        client->super.bytes_written.total += last.len;
        h2o_socket_write(client->sock, &last, 1, on_whole_request_sent);
        return;
    }

    client->state.req = STREAM_STATE_CLOSED;
    client->super.timings.request_end_at = h2o_gettimeofday(client->super.ctx->loop);

    switch (client->state.res) {
    case STREAM_STATE_HEAD:
        client->super._timeout.cb = on_head_first_byte_timeout;
        h2o_timer_link(client->super.ctx->loop, client->super.ctx->first_byte_timeout, &client->super._timeout);
        break;
    case STREAM_STATE_BODY:
        break;
    case STREAM_STATE_CLOSED:
        close_client(client);
        break;
    }
}

static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream);
static void on_req_body_done(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    if (client->_body_buf_in_flight != NULL) {
        if (err == NULL) {
            h2o_send_state_t send_state = client->_body_buf_is_done ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS;
            client->proceed_req(&client->super, client->_body_buf_in_flight->size, send_state);
        }
        h2o_buffer_consume(&client->_body_buf_in_flight, client->_body_buf_in_flight->size);
    }

    if (err) {
        on_whole_request_sent(client->sock, err);
        return;
    }

    if (client->_body_buf != NULL && client->_body_buf->size != 0) {
        do_write_req(&client->super, h2o_iovec_init(NULL, 0), client->_body_buf_is_done);
    } else if (client->_body_buf_is_done) {
        on_whole_request_sent(client->sock, NULL);
    }
}

static void swap_buffers(h2o_buffer_t **a, h2o_buffer_t **b)
{
    h2o_buffer_t *swap;
    swap = *b;
    *b = *a;
    *a = swap;
}

size_t encode_chunk(struct st_h2o_http1client_t *client, h2o_iovec_t *bufs, h2o_iovec_t chunk, size_t *bytes)
{
    *bytes = 0;

    size_t i = 0;
    bufs[i].len = snprintf(client->_chunk_len_str, sizeof(client->_chunk_len_str), "%zx\r\n", chunk.len);
    *bytes += bufs[i].len;
    bufs[i++].base = client->_chunk_len_str;

    if (chunk.base != NULL) {
        bufs[i++] = h2o_iovec_init(chunk.base, chunk.len);
        *bytes += chunk.len;
    }
    bufs[i++] = h2o_iovec_init("\r\n", 2);
    *bytes += 2;

    return i;
}

static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_h2o_http1client_t *client = (struct st_h2o_http1client_t *)_client;

    client->_body_buf_is_done = is_end_stream;

    if (client->_body_buf == NULL)
        h2o_buffer_init(&client->_body_buf, &h2o_socket_buffer_prototype);

    if (chunk.len != 0) {
        if (!h2o_buffer_try_append(&client->_body_buf, chunk.base, chunk.len))
            return -1;
    }

    if (client->state.res == STREAM_STATE_CLOSED) {
        /* have to close the connection for correct framing */
        client->_do_keepalive = 0;
    }

    if (h2o_socket_is_writing(client->sock))
        return 0;

    assert(client->_body_buf_in_flight == NULL || client->_body_buf_in_flight->size == 0);

    swap_buffers(&client->_body_buf, &client->_body_buf_in_flight);

    if (client->_body_buf_in_flight->size == 0) {
        /* return immediately if the chunk is empty */
        on_req_body_done(client->sock, NULL);
        return 0;
    }

    h2o_timer_unlink(&client->super._timeout);

    h2o_iovec_t iov = h2o_iovec_init(client->_body_buf_in_flight->bytes, client->_body_buf_in_flight->size);
    if (client->_is_chunked) {
        h2o_iovec_t bufs[3];
        size_t bytes;
        size_t bufcnt = encode_chunk(client, bufs, iov, &bytes);
        client->super.bytes_written.body += bytes;
        client->super.bytes_written.total += bytes;
        h2o_socket_write(client->sock, bufs, bufcnt, on_req_body_done);
    } else {
        client->super.bytes_written.body += iov.len;
        client->super.bytes_written.total += iov.len;
        h2o_socket_write(client->sock, &iov, 1, on_req_body_done);
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
    return 0;

}

static void on_send_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, super._timeout, entry);
    on_error(client, h2o_httpclient_error_io_timeout);
}

static h2o_iovec_t build_request(struct st_h2o_http1client_t *client, h2o_iovec_t method, h2o_url_t url, h2o_iovec_t connection,
                                 h2o_header_t *headers, size_t num_headers)
{
    h2o_iovec_t buf;
    size_t offset = 0;

    buf.len = method.len + url.path.len + url.authority.len + 512;
    buf.base = h2o_mem_alloc_pool(client->super.pool, char, buf.len);

#define RESERVE(sz)                                                                                                                \
    do {                                                                                                                           \
        size_t required = offset + sz + 4 /* for "\r\n\r\n" */;                                                                    \
        if (required > buf.len) {                                                                                                  \
            do {                                                                                                                   \
                buf.len *= 2;                                                                                                      \
            } while (required > buf.len);                                                                                          \
            char *newp = h2o_mem_alloc_pool(client->super.pool, char, buf.len);                                                    \
            memcpy(newp, buf.base, offset);                                                                                        \
            buf.base = newp;                                                                                                       \
        }                                                                                                                          \
    } while (0)
#define APPEND(s, l)                                                                                                               \
    do {                                                                                                                           \
        h2o_memcpy(buf.base + offset, (s), (l));                                                                                   \
        offset += (l);                                                                                                             \
    } while (0)
#define APPEND_STRLIT(lit) APPEND((lit), sizeof(lit) - 1)
#define APPEND_HEADER(h)                                                                                                           \
    do {                                                                                                                           \
        RESERVE((h)->name->len + (h)->value.len + 4);                                                                              \
        APPEND((h)->orig_name ? (h)->orig_name : (h)->name->base, (h)->name->len);                                                 \
        buf.base[offset++] = ':';                                                                                                  \
        buf.base[offset++] = ' ';                                                                                                  \
        APPEND((h)->value.base, (h)->value.len);                                                                                   \
        buf.base[offset++] = '\r';                                                                                                 \
        buf.base[offset++] = '\n';                                                                                                 \
    } while (0)

    APPEND(method.base, method.len);
    buf.base[offset++] = ' ';
    APPEND(url.path.base, url.path.len);
    APPEND_STRLIT(" HTTP/1.1\r\nhost: ");
    APPEND(url.authority.base, url.authority.len);
    buf.base[offset++] = '\r';
    buf.base[offset++] = '\n';
    assert(offset <= buf.len);

    if (connection.base != NULL) {
        h2o_header_t h = (h2o_header_t){&H2O_TOKEN_CONNECTION->buf, NULL, connection};
        APPEND_HEADER(&h);
    }

    h2o_header_t *h, *h_end;
    for (h = (h2o_header_t *)headers, h_end = h + num_headers; h != h_end; ++h)
        APPEND_HEADER(h);

    APPEND_STRLIT("\r\n");

    /* set the length */
    assert(offset <= buf.len);
    buf.len = offset;

    return buf;

#undef RESERVE
#undef APPEND
#undef APPEND_STRLIT
}

static void on_connection_ready(struct st_h2o_http1client_t *client)
{
    h2o_iovec_t proxy_protocol = h2o_iovec_init(NULL, 0);
    int chunked = 0;
    h2o_iovec_t connection_header = h2o_iovec_init(NULL, 0);
    h2o_httpclient_properties_t props = {
        &proxy_protocol,
        &chunked,
        &connection_header,
    };
    h2o_iovec_t method;
    h2o_url_t url;
    h2o_header_t *headers;
    size_t num_headers;
    h2o_iovec_t body;

    client->super._cb.on_head = client->super._cb.on_connect(&client->super, NULL, &method, &url, (const h2o_header_t **)&headers,
                                                             &num_headers, &body, &client->proceed_req, &props, client->_origin);

    if (client->super._cb.on_head == NULL) {
        close_client(client);
        return;
    }

    h2o_iovec_t reqbufs[3];
    size_t reqbufcnt = 0;
    if (props.proxy_protocol->base != NULL)
        reqbufs[reqbufcnt++] = *props.proxy_protocol;
    h2o_iovec_t header = build_request(client, method, url, *props.connection_header, headers, num_headers);
    reqbufs[reqbufcnt++] = header;
    client->super.bytes_written.header = header.len;

    client->_is_chunked = *props.chunked;
    client->_method_is_head = h2o_memis(method.base, method.len, H2O_STRLIT("HEAD"));

    if (client->proceed_req != NULL) {
        if (body.base != NULL) {
            h2o_buffer_init(&client->_body_buf, &h2o_socket_buffer_prototype);
            if (!h2o_buffer_try_append(&client->_body_buf, body.base, body.len)) {
                on_whole_request_sent(client->sock, h2o_httpclient_error_internal);
                return;
            }
        }
        h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_req_body_done);
    } else {
        if (client->_is_chunked) {
            assert(body.base != NULL);
            size_t bytes;
            reqbufcnt += encode_chunk(client, reqbufs + reqbufcnt, body, &bytes);
            client->super.bytes_written.body = bytes;
        } else if (body.base != NULL) {
            reqbufs[reqbufcnt++] = body;
            client->super.bytes_written.body = body.len;
        }
        h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_whole_request_sent);
    }
    client->super.bytes_written.total = client->sock->bytes_written;

    /* TODO no need to set the timeout if all data has been written into TCP sendbuf */
    client->super._timeout.cb = on_send_timeout;
    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);

    client->state.req = STREAM_STATE_BODY;
    client->super.timings.request_begin_at = h2o_gettimeofday(client->super.ctx->loop);

    h2o_socket_read_start(client->sock, on_head);
}

static void do_cancel(h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (struct st_h2o_http1client_t *)_client;
    client->_do_keepalive = 0;
    close_client(client);
}

static void do_update_window(h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (void *)_client;
    if ((*client->super.buf)->size >= client->super.ctx->max_buffer_size) {
        if (h2o_socket_is_reading(client->sock)) {
            client->reader = client->sock->_cb.read;
            h2o_socket_read_stop(client->sock);
        }
    } else {
        if (!h2o_socket_is_reading(client->sock)) {
            h2o_socket_read_start(client->sock, client->reader);
        }
    }
}

static h2o_socket_t *do_steal_socket(h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (void *)_client;
    h2o_socket_t *sock = client->sock;
    h2o_socket_read_stop(sock);
    h2o_buffer_consume(&sock->input, client->bytes_to_consume);
    client->bytes_to_consume = 0;
    client->sock = NULL;
    return sock;
}

static h2o_socket_t *do_get_socket(h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (void *)_client;
    return client->sock;
}

static void setup_client(struct st_h2o_http1client_t *client, h2o_socket_t *sock, h2o_url_t *origin)
{
    memset(&client->sock, 0, sizeof(*client) - offsetof(struct st_h2o_http1client_t, sock));
    client->super.cancel = do_cancel;
    client->super.steal_socket = do_steal_socket;
    client->super.get_socket = do_get_socket;
    client->super.update_window = do_update_window;
    client->super.write_req = do_write_req;
    client->super.buf = &sock->input;
    client->sock = sock;
    sock->data = client;
    client->_origin = origin;
}

void h2o_httpclient__h1_on_connect(h2o_httpclient_t *_client, h2o_socket_t *sock, h2o_url_t *origin)
{
    struct st_h2o_http1client_t *client = (void *)_client;

    assert(!h2o_timer_is_linked(&client->super._timeout));

    setup_client(client, sock, origin);
    on_connection_ready(client);
}

const size_t h2o_httpclient__h1_size = sizeof(struct st_h2o_http1client_t);
