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
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "picohttpparser.h"
#include "h2o/httpclient.h"
#include "h2o/token.h"

#if !H2O_USE_LIBUV && defined(__linux__)
#define USE_PIPE_READER 1
#else
#define USE_PIPE_READER 0
#endif

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
    /**
     * buffer used to hold chunk headers of a request body; the size is SIZE_MAX in hex + CRLF + '\0'
     */
    char _chunk_len_str[(sizeof(H2O_UINT64_LONGEST_HEX_STR) - 1) + 2 + 1];
    /**
     * buffer used to retain request body that is inflight
     */
    struct {
        h2o_buffer_t *buf;
        int is_end_stream;
    } body_buf;
    /**
     * `on_body_piped` is non-NULL iff used
     */
    h2o_httpclient_pipe_reader_t pipe_reader;
    /**
     * maintain the number of bytes being already processed on the associated socket
     */
    uint64_t _socket_bytes_processed;
    unsigned _is_chunked : 1;
    unsigned _seen_at_least_one_chunk : 1;
    unsigned _delay_free : 1;
    unsigned _app_prefers_pipe_reader : 1;
    unsigned _use_expect : 1;
};

static void on_body_to_pipe(h2o_socket_t *_sock, const char *err);

static void req_body_send(struct st_h2o_http1client_t *client);
static void update_read_state(struct st_h2o_http1client_t *client);

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
    if (client->body_buf.buf != NULL)
        h2o_buffer_dispose(&client->body_buf.buf);
    if (!client->_delay_free)
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

static h2o_httpclient_body_cb call_on_head(struct st_h2o_http1client_t *client, const char *errstr, h2o_httpclient_on_head_t *args)
{
    assert(!client->_delay_free);
    client->_delay_free = 1;
    h2o_httpclient_body_cb cb = client->super._cb.on_head(&client->super, errstr, args);
    client->_delay_free = 0;
    return cb;
}

static int call_on_body(struct st_h2o_http1client_t *client, const char *errstr)
{
    assert(!client->_delay_free);
    client->_delay_free = 1;
    int ret = (client->reader == on_body_to_pipe ? client->pipe_reader.on_body_piped : client->super._cb.on_body)(&client->super,
                                                                                                                  errstr, NULL, 0);
    client->_delay_free = 0;
    return ret;
}

static void call_proceed_req(struct st_h2o_http1client_t *client, const char *errstr)
{
    assert(!client->_delay_free);
    client->_delay_free = 1;
    client->proceed_req(&client->super, errstr);
    client->_delay_free = 0;
}

static void on_error(struct st_h2o_http1client_t *client, const char *errstr)
{
    switch (client->state.res) {
    case STREAM_STATE_HEAD:
        call_on_head(client, errstr, NULL);
        break;
    case STREAM_STATE_BODY:
        call_on_body(client, errstr);
        break;
    case STREAM_STATE_CLOSED:
        if (client->proceed_req != NULL)
            call_proceed_req(client, errstr);
        break;
    }
    close_client(client);
}

static void on_body_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, super._timeout, entry);
    on_error(client, h2o_httpclient_error_io_timeout);
}

static void on_body_until_close(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        client->state.res = STREAM_STATE_CLOSED;
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
        call_on_body(client, h2o_httpclient_error_is_eos);
        close_response(client);
        return;
    }
    uint64_t size = sock->bytes_read - client->_socket_bytes_processed;
    client->_socket_bytes_processed = sock->bytes_read;

    client->super.bytes_read.body += size;
    client->super.bytes_read.total += size;

    if (size != 0) {
        if (call_on_body(client, NULL) != 0) {
            close_client(client);
            return;
        }
        update_read_state(client);
    }
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
        ret = call_on_body(client, client->state.res == STREAM_STATE_CLOSED ? h2o_httpclient_error_is_eos : NULL);
        if (client->state.res == STREAM_STATE_CLOSED) {
            close_response(client);
            return;
        } else if (ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
    }

#if USE_PIPE_READER
    if (client->pipe_reader.on_body_piped != NULL) {
        h2o_socket_dont_read(client->sock, 1);
        client->reader = on_body_to_pipe;
    }
#endif
    update_read_state(client);
}

void on_body_to_pipe(h2o_socket_t *_sock, const char *err)
{
#if USE_PIPE_READER
    struct st_h2o_http1client_t *client = _sock->data;

    h2o_timer_unlink(&client->super._timeout);
    h2o_socket_read_stop(client->sock);

    if (err != NULL) {
        on_error(client, h2o_httpclient_error_io);
        return;
    }

    ssize_t bytes_read;
    while ((bytes_read = splice(h2o_socket_get_fd(client->sock), NULL, client->pipe_reader.fd, NULL,
                                client->_body_decoder.content_length.bytesleft, SPLICE_F_NONBLOCK)) == -1 &&
           errno == EINTR)
        ;
    if (bytes_read == -1 && errno == EAGAIN) {
        update_read_state(client);
        return;
    }
    if (bytes_read <= 0) {
        on_error(client, h2o_httpclient_error_io);
        return;
    }

    client->_socket_bytes_processed += bytes_read;
    client->sock->bytes_read += bytes_read;
    client->super.bytes_read.body += bytes_read;
    client->super.bytes_read.total += bytes_read;

    client->_body_decoder.content_length.bytesleft -= bytes_read;
    if (client->_body_decoder.content_length.bytesleft == 0) {
        client->state.res = STREAM_STATE_CLOSED;
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
        h2o_socket_dont_read(client->sock, 0);
    }

    int ret = call_on_body(client, client->state.res == STREAM_STATE_CLOSED ? h2o_httpclient_error_is_eos : NULL);

    if (client->state.res == STREAM_STATE_CLOSED) {
        close_response(client);
    } else if (ret != 0) {
        client->_do_keepalive = 0;
        close_client(client);
    }
#else
    h2o_fatal("%s cannot be called", __FUNCTION__);
#endif
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
            call_on_body(client, h2o_httpclient_error_is_eos);
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
        cb_ret = call_on_body(client, errstr);
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
        update_read_state(client);
    }
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

    /* revert max read size to 1MB now that we have received the first chunk, presumably carrying all the response headers */
#if USE_PIPE_READER
    if (client->_app_prefers_pipe_reader)
        h2o_evloop_socket_set_max_read_size(client->sock, h2o_evloop_socket_max_read_size);
#endif

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

        if (http_status == 101) {
            if (client->_use_expect) {
                /* expect: 100-continue is incompatible CONNECT or upgrade (when trying to establish a tunnel */
                on_error(client, h2o_httpclient_error_unexpected_101);
                return;
            }
            break;
        } else if (http_status == 100 || http_status >= 200) {
            /* When request body has been withheld and a 100 or a final response has been received, start sending the request body,
             * see: https://github.com/h2o/h2o/pull/3316#discussion_r1456859634. */
            if (client->_use_expect) {
                client->_use_expect = 0;
                req_body_send(client);
            }
            if (http_status >= 200)
                break;
        }
        assert(http_status <= 199);
        if (client->super.informational_cb != NULL &&
            client->super.informational_cb(&client->super, version, http_status, h2o_iovec_init(msg, msg_len), headers,
                                           num_headers) != 0) {
            close_client(client);
            return;
        }

        h2o_buffer_consume(&client->sock->input, rlen);
        if (client->sock->input->size == 0) {
            if (!h2o_timer_is_linked(&client->super._timeout)) {
                h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
            }
            return;
        }
    }

    /* recognize hop-by-hop response headers */
    reader = on_body_until_close;
    if (!h2o_httpclient__tunnel_is_ready(&client->super, http_status, version)) {
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
    }

    client->state.res = STREAM_STATE_BODY;
    client->super.timings.response_start_at = h2o_gettimeofday(client->super.ctx->loop);

    /* RFC 2616 4.4 */
    if (client->_method_is_head || http_status == 204 || http_status == 304) {
        client->state.res = STREAM_STATE_CLOSED;
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
    } else {
        /* close the connection if impossible to determine the end of the response (RFC 7230 3.3.3) */
        if (reader == on_body_until_close)
            client->_do_keepalive = 0;
    }

    h2o_httpclient_on_head_t on_head = {
        .version = version,
        .status = http_status,
        .msg = h2o_iovec_init(msg, msg_len),
        .headers = headers,
        .num_headers = num_headers,
        .header_requires_dup = 1,
    };
#if USE_PIPE_READER
    /* If there is no less than 64KB of data to be read from the socket, offer the application the opportunity to use pipe for
     * transferring the content zero-copy. As switching to pipe involves the cost of creating a pipe (and disposing it when the
     * request is complete), we adopt this margin of 64KB, which offers clear improvement (5%) on 9th-gen Intel Core. */
    if (client->_app_prefers_pipe_reader && reader == on_body_content_length &&
        client->sock->input->size + 65536 <= client->_body_decoder.content_length.bytesleft)
        on_head.pipe_reader = &client->pipe_reader;
#endif

    /* call the callback */
    client->super._cb.on_body =
        call_on_head(client, client->state.res == STREAM_STATE_CLOSED ? h2o_httpclient_error_is_eos : NULL, &on_head);

    if (client->state.res == STREAM_STATE_CLOSED) {
        close_response(client);
        return;
    } else if (client->super._cb.on_body == NULL) {
        client->_do_keepalive = 0;
        close_client(client);
        return;
    }

    h2o_buffer_consume(&sock->input, rlen);
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

    client->state.req = STREAM_STATE_CLOSED;
    client->super.timings.request_end_at = h2o_gettimeofday(client->super.ctx->loop);

    if (client->super.upgrade_to != NULL) {
        /* TODO use shutdown(2) to signal the peer that our send side has been closed, but continue reading on the receive side. */
        on_error(client, client->state.res < STREAM_STATE_BODY ? h2o_httpclient_error_io : h2o_httpclient_error_is_eos);
    } else {
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
}

static void on_header_sent_wait_100(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timer_unlink(&client->super._timeout);

    if (err != NULL) {
        on_error(client, h2o_httpclient_error_io);
        return;
    }

    if (client->state.res == STREAM_STATE_HEAD) {
        client->super._timeout.cb = on_head_first_byte_timeout;
        h2o_timer_link(client->super.ctx->loop, client->super.ctx->first_byte_timeout, &client->super._timeout);
    }
}

static void req_body_send_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_buffer_consume(&client->body_buf.buf, client->body_buf.buf->size);

    if (err != NULL) {
        on_whole_request_sent(client->sock, err);
        return;
    }

    int is_end_stream = client->body_buf.is_end_stream;

    if (client->proceed_req != NULL) {
        call_proceed_req(client, NULL);
    }

    if (is_end_stream)
        on_whole_request_sent(client->sock, NULL);
}

/**
 * Encodes data. `bufs` must have at least 4 elements of space.
 */
static size_t req_body_send_prepare(struct st_h2o_http1client_t *client, h2o_iovec_t *bufs, size_t *bytes)
{
    size_t bufcnt = 0;
    *bytes = 0;

    if (client->_is_chunked) {
        if (client->body_buf.buf->size != 0) {
            /* build chunk header */
            bufs[bufcnt].base = client->_chunk_len_str;
            bufs[bufcnt].len =
                snprintf(client->_chunk_len_str, sizeof(client->_chunk_len_str), "%zx\r\n", client->body_buf.buf->size);
            *bytes += bufs[bufcnt].len;
            ++bufcnt;
            /* append chunk body */
            bufs[bufcnt++] = h2o_iovec_init(client->body_buf.buf->bytes, client->body_buf.buf->size);
            *bytes += client->body_buf.buf->size;
            /* append CRLF */
            bufs[bufcnt++] = h2o_iovec_init("\r\n", 2);
            *bytes += 2;
        }
        if (client->body_buf.is_end_stream) {
            static const h2o_iovec_t terminator = {H2O_STRLIT("0\r\n\r\n")};
            bufs[bufcnt++] = terminator;
            *bytes += terminator.len;
        }
    } else if (client->body_buf.buf->size != 0) {
        bufs[bufcnt++] = h2o_iovec_init(client->body_buf.buf->bytes, client->body_buf.buf->size);
        *bytes += client->body_buf.buf->size;
    }

    return bufcnt;
}

static void req_body_send(struct st_h2o_http1client_t *client)
{
    h2o_iovec_t bufs[4];
    size_t bytes, bufcnt = req_body_send_prepare(client, bufs, &bytes);

    h2o_timer_unlink(&client->super._timeout);

    h2o_socket_write(client->sock, bufs, bufcnt, req_body_send_complete);
    client->super.bytes_written.body += bytes;
    client->super.bytes_written.total += bytes;

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
}

static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_h2o_http1client_t *client = (struct st_h2o_http1client_t *)_client;

    assert(chunk.len != 0 || is_end_stream);
    assert(!h2o_socket_is_writing(client->sock));
    assert(client->body_buf.buf->size == 0);

    /* store given content to buffer */
    if (chunk.len != 0) {
        if (!h2o_buffer_try_append(&client->body_buf.buf, chunk.base, chunk.len))
            return -1;
    }
    client->body_buf.is_end_stream = is_end_stream;

    /* check if the connection has to be closed for correct framing */
    if (client->state.res == STREAM_STATE_CLOSED)
        client->_do_keepalive = 0;

    req_body_send(client);

    return 0;
}

static void on_send_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, super._timeout, entry);
    on_error(client, h2o_httpclient_error_io_timeout);
}

static h2o_iovec_t build_request(struct st_h2o_http1client_t *client, h2o_iovec_t method, const h2o_url_t *url,
                                 h2o_iovec_t connection, const h2o_header_t *headers, size_t num_headers)
{
    h2o_iovec_t buf;
    size_t offset = 0;

    buf.len = method.len + url->path.len + url->authority.len + 512;
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
    if (client->super.upgrade_to == h2o_httpclient_upgrade_to_connect) {
        if (h2o_memis(method.base, method.len, H2O_STRLIT("CONNECT-UDP"))) {
            APPEND_STRLIT("masque://");
            APPEND(url->authority.base, url->authority.len);
            APPEND_STRLIT("/");
        } else {
            APPEND(url->authority.base, url->authority.len);
        }
    } else {
        APPEND(url->path.base, url->path.len);
    }
    APPEND_STRLIT(" HTTP/1.1\r\nhost: ");
    APPEND(url->authority.base, url->authority.len);
    buf.base[offset++] = '\r';
    buf.base[offset++] = '\n';
    assert(offset <= buf.len);

    /* append supplied connection header, or "connection: upgrade" and upgrade header when request an upgrade */
    if (client->super.upgrade_to != NULL && client->super.upgrade_to != h2o_httpclient_upgrade_to_connect) {
        h2o_header_t c = {&H2O_TOKEN_CONNECTION->buf, NULL, h2o_iovec_init(H2O_STRLIT("upgrade"))},
                     u = {&H2O_TOKEN_UPGRADE->buf, NULL,
                          h2o_iovec_init(client->super.upgrade_to, strlen(client->super.upgrade_to))};
        APPEND_HEADER(&c);
        APPEND_HEADER(&u);
    } else if (connection.base != NULL) {
        h2o_header_t h = {&H2O_TOKEN_CONNECTION->buf, NULL, connection};
        APPEND_HEADER(&h);
    }

    if (client->_use_expect) {
        h2o_header_t h = {&H2O_TOKEN_EXPECT->buf, NULL, h2o_iovec_init(H2O_STRLIT("100-continue"))};
        APPEND_HEADER(&h);
    }

    if (num_headers != 0) {
        for (const h2o_header_t *h = headers, *h_end = h + num_headers; h != h_end; ++h)
            APPEND_HEADER(h);
    }

    APPEND_STRLIT("\r\n");

    /* set the length */
    assert(offset <= buf.len);
    buf.len = offset;

    return buf;

#undef RESERVE
#undef APPEND
#undef APPEND_STRLIT
}

static void start_request(struct st_h2o_http1client_t *client, h2o_iovec_t method, const h2o_url_t *url,
                          const h2o_header_t *headers, size_t num_headers, h2o_iovec_t body,
                          const h2o_httpclient_properties_t *props)
{
    h2o_iovec_t reqbufs[6]; /* 6 should be the maximum possible elements used */
    size_t reqbufcnt = 0;
    if (props->proxy_protocol->base != NULL)
        reqbufs[reqbufcnt++] = *props->proxy_protocol;

    if (props->use_expect && (client->proceed_req != NULL || body.len != 0) && client->super.upgrade_to == NULL)
        client->_use_expect = 1; /* this must be set before calling build_request */

    h2o_iovec_t header = build_request(client, method, url, *props->connection_header, headers, num_headers);
    reqbufs[reqbufcnt++] = header;
    client->super.bytes_written.header = header.len;

    client->_is_chunked = *props->chunked;
    client->_method_is_head = h2o_memis(method.base, method.len, H2O_STRLIT("HEAD"));

    assert(PTLS_ELEMENTSOF(reqbufs) - reqbufcnt >= 4); /* req_body_send_prepare could write to 4 additional elements */
    if (client->proceed_req != NULL) {
        h2o_buffer_init(&client->body_buf.buf, &h2o_socket_buffer_prototype);
        if (body.len != 0 && !h2o_buffer_try_append(&client->body_buf.buf, body.base, body.len)) {
            on_whole_request_sent(client->sock, h2o_httpclient_error_internal);
            return;
        }
        if (client->_use_expect) {
            h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_header_sent_wait_100);
        } else {
            size_t bytes_written;
            reqbufcnt += req_body_send_prepare(client, reqbufs + reqbufcnt, &bytes_written);
            client->super.bytes_written.body = bytes_written;
            h2o_socket_write(client->sock, reqbufs, reqbufcnt, req_body_send_complete);
        }
    } else if (body.len != 0) {
        assert(!client->_is_chunked);
        if (client->_use_expect) {
            h2o_buffer_init(&client->body_buf.buf, &h2o_socket_buffer_prototype);
            client->body_buf.is_end_stream = 1;
            if (!h2o_buffer_try_append(&client->body_buf.buf, body.base, body.len)) {
                on_whole_request_sent(client->sock, h2o_httpclient_error_internal);
                return;
            }
            h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_header_sent_wait_100);
        } else {
            reqbufs[reqbufcnt++] = body;
            client->super.bytes_written.body = body.len;
            h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_whole_request_sent);
        }
    } else {
        assert(!client->_is_chunked);
        h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_whole_request_sent);
    }
    client->super.bytes_written.total = client->sock->bytes_written;

    /* Even all data highly likely has been written into TCP sendbuf, it is our practice to assume the socket write operation is
     * asynchronous and link the timer. */
    client->super._timeout.cb = on_send_timeout;
    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);

    client->state.req = STREAM_STATE_BODY;
    client->super.timings.request_begin_at = h2o_gettimeofday(client->super.ctx->loop);

    /* If there's possibility of using a pipe for forwarding the content, reduce maximum read size before fetching headers. The
     * intent here is to not do a full-sized read of 1MB. 16KB has been chosen so that all HTTP response headers would be available,
     * and that an almost full-sized HTTP/2 frame / TLS record can be generated for the first chunk of data that we pass through
     * memory. */
#if USE_PIPE_READER
    if (client->_app_prefers_pipe_reader && h2o_evloop_socket_max_read_size > 16384)
        h2o_evloop_socket_set_max_read_size(client->sock, 16384);
#endif

    h2o_socket_read_start(client->sock, on_head);
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
    client->_app_prefers_pipe_reader = props.prefer_pipe_reader;

    if (client->super._cb.on_head == NULL) {
        close_client(client);
        return;
    }

    start_request(client, method, &url, headers, num_headers, body, &props);
}

static void do_cancel(h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (struct st_h2o_http1client_t *)_client;
    client->_do_keepalive = 0;
    close_client(client);
}

void update_read_state(struct st_h2o_http1client_t *client)
{
    /* If pipe used, `client->reader` would have switched to `on_body_pipe` by the time this function is called for the first time.
     */
    assert((client->pipe_reader.on_body_piped != NULL) == (client->reader == on_body_to_pipe));

    if (client->reader == on_body_to_pipe) {
        /* When pipe is being used, resume read when consumption is notified from user. `h2o_socket_read_start` is invoked without
         * checking if we are already reading; this is because we want to make sure that the read callback replaced to the current
         * one. */
        h2o_socket_read_start(client->sock, client->reader);
    } else {
        /* When buffer is used, start / stop reading based on the amount of data being buffered. */
        if ((*client->super.buf)->size >= client->super.ctx->max_buffer_size) {
            if (h2o_socket_is_reading(client->sock)) {
                client->reader = client->sock->_cb.read;
                h2o_socket_read_stop(client->sock);
            }
        } else {
            if (!h2o_socket_is_reading(client->sock))
                h2o_socket_read_start(client->sock, client->reader);
        }
    }

    /* arm or unarm i/o timeout depending on if we are reading */
    if (h2o_socket_is_reading(client->sock)) {
        if (h2o_timer_is_linked(&client->super._timeout))
            h2o_timer_unlink(&client->super._timeout);
        h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->super._timeout);
    } else {
        if (h2o_timer_is_linked(&client->super._timeout))
            h2o_timer_unlink(&client->super._timeout);
    }
}

static void do_update_window(struct st_h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (void *)_client;

    /* When we are splicing to pipe, read synchronously. For prioritization logic to work correctly, it is important to provide
     * additional data synchronously in response to the invocation of `h2o_proceed_response`. When memory buffers are used,
     * lib/core/proxy.c uses a double buffering to prepare next chunk of data while a chunk of data is being fed to the HTTP
     * handlers via `h2o_sendvec`. But when using splice, the pipe is the only one buffer available. */
    if (client->reader == on_body_to_pipe) {
        on_body_to_pipe(client->sock, NULL);
        return;
    }

    update_read_state(client);
}

static void do_get_conn_properties(h2o_httpclient_t *_client, h2o_httpclient_conn_properties_t *properties)
{
    struct st_h2o_http1client_t *client = (void *)_client;
    h2o_httpclient_set_conn_properties_of_socket(client->sock, properties);
}

static void setup_client(struct st_h2o_http1client_t *client, h2o_socket_t *sock, h2o_url_t *origin)
{
    memset(&client->sock, 0, sizeof(*client) - offsetof(struct st_h2o_http1client_t, sock));
    client->super.cancel = do_cancel;
    client->super.get_conn_properties = do_get_conn_properties;
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
