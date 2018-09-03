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
#include "h2o.h"

struct st_h2o_http1client_private_t {
    h2o_http1client_t super;
    union {
        h2o_http1client_connect_cb on_connect;
        h2o_http1client_head_cb on_head;
        h2o_http1client_body_cb on_body;
    } _cb;
    h2o_url_t *_origin;
    h2o_timer_t _timeout;
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
    h2o_http1client_proceed_req_cb proceed_req;
    char _chunk_len_str[(sizeof(H2O_UINT64_LONGEST_HEX_STR) - 1) + 2 + 1]; /* SIZE_MAX in hex + CRLF + '\0' */
    h2o_buffer_t *_body_buf;
    h2o_buffer_t *_body_buf_in_flight;
    unsigned _is_chunked : 1;
    unsigned _body_buf_is_done : 1;
};

static void close_client(struct st_h2o_http1client_private_t *client)
{
    if (client->super.sock != NULL) {
        if (client->super.sockpool.pool != NULL && client->_do_keepalive) {

            /* we do not send pipelined requests, and thus can trash all the received input at the end of the request */
            h2o_buffer_consume(&client->super.sock->input, client->super.sock->input->size);
            h2o_socketpool_return(client->super.sockpool.pool, client->super.sock);
        } else {
            h2o_socket_close(client->super.sock);
        }
    } else {
        if (client->super.sockpool.connect_req != NULL) {
            h2o_socketpool_cancel_connect(client->super.sockpool.connect_req);
            client->super.sockpool.connect_req = NULL;
        }
    }
    if (h2o_timer_is_linked(&client->_timeout))
        h2o_timer_unlink(&client->_timeout);
    if (client->_body_buf != NULL)
        h2o_buffer_dispose(&client->_body_buf);
    if (client->_body_buf_in_flight != NULL)
        h2o_buffer_dispose(&client->_body_buf_in_flight);
    free(client);
}

static void on_body_error(struct st_h2o_http1client_private_t *client, const char *errstr)
{
    client->_do_keepalive = 0;
    client->_cb.on_body(&client->super, errstr);
    close_client(client);
}

static void on_body_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_body_error(client, "I/O timeout");
}

static void on_body_until_close(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    h2o_timer_unlink(&client->_timeout);

    if (err != NULL) {
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
        client->_cb.on_body(&client->super, h2o_http1client_error_is_eos);
        close_client(client);
        return;
    }

    if (sock->bytes_read != 0) {
        if (client->_cb.on_body(&client->super, NULL) != 0) {
            close_client(client);
            return;
        }
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_body_content_length(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    h2o_timer_unlink(&client->_timeout);

    if (err != NULL) {
        on_body_error(client, "I/O error (body; content-length)");
        return;
    }

    if (sock->bytes_read != 0 || client->_body_decoder.content_length.bytesleft == 0) {
        const char *errstr;
        int ret;
        if (client->_body_decoder.content_length.bytesleft <= sock->bytes_read) {
            if (client->_body_decoder.content_length.bytesleft < sock->bytes_read) {
                /* remove the trailing garbage from buf, and disable keepalive */
                client->super.sock->input->size -= sock->bytes_read - client->_body_decoder.content_length.bytesleft;
                client->_do_keepalive = 0;
            }
            client->_body_decoder.content_length.bytesleft = 0;
            errstr = h2o_http1client_error_is_eos;
            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
        } else {
            client->_body_decoder.content_length.bytesleft -= sock->bytes_read;
            errstr = NULL;
        }
        ret = client->_cb.on_body(&client->super, errstr);
        if (errstr == h2o_http1client_error_is_eos) {
            close_client(client);
            return;
        } else if (ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_req_chunked(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;
    h2o_buffer_t *inbuf;

    h2o_timer_unlink(&client->_timeout);

    if (err != NULL) {
        if (err == h2o_socket_error_closed && !phr_decode_chunked_is_in_data(&client->_body_decoder.chunked.decoder)) {
            /*
             * if the peer closed after a full chunk, treat this
             * as if the transfer had complete, browsers appear to ignore
             * a missing 0\r\n chunk
             */
            client->_do_keepalive = 0;
            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
            client->_cb.on_body(&client->super, h2o_http1client_error_is_eos);
            close_client(client);
        } else {
            on_body_error(client, "I/O error (body; chunked)");
        }
        return;
    }

    inbuf = client->super.sock->input;
    if (sock->bytes_read != 0) {
        const char *errstr;
        int cb_ret;
        size_t newsz = sock->bytes_read;

        switch (phr_decode_chunked(&client->_body_decoder.chunked.decoder, inbuf->bytes + inbuf->size - newsz, &newsz)) {
        case -1: /* error */
            newsz = sock->bytes_read;
            client->_do_keepalive = 0;
            errstr = "failed to parse the response (chunked)";
            break;
        case -2: /* incomplete */
            errstr = NULL;
            break;
        default: /* complete, with garbage on tail; should disable keepalive */
            client->_do_keepalive = 0;
        /* fallthru */
        case 0: /* complete */
            errstr = h2o_http1client_error_is_eos;
            client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
            break;
        }
        inbuf->size -= sock->bytes_read - newsz;
        cb_ret = client->_cb.on_body(&client->super, errstr);
        if (errstr != NULL) {
            close_client(client);
            return;
        } else if (cb_ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
    }

    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_error_before_head(struct st_h2o_http1client_private_t *client, const char *errstr)
{
    client->_do_keepalive = 0;
    client->_cb.on_head(&client->super, errstr, 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0);
    close_client(client);
}

static void on_head(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;
    int minor_version, http_status, rlen, is_eos;
    const char *msg;
#define MAX_HEADERS 100
    h2o_header_t *headers;
    h2o_iovec_t *header_names;
    size_t msg_len, num_headers, i;
    h2o_socket_cb reader;
    h2o_mem_pool_t pool;

    h2o_timer_unlink(&client->_timeout);

    if (err != NULL) {
        on_error_before_head(client, "I/O error (head)");
        return;
    }

    h2o_mem_init_pool(&pool);

    headers = h2o_mem_alloc_pool(&pool, *headers, MAX_HEADERS);
    header_names = h2o_mem_alloc_pool(&pool, *header_names, MAX_HEADERS);

    /* continue parsing the responses until we see a final one */
    while (1) {
        /* parse response */
        struct phr_header src_headers[MAX_HEADERS];
        num_headers = MAX_HEADERS;
        rlen = phr_parse_response(sock->input->bytes, sock->input->size, &minor_version, &http_status, &msg, &msg_len, src_headers,
                                  &num_headers, 0);
        switch (rlen) {
        case -1: /* error */
            on_error_before_head(client, "failed to parse the response");
            goto Exit;
        case -2: /* incomplete */
            h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
            goto Exit;
        }
        /* fill-in the headers */
        for (i = 0; i != num_headers; ++i) {
            const h2o_token_t *token;
            char *orig_name = h2o_strdup(&pool, src_headers[i].name, src_headers[i].name_len).base;
            h2o_strtolower((char *)src_headers[i].name, src_headers[i].name_len);
            token = h2o_lookup_token(src_headers[i].name, src_headers[i].name_len);
            if (token != NULL) {
                headers[i].name = (h2o_iovec_t *)&token->buf;
                headers[i].flags = token->flags;
            } else {
                header_names[i] = h2o_iovec_init(src_headers[i].name, src_headers[i].name_len);
                headers[i].name = &header_names[i];
                headers[i].flags = (h2o_header_flags_t){0};
            }
            headers[i].value = h2o_iovec_init(src_headers[i].value, src_headers[i].value_len);
            headers[i].orig_name = orig_name;
        }

        if (!(100 <= http_status && http_status <= 199 && http_status != 101))
            break;

        if (client->super.informational_cb != NULL &&
            client->super.informational_cb(&client->super, minor_version, http_status, h2o_iovec_init(msg, msg_len), headers,
                                           num_headers) != 0) {
            close_client(client);
            goto Exit;
        }
        h2o_buffer_consume(&client->super.sock->input, rlen);
        if (client->super.sock->input->size == 0) {
            h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
            goto Exit;
        }
    }

    client->super.timings.response_start_at = h2o_gettimeofday(client->super.ctx->loop);

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
                reader = on_req_chunked;
            } else if (h2o_memis(headers[i].value.base, headers[i].value.len, H2O_STRLIT("identity"))) {
                /* continue */
            } else {
                on_error_before_head(client, "unexpected type of transfer-encoding");
                goto Exit;
            }
        } else if (headers[i].name == &H2O_TOKEN_CONTENT_LENGTH->buf) {
            if ((client->_body_decoder.content_length.bytesleft = h2o_strtosize(headers[i].value.base, headers[i].value.len)) ==
                SIZE_MAX) {
                on_error_before_head(client, "invalid content-length");
                goto Exit;
            }
            if (reader != on_req_chunked)
                reader = on_body_content_length;
        }
    }

    /* RFC 2616 4.4 */
    if (client->_method_is_head || http_status == 101 || http_status == 204 || http_status == 304) {
        is_eos = 1;
        client->super.timings.response_end_at = h2o_gettimeofday(client->super.ctx->loop);
    } else {
        is_eos = 0;
        /* close the connection if impossible to determine the end of the response (RFC 7230 3.3.3) */
        if (reader == on_body_until_close)
            client->_do_keepalive = 0;
    }

    /* call the callback. sock may be stealed and stealed sock need rlen.*/
    client->_cb.on_body = client->_cb.on_head(&client->super, is_eos ? h2o_http1client_error_is_eos : NULL, minor_version,
                                              http_status, h2o_iovec_init(msg, msg_len), headers, num_headers, rlen);

    if (is_eos) {
        close_client(client);
        goto Exit;
    } else if (client->_cb.on_body == NULL) {
        client->_do_keepalive = 0;
        close_client(client);
        goto Exit;
    }

    h2o_buffer_consume(&client->super.sock->input, rlen);
    client->super.sock->bytes_read = client->super.sock->input->size;

    client->_timeout.cb = on_body_timeout;
    h2o_socket_read_start(sock, reader);
    reader(client->super.sock, 0);

Exit:
    h2o_mem_clear_pool(&pool);
#undef MAX_HEADERS
}

static void on_head_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_send_request(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    h2o_timer_unlink(&client->_timeout);

    if (err != NULL) {
        on_error_before_head(client, "I/O error (send request)");
        return;
    }

    if (client->_is_chunked) {
        client->_is_chunked = 0;
        h2o_iovec_t last = h2o_iovec_init(H2O_STRLIT("0\r\n"));
        h2o_socket_write(client->super.sock, &last, 1, on_send_request);
        return;
    }

    client->super.timings.request_end_at = h2o_gettimeofday(client->super.ctx->loop);

    h2o_socket_read_start(client->super.sock, on_head);
    client->_timeout.cb = on_head_timeout;
    h2o_timer_link(client->super.ctx->loop, client->super.ctx->first_byte_timeout, &client->_timeout);
}

static void on_req_body_done(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    if (client->_body_buf_in_flight != NULL) {
        client->proceed_req(&client->super, client->_body_buf_in_flight->size, client->_body_buf_is_done);
        h2o_buffer_consume(&client->_body_buf_in_flight, client->_body_buf_in_flight->size);
    }

    if (err) {
        on_send_request(client->super.sock, err);
        return;
    }

    if (client->_body_buf != NULL && client->_body_buf->size != 0)
        h2o_http1client_write_req(client->super.sock, h2o_iovec_init(NULL, 0), client->_body_buf_is_done);
    else if (client->_body_buf_is_done)
        on_send_request(client->super.sock, NULL);
}

static void swap_buffers(h2o_buffer_t **a, h2o_buffer_t **b)
{
    h2o_buffer_t *swap;
    swap = *b;
    *b = *a;
    *a = swap;
}

void write_chunk_to_socket(struct st_h2o_http1client_private_t *client, h2o_iovec_t headers, h2o_iovec_t chunk, h2o_socket_cb cb)
{
    int i = 0;
    h2o_iovec_t chunk_and_reqbufs[4];

    if (headers.base != NULL)
        chunk_and_reqbufs[i++] = headers;

    chunk_and_reqbufs[i].len = snprintf(client->_chunk_len_str, sizeof(client->_chunk_len_str), "%zx\r\n", chunk.len);
    chunk_and_reqbufs[i++].base = client->_chunk_len_str;

    if (chunk.base != NULL)
        chunk_and_reqbufs[i++] = h2o_iovec_init(chunk.base, chunk.len);
    chunk_and_reqbufs[i++] = h2o_iovec_init("\r\n", 2);

    h2o_socket_write(client->super.sock, chunk_and_reqbufs, i, cb);
}

int h2o_http1client_write_req(void *priv, h2o_iovec_t chunk, int is_end_stream)
{
    h2o_socket_t *sock = priv;
    struct st_h2o_http1client_private_t *client = sock->data;

    client->_body_buf_is_done = is_end_stream;

    if (client->_body_buf == NULL)
        h2o_buffer_init(&client->_body_buf, &h2o_socket_buffer_prototype);

    if (chunk.len != 0) {
        if (h2o_buffer_append(&client->_body_buf, chunk.base, chunk.len) == 0)
            return -1;
    }

    if (client->super.sock->_cb.write != NULL)
        return 0;

    assert(client->_body_buf_in_flight == NULL || client->_body_buf_in_flight->size == 0);

    swap_buffers(&client->_body_buf, &client->_body_buf_in_flight);

    if (client->_body_buf_in_flight->size == 0) {
        /* return immediately if the chunk is empty */
        on_req_body_done(client->super.sock, NULL);
        return 0;
    }

    if (client->_is_chunked) {
        if (is_end_stream && client->_body_buf_in_flight->size == 0) {
            on_send_request(sock, NULL);
            return 0;
        }
        write_chunk_to_socket(client, h2o_iovec_init(NULL, 0),
                              h2o_iovec_init(client->_body_buf_in_flight->bytes, client->_body_buf_in_flight->size),
                              on_req_body_done);
    } else {
        h2o_iovec_t iov = h2o_iovec_init(client->_body_buf_in_flight->bytes, client->_body_buf_in_flight->size);

        h2o_socket_write(client->super.sock, &iov, 1, on_req_body_done);
    }
    return 0;
}

static void on_send_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_connect_error(struct st_h2o_http1client_private_t *client, const char *errstr)
{
    assert(errstr != NULL);
    client->_cb.on_connect(&client->super, errstr, NULL, NULL, NULL, NULL, NULL, NULL, client->_origin);
    close_client(client);
}

static void on_connection_ready(struct st_h2o_http1client_private_t *client)
{
    h2o_iovec_t *reqbufs;
    size_t reqbufcnt;
    h2o_iovec_t cur_body = h2o_iovec_init(NULL, 0);
    int is_chunked = 0;

    client->_cb.on_head = client->_cb.on_connect(&client->super, NULL, &reqbufs, &reqbufcnt, &client->_method_is_head,
                                                 &client->proceed_req, &cur_body, &is_chunked, client->_origin);
    if (client->_cb.on_head == NULL) {
        close_client(client);
        return;
    }
    client->_is_chunked = is_chunked;
    if (client->proceed_req != NULL) {
        if (cur_body.len != 0) {
            h2o_buffer_init(&client->_body_buf, &h2o_socket_buffer_prototype);
            if (h2o_buffer_append(&client->_body_buf, cur_body.base, cur_body.len) == 0) {
                on_send_request(client->super.sock, "Internal error");
                return;
            }
        }
        h2o_socket_write(client->super.sock, reqbufs, reqbufcnt, on_req_body_done);
    } else {
        if (client->_is_chunked) {
            assert(reqbufcnt == 2);
            write_chunk_to_socket(client, reqbufs[0], reqbufs[1], on_send_request);
        } else {
            h2o_socket_write(client->super.sock, reqbufs, reqbufcnt, on_send_request);
        }
    }

    /* TODO no need to set the timeout if all data has been written into TCP sendbuf */
    client->_timeout.cb = on_send_timeout;
    h2o_timer_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);

    client->super.timings.request_begin_at = h2o_gettimeofday(client->super.ctx->loop);
}

static void on_pool_connect(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *origin)
{
    struct st_h2o_http1client_private_t *client = data;

    client->super.sockpool.connect_req = NULL;

    if (sock == NULL) {
        assert(errstr != NULL);
        h2o_timer_unlink(&client->_timeout);
        on_connect_error(client, errstr);
        return;
    }

    client->super.sock = sock;
    sock->data = client;
    client->_origin = origin;
    h2o_timer_unlink(&client->_timeout);

    on_connection_ready(client);
}

static void on_connect_timeout(h2o_timer_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_connect_error(client, "connection timeout");
}

static struct st_h2o_http1client_private_t *create_client(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx,
                                                          h2o_http1client_connect_cb cb)
{
    struct st_h2o_http1client_private_t *client = h2o_mem_alloc(sizeof(*client));

    *client = (struct st_h2o_http1client_private_t){{ctx}};
    client->super.data = data;
    client->_cb.on_connect = cb;
    /* caller needs to setup _cb, timeout.cb, sock, and sock->data */

    if (_client != NULL)
        *_client = &client->super;

    return client;
}

const char *const h2o_http1client_error_is_eos = "end of stream";

void h2o_http1client_connect(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx, h2o_socketpool_t *socketpool,
                             h2o_url_t *target, h2o_http1client_connect_cb cb)
{
    assert(socketpool != NULL);
    struct st_h2o_http1client_private_t *client;

    /* setup */
    client = create_client(_client, data, ctx, cb);
    client->_timeout.cb = on_connect_timeout;
    h2o_timer_link(ctx->loop, ctx->connect_timeout, &client->_timeout);
    client->super.sockpool.pool = socketpool;

    client->super.timings.start_at = h2o_gettimeofday(client->super.ctx->loop);
    h2o_socketpool_connect(&client->super.sockpool.connect_req, socketpool, target, ctx->loop, ctx->getaddr_receiver,
                           on_pool_connect, client);
}

void h2o_http1client_cancel(h2o_http1client_t *_client)
{
    struct st_h2o_http1client_private_t *client = (void *)_client;
    client->_do_keepalive = 0;
    close_client(client);
}

h2o_socket_t *h2o_http1client_steal_socket(h2o_http1client_t *_client)
{
    struct st_h2o_http1client_private_t *client = (void *)_client;
    h2o_socket_t *sock = client->super.sock;
    h2o_socket_read_stop(sock);
    client->super.sock = NULL;
    return sock;
}

void h2o_http1client_body_read_stop(h2o_http1client_t *_client)
{
    struct st_h2o_http1client_private_t *client = (void *)_client;
    client->reader = client->super.sock->_cb.read;
    h2o_socket_read_stop(client->super.sock);
}

void h2o_http1client_body_read_resume(h2o_http1client_t *_client)
{
    struct st_h2o_http1client_private_t *client = (void *)_client;
    h2o_socket_read_start(client->super.sock, client->reader);
}
