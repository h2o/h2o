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
#include "h2o/httpclient_internal_h1.h"
#include "h2o/token.h"

static void close_client(struct st_h2o_http1client_t *client)
{
    if (client->sock != NULL) {
        if (client->super.super.connpool != NULL && client->_do_keepalive) {
            /* we do not send pipelined requests, and thus can trash all the received input at the end of the request */
            h2o_buffer_consume(&client->sock->input, client->sock->input->size);
            h2o_socketpool_return(client->super.super.connpool->socketpool, client->sock);
        } else {
            h2o_socket_close(client->sock);
        }
    }
    if (h2o_timeout_is_linked(&client->_timeout))
        h2o_timeout_unlink(&client->_timeout);
    if (client->_body_buf != NULL)
        h2o_buffer_dispose(&client->_body_buf);
    if (client->_body_buf_in_flight != NULL)
        h2o_buffer_dispose(&client->_body_buf_in_flight);
    free(client);
}

static void on_body_error(struct st_h2o_http1client_t *client, const char *errstr)
{
    client->_do_keepalive = 0;
    client->super.cb.on_body(&client->super.super, errstr);
    close_client(client);
}

static void on_body_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, _timeout, entry);
    on_body_error(client, "I/O timeout");
}

static void do_update_window(h2o_httpclient_t *_client);
static void on_body_until_close(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        client->super.cb.on_body(&client->super.super, h2o_httpclient_error_is_eos);
        close_client(client);
        return;
    }

    if (sock->bytes_read != 0) {
        if (client->super.cb.on_body(&client->super.super, NULL) != 0) {
            close_client(client);
            return;
        }
        do_update_window(&client->super.super);
    }

    h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->io_timeout, &client->_timeout);
}

static void on_body_content_length(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

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
                client->sock->input->size -= sock->bytes_read - client->_body_decoder.content_length.bytesleft;
                client->_do_keepalive = 0;
            }
            client->_body_decoder.content_length.bytesleft = 0;
            errstr = h2o_httpclient_error_is_eos;
        } else {
            client->_body_decoder.content_length.bytesleft -= sock->bytes_read;
            errstr = NULL;
        }
        ret = client->super.cb.on_body(&client->super.super, errstr);
        if (errstr == h2o_httpclient_error_is_eos) {
            close_client(client);
            return;
        } else if (ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
        do_update_window(&client->super.super);
    }

    h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->io_timeout, &client->_timeout);
}

static void on_req_chunked(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;
    h2o_buffer_t *inbuf;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        if (err == h2o_socket_error_closed && !phr_decode_chunked_is_in_data(&client->_body_decoder.chunked.decoder)) {
            /*
             * if the peer closed after a full chunk, treat this
             * as if the transfer had complete, browsers appear to ignore
             * a missing 0\r\n chunk
             */
            client->_do_keepalive = 0;
            client->super.cb.on_body(&client->super.super, h2o_httpclient_error_is_eos);
            close_client(client);
        } else {
            on_body_error(client, "I/O error (body; chunked)");
        }
        return;
    }

    inbuf = client->sock->input;
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
            errstr = h2o_httpclient_error_is_eos;
            break;
        }
        inbuf->size -= sock->bytes_read - newsz;
        cb_ret = client->super.cb.on_body(&client->super.super, errstr);
        if (errstr != NULL) {
            close_client(client);
            return;
        } else if (cb_ret != 0) {
            client->_do_keepalive = 0;
            close_client(client);
            return;
        }
        do_update_window(&client->super.super);
    }

    h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->io_timeout, &client->_timeout);
}

static void on_error_before_head(struct st_h2o_http1client_t *client, const char *errstr)
{
    client->_do_keepalive = 0;
    client->super.cb.on_head(&client->super.super, errstr, 0, 0, h2o_iovec_init(NULL, 0), NULL, 0, 0, 0);
    close_client(client);
}

static void on_head(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;
    int minor_version, http_status, rlen, is_eos;
    const char *msg;
#define MAX_HEADERS 100
    h2o_header_t *headers;
    h2o_iovec_t *header_names;
    size_t msg_len, num_headers, i;
    h2o_socket_cb reader;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        on_error_before_head(client, "I/O error (head)");
        return;
    }

    headers = h2o_mem_alloc_pool(client->super.super.pool, *headers, MAX_HEADERS);
    header_names = h2o_mem_alloc_pool(client->super.super.pool, *header_names, MAX_HEADERS);

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
            return;
        case -2: /* incomplete */
            h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->io_timeout, &client->_timeout);
            return;
        }
        /* fill-in the headers */
        for (i = 0; i != num_headers; ++i) {
            const h2o_token_t *token;
            char *orig_name = h2o_strdup(client->super.super.pool, src_headers[i].name, src_headers[i].name_len).base;
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
        }

        if (!(100 <= http_status && http_status <= 199 && http_status != 101))
            break;

        if (client->super.super.informational_cb != NULL &&
            client->super.super.informational_cb(&client->super.super, minor_version, http_status, h2o_iovec_init(msg, msg_len), headers,
                                           num_headers) != 0) {
            close_client(client);
            return;
        }
        h2o_buffer_consume(&client->sock->input, rlen);
        if (client->sock->input->size == 0) {
            h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->io_timeout, &client->_timeout);
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
                reader = on_req_chunked;
            } else if (h2o_memis(headers[i].value.base, headers[i].value.len, H2O_STRLIT("identity"))) {
                /* continue */
            } else {
                on_error_before_head(client, "unexpected type of transfer-encoding");
                return;
            }
        } else if (headers[i].name == &H2O_TOKEN_CONTENT_LENGTH->buf) {
            if ((client->_body_decoder.content_length.bytesleft = h2o_strtosize(headers[i].value.base, headers[i].value.len)) ==
                SIZE_MAX) {
                on_error_before_head(client, "invalid content-length");
                return;
            }
            if (reader != on_req_chunked)
                reader = on_body_content_length;
        }
    }

    /* RFC 2616 4.4 */
    if (client->_method_is_head || http_status == 101 || http_status == 204 || http_status == 304) {
        is_eos = 1;
    } else {
        is_eos = 0;
        /* close the connection if impossible to determine the end of the response (RFC 7230 3.3.3) */
        if (reader == on_body_until_close)
            client->_do_keepalive = 0;
    }

    /* call the callback. sock may be stealed and stealed sock need rlen.*/
    client->super.cb.on_body = client->super.cb.on_head(&client->super.super, is_eos ? h2o_httpclient_error_is_eos : NULL, minor_version,
                                              http_status, h2o_iovec_init(msg, msg_len), headers, num_headers, rlen, 1);

    if (is_eos) {
        close_client(client);
        return;
    } else if (client->super.cb.on_body == NULL) {
        client->_do_keepalive = 0;
        close_client(client);
        return;
    }

    h2o_buffer_consume(&client->sock->input, rlen);
    client->sock->bytes_read = client->sock->input->size;

    client->_timeout.cb = on_body_timeout;
    h2o_socket_read_start(sock, reader);
    reader(client->sock, 0);

#undef MAX_HEADERS
}

static void on_head_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_send_request(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        on_error_before_head(client, "I/O error (send request)");
        return;
    }

    if (client->_is_chunked) {
        client->_is_chunked = 0;
        h2o_iovec_t last = h2o_iovec_init(H2O_STRLIT("0\r\n"));
        h2o_socket_write(client->sock, &last, 1, on_send_request);
        return;
    }

    h2o_socket_read_start(client->sock, on_head);
    client->_timeout.cb = on_head_timeout;
    h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->first_byte_timeout, &client->_timeout);
}

static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream);
static void on_req_body_done(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_t *client = sock->data;

    if (client->_body_buf_in_flight != NULL) {
        client->proceed_req(&client->super.super, client->_body_buf_in_flight->size, client->_body_buf_is_done);
        h2o_buffer_consume(&client->_body_buf_in_flight, client->_body_buf_in_flight->size);
    }

    if (err) {
        on_send_request(client->sock, err);
        return;
    }

    if (client->_body_buf != NULL && client->_body_buf->size != 0)
        do_write_req(&client->super.super, h2o_iovec_init(NULL, 0), client->_body_buf_is_done);
    else if (client->_body_buf_is_done)
        on_send_request(client->sock, NULL);
}

static void swap_buffers(h2o_buffer_t **a, h2o_buffer_t **b)
{
    h2o_buffer_t *swap;
    swap = *b;
    *b = *a;
    *a = swap;
}

size_t encode_chunk(struct st_h2o_http1client_t *client, h2o_iovec_t *bufs, h2o_iovec_t chunk)
{
    size_t i = 0;
    bufs[i].len = snprintf(client->_chunk_len_str, sizeof(client->_chunk_len_str), "%zx\r\n", chunk.len);
    bufs[i++].base = client->_chunk_len_str;

    if (chunk.base != NULL)
        bufs[i++] = h2o_iovec_init(chunk.base, chunk.len);
    bufs[i++] = h2o_iovec_init("\r\n", 2);

    return i;
}

static int do_write_req(h2o_httpclient_t *_client, h2o_iovec_t chunk, int is_end_stream)
{
    struct st_h2o_http1client_t *client = (struct st_h2o_http1client_t *)_client;

    client->_body_buf_is_done = is_end_stream;

    if (client->_body_buf == NULL)
        h2o_buffer_init(&client->_body_buf, &h2o_socket_buffer_prototype);

    if (chunk.len != 0) {
        if (h2o_buffer_append(&client->_body_buf, chunk.base, chunk.len) == 0)
            return -1;
    }

    if (client->sock->_cb.write != NULL)
        return 0;

    assert(client->_body_buf_in_flight == NULL || client->_body_buf_in_flight->size == 0);

    swap_buffers(&client->_body_buf, &client->_body_buf_in_flight);

    if (client->_body_buf_in_flight->size == 0) {
        /* return immediately if the chunk is empty */
        on_req_body_done(client->sock, NULL);
        return 0;
    }

    h2o_iovec_t iov = h2o_iovec_init(client->_body_buf_in_flight->bytes, client->_body_buf_in_flight->size);
    if (client->_is_chunked) {
        h2o_iovec_t bufs[3];
        size_t bufcnt = encode_chunk(client, bufs, iov);
        h2o_socket_write(client->sock, bufs, bufcnt, on_req_body_done);
    } else {
        h2o_socket_write(client->sock, &iov, 1, on_req_body_done);
    }
    return 0;
}

static void on_send_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static h2o_iovec_t build_request(struct st_h2o_http1client_t *client, h2o_iovec_t method, h2o_url_t url, h2o_iovec_t connection, h2o_header_t *headers, size_t num_headers)
{
    h2o_iovec_t buf;
    size_t offset = 0;

    buf.len = method.len + url.path.len + url.authority.len + 512;
    buf.base = h2o_mem_alloc_pool(client->super.super.pool, char, buf.len);

#define RESERVE(sz)                                                                                                                \
    do {                                                                                                                           \
        size_t required = offset + sz + 4 /* for "\r\n\r\n" */;                                                                    \
        if (required > buf.len) {                                                                                                  \
            do {                                                                                                                   \
                buf.len *= 2;                                                                                                      \
            } while (required > buf.len);                                                                                          \
            char *newp = h2o_mem_alloc_pool(client->super.super.pool, char, buf.len);                                                         \
            memcpy(newp, buf.base, offset);                                                                                        \
            buf.base = newp;                                                                                                       \
        }                                                                                                                          \
    } while (0)
#define APPEND(s, l)                                                                                                               \
    do {                                                                                                                           \
        memcpy(buf.base + offset, (s), (l));                                                                                       \
        offset += (l);                                                                                                             \
    } while (0)
#define APPEND_STRLIT(lit) APPEND((lit), sizeof(lit) - 1)
#define APPEND_HEADER(h) \
    do { \
        RESERVE((h)->name->len + (h)->value.len + 4); \
        APPEND((h)->orig_name ? (h)->orig_name : (h)->name->base, (h)->name->len); \
        buf.base[offset++] = ':'; \
        buf.base[offset++] = ' '; \
        APPEND((h)->value.base, (h)->value.len); \
        buf.base[offset++] = '\r'; \
        buf.base[offset++] = '\n'; \
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
    for (h = (h2o_header_t*)headers, h_end = h + num_headers; h != h_end; ++h)
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

    h2o_iovec_t method = h2o_iovec_init(NULL, 0);
    h2o_url_t url = {NULL};
    h2o_header_t *headers = NULL;
    size_t num_headers = 0;
    h2o_iovec_t body = h2o_iovec_init(NULL, 0);;

    client->super.cb.on_head = client->super.cb.on_connect(&client->super.super, NULL, &method, &url, (const h2o_header_t **)&headers, &num_headers, &body, &client->proceed_req, &props, client->_origin);

    if (client->super.cb.on_head == NULL) {
        close_client(client);
        return;
    }

    h2o_iovec_t reqbufs[3];
    size_t reqbufcnt = 0;
    if (props.proxy_protocol->base != NULL)
        reqbufs[reqbufcnt++] = *props.proxy_protocol;
    reqbufs[reqbufcnt++] = build_request(client, method, url, *props.connection_header, headers, num_headers);

    client->_is_chunked = *props.chunked;
    client->_method_is_head = h2o_memis(method.base, method.len, H2O_STRLIT("HEAD"));

    if (client->proceed_req != NULL) {
        if (body.base != NULL) {
            h2o_buffer_init(&client->_body_buf, &h2o_socket_buffer_prototype);
            if (h2o_buffer_append(&client->_body_buf, body.base, body.len) == 0) {
                on_send_request(client->sock, "Internal error");
                return;
            }
        }
        h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_req_body_done);
    } else {
        if (client->_is_chunked) {
            assert(body.base != NULL);
            reqbufcnt += encode_chunk(client, reqbufs + reqbufcnt, body);
        } else if (body.base != NULL) {
            reqbufs[reqbufcnt++] = body;
        }
        h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_send_request);
    }

    /* TODO no need to set the timeout if all data has been written into TCP sendbuf */
    client->_timeout.cb = on_send_timeout;
    h2o_timeout_link(client->super.super.ctx->loop, client->super.super.ctx->io_timeout, &client->_timeout);
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
    if ((*client->super.super.buf)->size >= client->super.super.ctx->max_buffer_size) {
        if (client->sock->_cb.read != NULL) {
            client->reader = client->sock->_cb.read;
            h2o_socket_read_stop(client->sock);
        }
    } else {
        if (client->sock->_cb.read == NULL) {
            h2o_socket_read_start(client->sock, client->reader);
        }
    }
}

static h2o_socket_t *do_steal_socket(h2o_httpclient_t *_client)
{
    struct st_h2o_http1client_t *client = (void *)_client;
    h2o_socket_t *sock = client->sock;
    h2o_socket_read_stop(sock);
    client->sock = NULL;
    return sock;
}

static void setup_client(struct st_h2o_http1client_t *client, h2o_socket_t *sock, h2o_url_t *origin)
{
    memset(&client->sock, 0, sizeof(*client) - offsetof(struct st_h2o_http1client_t, sock));
    client->super.super.cancel = do_cancel;
    client->super.super.steal_socket = do_steal_socket;
    client->super.super.update_window = do_update_window;
    client->super.super.write_req = do_write_req;
    client->super.super.buf = &sock->input;
    client->sock = sock;
    sock->data = client;
    client->_origin = origin;
}

void h2o_http1client_on_connect(struct st_h2o_httpclient_private_t *_client, h2o_socket_t *sock, h2o_url_t *origin)
{
    struct st_h2o_http1client_t *client = (void *)_client;
    setup_client(client, sock, origin);
    on_connection_ready(client);
}
