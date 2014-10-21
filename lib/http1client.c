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
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o/string_.h"
#include "h2o/http1client.h"

static void close_client(h2o_http1client_t *client)
{
    if (client->sock != NULL)
        h2o_socket_close(client->sock);
    if (h2o_timeout_is_linked(&client->_timeout))
        h2o_timeout_unlink(&client->_timeout);
    free(client);
}

static void on_body_error(h2o_http1client_t *client, const char *errstr)
{
    client->_cb.on_body(client, errstr, NULL, 0);
    close_client(client);
}

static void on_body_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_t, _timeout, entry);
    on_body_error(client, "I/O timeout");
}

static void on_body_until_close(h2o_socket_t *sock, int status)
{
    h2o_http1client_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (status != 0) {
        client->_cb.on_body(client, h2o_http1client_error_is_eos, NULL, 0);
        close_client(client);
        return;
    }

    if (client->sock->input->size != 0) {
        h2o_buf_t buf = { client->sock->input->bytes, client->sock->input->size };
        if (client->_cb.on_body(client, NULL, &buf, 1) != 0) {
            close_client(client);
            return;
        }
        h2o_consume_input_buffer(&client->sock->input, client->sock->input->size);
    }

    h2o_timeout_link(client->ctx->loop, client->ctx->io_timeout, &client->_timeout);
}

static void on_body_content_length(h2o_socket_t *sock, int status)
{
    h2o_http1client_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (status != 0) {
        on_body_error(client, "I/O error");
        return;
    }

    if (client->sock->input->size != 0) {
        h2o_buf_t buf = {
            client->sock->input->bytes,
            client->sock->input->size < client->_body_bytesleft ? client->sock->input->size : client->_body_bytesleft
        };
        int is_eos;
        client->_body_bytesleft -= client->sock->input->size;
        is_eos = client->_body_bytesleft == 0;
        if (client->_cb.on_body(client, is_eos ? h2o_http1client_error_is_eos : NULL, &buf, 1) != 0 || is_eos) {
            close_client(client);
            return;
        }
        h2o_consume_input_buffer(&client->sock->input, buf.len);
    }

    h2o_timeout_link(client->ctx->loop, client->ctx->io_timeout, &client->_timeout);
}

static void on_body_chunked(h2o_socket_t *sock, int status)
{
    assert(!"FIXME");
}

static void on_error_before_head(h2o_http1client_t *client, const char *errstr)
{
    client->_cb.on_head(client, errstr, 0, 0, h2o_buf_init(NULL, 0), NULL, 0);
    close_client(client);
}

static void on_head(h2o_socket_t *sock, int status)
{
    h2o_http1client_t *client = sock->data;
    int minor_version, http_status, rlen, is_head_only;
    const char *msg;
    struct phr_header headers[100];
    size_t msg_len, num_headers, i;
    h2o_socket_cb reader;

    h2o_timeout_unlink(&client->_timeout);

    if (status != 0) {
        on_error_before_head(client , "I/O error");
        return;
    }

    /* parse response */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    rlen = phr_parse_response(sock->input->bytes, sock->input->size, &minor_version, &http_status, &msg, &msg_len, headers, &num_headers, 0);
    switch (rlen) {
    case -1: /* error */
        on_error_before_head(client, "failed to parse the response");
        return;
    case -2: /* incomplete */
        h2o_timeout_link(client->ctx->loop, client->ctx->io_timeout, &client->_timeout);
        return;
    }

    /* RFC 2616 4.4 */
    is_head_only = client->_method_is_head
        || ((100 <= status && status <= 199) || status == 204 || status == 304);

    /* call the callback */
    if ((client->_cb.on_body = client->_cb.on_head(client, is_head_only ? h2o_http1client_error_is_eos : NULL, minor_version, http_status, h2o_buf_init(msg, msg_len), headers, num_headers)) == NULL) {
        close_client(client);
        return;
    }
    assert(! is_head_only);

    /* setup and start reading the body */
    reader = on_body_until_close;
    for (i = 0; i != num_headers; ++i) {
        if (h2o_lcstris(headers[i].name, headers[i].name_len, H2O_STRLIT("content-encoding"))) {
            if (h2o_memis(headers[i].value, headers[i].value_len, H2O_STRLIT("chunked"))) {
                reader = on_body_chunked;
                break;
            } else if (h2o_memis(headers[i].value, headers[i].value_len, H2O_STRLIT("identity"))) {
                /* continue */
            } else {
                on_error_before_head(client, "unexpected type of transfer-encoding");
                return;
            }
        } else if (h2o_lcstris(headers[i].name, headers[i].name_len, H2O_STRLIT("content-length"))) {
            if ((client->_body_bytesleft = h2o_strtosize(headers[i].value, headers[i].value_len)) == SIZE_MAX) {
                on_error_before_head(client, "invalid content-length");
                return;
            }
            reader = on_body_content_length;
        }
    }

    h2o_consume_input_buffer(&client->sock->input, rlen);

    client->_timeout.cb = on_body_timeout;
    h2o_socket_read_start(sock, reader);
    reader(client->sock, 0);
}

static void on_head_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_send_request(h2o_socket_t *sock, int status)
{
    h2o_http1client_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (status != 0) {
        on_error_before_head(client, "I/O error");
        return;
    }

    h2o_socket_read_start(client->sock, on_head);
    client->_timeout.cb = on_head_timeout;
    h2o_timeout_link(client->ctx->loop, client->ctx->io_timeout, &client->_timeout);
}

static void on_send_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_connect_error(h2o_http1client_t *client, const char *errstr)
{
    client->_cb.on_connect(client, errstr, NULL, NULL, NULL);
    close_client(client);
}

static void on_connect(h2o_socket_t *sock, int status)
{
    h2o_http1client_t *client = sock->data;
    h2o_buf_t *reqbufs;
    size_t reqbufcnt;

    h2o_timeout_unlink(&client->_timeout);

    if (status != 0) {
        on_connect_error(client, "connection failed");
        return;
    }

    if ((client->_cb.on_head = client->_cb.on_connect(client, NULL, &reqbufs, &reqbufcnt, &client->_method_is_head)) == NULL) {
        close_client(client);
        return;
    }
    h2o_socket_write(client->sock, reqbufs, reqbufcnt, on_send_request);
    /* TODO no need to set the timeout if all data has been written into TCP sendbuf */
    client->_timeout.cb = on_send_timeout;
    h2o_timeout_link(client->ctx->loop, client->ctx->io_timeout, &client->_timeout);
}

static void on_connect_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http1client_t *client = H2O_STRUCT_FROM_MEMBER(h2o_http1client_t, _timeout, entry);
    on_connect_error(client, client->_errstr);
}

const char * const h2o_http1client_error_is_eos = "end of stream";

h2o_http1client_t *h2o_http1client_connect(h2o_http1client_ctx_t *ctx, h2o_mempool_t *pool, const char *host, uint16_t port, h2o_http1client_connect_cb cb)
{
    h2o_http1client_t *client;
    struct addrinfo hints, *res;
    char serv[sizeof("65535")];
    int err;

    client = h2o_malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->ctx = ctx;
    client->pool = pool;
    client->_cb.on_connect = cb;
    client->_timeout.cb = on_connect_timeout;

    /* resolve destination (FIXME use the function supplied by the loop) */
    sprintf(serv, "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    if ((err = getaddrinfo(host, serv, &hints, &res)) != 0) {
        client->_errstr = "name resulution failure";
        goto Error;
    }
    /* start connecting */
    if ((client->sock = h2o_socket_connect(ctx->loop, res->ai_addr, res->ai_addrlen, on_connect)) == NULL) {
        client->_errstr = "socket create error";
        goto Error;
    }
    client->sock->data = client;
    h2o_timeout_link(ctx->loop, ctx->io_timeout, &client->_timeout);

    return client;
Error:
    h2o_timeout_link(ctx->loop, ctx->zero_timeout, &client->_timeout);
    return client;
}

void h2o_http1client_cancel(h2o_http1client_t *client)
{
    close_client(client);
}
