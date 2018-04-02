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
    h2o_timeout_entry_t _timeout;
    int _method_is_head;
    h2o_hostinfo_getaddr_req_t *_getaddr_req;
    int _can_keepalive;
    union {
        struct {
            size_t bytesleft;
        } content_length;
        struct {
            struct phr_chunked_decoder decoder;
            size_t bytes_decoded_in_buf;
        } chunked;
    } _body_decoder;
};

static void close_client(struct st_h2o_http1client_private_t *client)
{
    if (client->_getaddr_req != NULL) {
        h2o_hostinfo_getaddr_cancel(client->_getaddr_req);
        client->_getaddr_req = NULL;
    }
    if (client->super.ssl.server_name != NULL)
        free(client->super.ssl.server_name);
    if (client->super.sock != NULL) {
        if (client->super.sockpool.pool != NULL && client->_can_keepalive) {
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
    if (h2o_timeout_is_linked(&client->_timeout))
        h2o_timeout_unlink(&client->_timeout);
    free(client);
}

static void on_body_error(struct st_h2o_http1client_private_t *client, const char *errstr)
{
    client->_can_keepalive = 0;
    client->_cb.on_body(&client->super, errstr);
    close_client(client);
}

static void on_body_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_body_error(client, "I/O timeout");
}

static void on_body_until_close(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
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

    h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_body_content_length(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

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
                client->super.sock->input->size -= sock->bytes_read - client->_body_decoder.content_length.bytesleft;
                client->_can_keepalive = 0;
            }
            client->_body_decoder.content_length.bytesleft = 0;
            errstr = h2o_http1client_error_is_eos;
        } else {
            client->_body_decoder.content_length.bytesleft -= sock->bytes_read;
            errstr = NULL;
        }
        ret = client->_cb.on_body(&client->super, errstr);
        if (errstr == h2o_http1client_error_is_eos) {
            close_client(client);
            return;
        } else if (ret != 0) {
            client->_can_keepalive = 0;
            close_client(client);
            return;
        }
    }

    h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_body_chunked(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;
    h2o_buffer_t *inbuf;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        if (err == h2o_socket_error_closed && !phr_decode_chunked_is_in_data(&client->_body_decoder.chunked.decoder)) {
            /*
             * if the peer closed after a full chunk, treat this
             * as if the transfer had complete, browsers appear to ignore
             * a missing 0\r\n chunk
             */
            client->_can_keepalive = 0;
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
            client->_can_keepalive = 0;
            errstr = "failed to parse the response (chunked)";
            break;
        case -2: /* incomplete */
            errstr = NULL;
            break;
        default: /* complete, with garbage on tail; should disable keepalive */
            client->_can_keepalive = 0;
        /* fallthru */
        case 0: /* complete */
            errstr = h2o_http1client_error_is_eos;
            break;
        }
        inbuf->size -= sock->bytes_read - newsz;
        cb_ret = client->_cb.on_body(&client->super, errstr);
        if (errstr != NULL) {
            close_client(client);
            return;
        } else if (cb_ret != 0) {
            client->_can_keepalive = 0;
            close_client(client);
            return;
        }
    }

    h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_error_before_head(struct st_h2o_http1client_private_t *client, const char *errstr)
{
    assert(!client->_can_keepalive);
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

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        on_error_before_head(client, "I/O error (head)");
        return;
    }

    h2o_mem_init_pool(&pool);

    headers = h2o_mem_alloc_pool(&pool, sizeof(*headers) * MAX_HEADERS);
    header_names = h2o_mem_alloc_pool(&pool, sizeof(*header_names) * MAX_HEADERS);

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
            h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
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
            } else {
                header_names[i] = h2o_iovec_init(src_headers[i].name, src_headers[i].name_len);
                headers[i].name = &header_names[i];
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
            h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
            goto Exit;
        }
    }

    /* parse the headers */
    reader = on_body_until_close;
    client->_can_keepalive = minor_version >= 1;
    for (i = 0; i != num_headers; ++i) {
        if (headers[i].name == &H2O_TOKEN_CONNECTION->buf) {
            if (h2o_contains_token(headers[i].value.base, headers[i].value.len, H2O_STRLIT("keep-alive"), ',')) {
                client->_can_keepalive = 1;
            } else {
                client->_can_keepalive = 0;
            }
        } else if (headers[i].name == &H2O_TOKEN_TRANSFER_ENCODING->buf) {
            if (h2o_memis(headers[i].value.base, headers[i].value.len, H2O_STRLIT("chunked"))) {
                /* precond: _body_decoder.chunked is zero-filled */
                client->_body_decoder.chunked.decoder.consume_trailer = 1;
                reader = on_body_chunked;
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
            if (reader != on_body_chunked)
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
            client->_can_keepalive = 0;
    }

    /* call the callback. sock may be stealed and stealed sock need rlen.*/
    client->_cb.on_body = client->_cb.on_head(&client->super, is_eos ? h2o_http1client_error_is_eos : NULL, minor_version,
                                              http_status, h2o_iovec_init(msg, msg_len), headers, num_headers, rlen);

    if (is_eos) {
        close_client(client);
        goto Exit;
    } else if (client->_cb.on_body == NULL) {
        client->_can_keepalive = 0;
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

static void on_head_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_send_request(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (err != NULL) {
        on_error_before_head(client, "I/O error (send request)");
        return;
    }

    h2o_socket_read_start(client->super.sock, on_head);
    client->_timeout.cb = on_head_timeout;
    h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_send_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_error_before_head(client, "I/O timeout");
}

static void on_connect_error(struct st_h2o_http1client_private_t *client, const char *errstr)
{
    assert(errstr != NULL);
    client->_cb.on_connect(&client->super, errstr, NULL, NULL, NULL);
    close_client(client);
}

static void on_connection_ready(struct st_h2o_http1client_private_t *client)
{
    h2o_iovec_t *reqbufs;
    size_t reqbufcnt;

    if ((client->_cb.on_head = client->_cb.on_connect(&client->super, NULL, &reqbufs, &reqbufcnt, &client->_method_is_head)) ==
        NULL) {
        close_client(client);
        return;
    }
    h2o_socket_write(client->super.sock, reqbufs, reqbufcnt, on_send_request);
    /* TODO no need to set the timeout if all data has been written into TCP sendbuf */
    client->_timeout.cb = on_send_timeout;
    h2o_timeout_link(client->super.ctx->loop, client->super.ctx->io_timeout, &client->_timeout);
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    h2o_timeout_unlink(&client->_timeout);

    if (err == NULL) {
        /* success */
    } else if (err == h2o_socket_error_ssl_cert_name_mismatch &&
               (SSL_CTX_get_verify_mode(client->super.ctx->ssl_ctx) & SSL_VERIFY_PEER) == 0) {
        /* peer verification skipped */
    } else {
        on_connect_error(client, err);
        return;
    }

    on_connection_ready(client);
}

static void on_connect(h2o_socket_t *sock, const char *err)
{
    struct st_h2o_http1client_private_t *client = sock->data;

    if (err != NULL) {
        h2o_timeout_unlink(&client->_timeout);
        on_connect_error(client, err);
        return;
    }
    if (client->super.ssl.server_name != NULL && client->super.sock->ssl == NULL) {
        h2o_socket_ssl_handshake(client->super.sock, client->super.ctx->ssl_ctx, client->super.ssl.server_name,
                                 on_handshake_complete);
        return;
    }

    h2o_timeout_unlink(&client->_timeout);

    on_connection_ready(client);
}

static void on_pool_connect(h2o_socket_t *sock, const char *errstr, void *data)
{
    struct st_h2o_http1client_private_t *client = data;

    client->super.sockpool.connect_req = NULL;

    if (sock == NULL) {
        assert(errstr != NULL);
        on_connect_error(client, errstr);
        return;
    }

    client->super.sock = sock;
    sock->data = client;
    on_connect(sock, NULL);
}

static void on_connect_timeout(h2o_timeout_entry_t *entry)
{
    struct st_h2o_http1client_private_t *client = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http1client_private_t, _timeout, entry);
    on_connect_error(client, "connection timeout");
}

static void start_connect(struct st_h2o_http1client_private_t *client, struct sockaddr *addr, socklen_t addrlen)
{
    if ((client->super.sock = h2o_socket_connect(client->super.ctx->loop, addr, addrlen, on_connect)) == NULL) {
        on_connect_error(client, "socket create error");
        return;
    }
    client->super.sock->data = client;
}

static void on_getaddr(h2o_hostinfo_getaddr_req_t *getaddr_req, const char *errstr, struct addrinfo *res, void *_client)
{
    struct st_h2o_http1client_private_t *client = _client;

    assert(getaddr_req == client->_getaddr_req);
    client->_getaddr_req = NULL;

    if (errstr != NULL) {
        on_connect_error(client, errstr);
        return;
    }

    /* start connecting */
    struct addrinfo *selected = h2o_hostinfo_select_one(res);
    start_connect(client, selected->ai_addr, selected->ai_addrlen);
}

static struct st_h2o_http1client_private_t *create_client(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx,
                                                          h2o_iovec_t ssl_server_name, h2o_http1client_connect_cb cb)
{
    struct st_h2o_http1client_private_t *client = h2o_mem_alloc(sizeof(*client));

    *client = (struct st_h2o_http1client_private_t){{ctx}};
    if (ssl_server_name.base != NULL)
        client->super.ssl.server_name = h2o_strdup(NULL, ssl_server_name.base, ssl_server_name.len).base;
    client->super.data = data;
    client->_cb.on_connect = cb;
    /* caller needs to setup _cb, timeout.cb, sock, and sock->data */

    if (_client != NULL)
        *_client = &client->super;
    return client;
}

const char *const h2o_http1client_error_is_eos = "end of stream";

void h2o_http1client_connect(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx, h2o_iovec_t host, uint16_t port,
                             int is_ssl, h2o_http1client_connect_cb cb)
{
    struct st_h2o_http1client_private_t *client;
    char serv[sizeof("65536")];

    /* setup */
    client = create_client(_client, data, ctx, is_ssl ? host : h2o_iovec_init(NULL, 0), cb);
    client->_timeout.cb = on_connect_timeout;
    h2o_timeout_link(ctx->loop, ctx->io_timeout, &client->_timeout);

    { /* directly call connect(2) if `host` is an IP address */
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        if (h2o_hostinfo_aton(host, &sin.sin_addr) == 0) {
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            start_connect(client, (void *)&sin, sizeof(sin));
            return;
        }
    }
    { /* directly call connect(2) if `host` refers to an UNIX-domain socket */
        struct sockaddr_un sa;
        const char *to_sa_err;
        if ((to_sa_err = h2o_url_host_to_sun(host, &sa)) != h2o_url_host_to_sun_err_is_not_unix_socket) {
            if (to_sa_err != NULL) {
                on_connect_error(client, to_sa_err);
                return;
            }
            start_connect(client, (void *)&sa, sizeof(sa));
            return;
        }
    }
    /* resolve destination and then connect */
    client->_getaddr_req =
        h2o_hostinfo_getaddr(ctx->getaddr_receiver, host, h2o_iovec_init(serv, sprintf(serv, "%u", (unsigned)port)), AF_UNSPEC,
                             SOCK_STREAM, IPPROTO_TCP, AI_ADDRCONFIG | AI_NUMERICSERV, on_getaddr, client);
}

void h2o_http1client_connect_with_pool(h2o_http1client_t **_client, void *data, h2o_http1client_ctx_t *ctx,
                                       h2o_socketpool_t *sockpool, h2o_http1client_connect_cb cb)
{
    struct st_h2o_http1client_private_t *client =
        create_client(_client, data, ctx, sockpool->is_ssl ? sockpool->peer.host : h2o_iovec_init(NULL, 0), cb);
    client->super.sockpool.pool = sockpool;
    client->_timeout.cb = on_connect_timeout;
    h2o_timeout_link(ctx->loop, ctx->io_timeout, &client->_timeout);
    h2o_socketpool_connect(&client->super.sockpool.connect_req, sockpool, ctx->loop, ctx->getaddr_receiver, on_pool_connect,
                           client);
}

void h2o_http1client_cancel(h2o_http1client_t *_client)
{
    struct st_h2o_http1client_private_t *client = (void *)_client;
    client->_can_keepalive = 0;
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
