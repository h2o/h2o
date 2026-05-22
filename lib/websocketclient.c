/*
 * Copyright (c) 2018 Baodng Chen
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "h2o/websocketclient.h"

static void create_sec_websock_key(char dst[25], int fd)
{
    uint8_t nonce[16];

    read(fd, nonce, sizeof(nonce));
    h2o_base64_encode(dst, nonce, sizeof(nonce), 0);
    dst[24] = '\0';
}

static void on_close(h2o_websocket_client_conn_t *conn)
{
    (*conn->cb)(conn, NULL);
}

static void on_recv(h2o_socket_t *sock, const char *err)
{
    h2o_websocket_client_conn_t *conn = sock->data;

    if (err != NULL) {
        on_close(conn);
        return;
    }
    h2o_websocket_client_proceed(conn);
}

static void free_write_buf(h2o_websocket_client_conn_t *conn)
{
    size_t i;
    for (i = 0; i < conn->_write_buf.cnt; ++i)
        free(conn->_write_buf.bufs[i].base);
}

static void on_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_websocket_client_conn_t *conn = sock->data;

    if (err != NULL) {
        on_close(conn);
        return;
    }
    assert(conn->_write_buf.cnt > 0);
    free_write_buf(conn);
    conn->_write_buf.cnt = 0;

    h2o_websocket_client_proceed(conn);
}

static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *_conn)
{
    h2o_websocket_client_conn_t *conn = _conn;

    /* return WOULDBLOCK if no data */
    if (conn->sock->input->size == 0) {
        wslay_event_set_error(conn->ws_ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }

    if (conn->sock->input->size < len)
        len = conn->sock->input->size;
    memcpy(buf, conn->sock->input->bytes, len);
    h2o_buffer_consume(&conn->sock->input, len);
    return len;
}

static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *_conn)
{
    h2o_websocket_client_conn_t *conn = _conn;
    h2o_iovec_t *buf;

    /* return WOULDBLOCK if pending or no buffer available */
    if (h2o_socket_is_writing(conn->sock) ||
        conn->_write_buf.cnt == sizeof(conn->_write_buf.bufs) / sizeof(conn->_write_buf.bufs[0])) {
        wslay_event_set_error(conn->ws_ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }

    buf = &conn->_write_buf.bufs[conn->_write_buf.cnt];

    /* copy data */
    buf->base = h2o_mem_alloc(len);
    buf->len = len;
    memcpy(buf->base, data, len);
    ++conn->_write_buf.cnt;
    return len;
}

static int genmask_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *_conn)
{
    h2o_websocket_client_conn_t *conn = _conn;
    assert(conn->fd > 0);
    read(conn->fd, buf, len);
    return 0;
}

static void on_msg_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *_conn)
{
    h2o_websocket_client_conn_t *conn = _conn;
    (*conn->cb)(conn, arg);
}

h2o_websocket_client_conn_t *h2o_upgrade_to_websocket_client(h2o_httpclient_t *client, void *data, int version, int fd,
                                                             h2o_websocket_client_msg_callback cb)
{
    h2o_websocket_client_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
    h2o_socket_t *sock;

    assert(fd > 0);

    /* only for http1 connection */
    assert(version < 0x200);

    /* setup the context */
    memset(conn, 0, sizeof(*conn));

    /* steal socket from http client */
    sock = client->steal_socket(client);
    sock->data = conn;
    conn->sock = sock;

    /* detach from socket pool */
    h2o_socketpool_detach(client->connpool->socketpool, sock);

    conn->ws_callbacks.recv_callback = recv_callback;
    conn->ws_callbacks.send_callback = send_callback;
    conn->ws_callbacks.genmask_callback = genmask_callback;
    conn->ws_callbacks.on_msg_recv_callback = on_msg_callback;
    conn->data = data;
    conn->cb = cb;
    conn->fd = fd;

    /* init wslay client context */
    wslay_event_context_client_init(&conn->ws_ctx, &conn->ws_callbacks, conn);

    if (sock->input->size != 0) {
        h2o_buffer_consume(&sock->input, sock->input->size);
    }
    assert(!h2o_socket_is_reading(sock));
    assert(!h2o_socket_is_writing(sock));
    assert(wslay_event_want_read(conn->ws_ctx));
    h2o_websocket_client_proceed(conn);
    return conn;
}

size_t h2o_websocket_client_create_headers(h2o_mem_pool_t *pool, const h2o_url_t *url_parsed, int fd, h2o_header_t **_headers,
                                           char **_sec_websock_key)
{
    h2o_headers_t headers = {NULL, 0, 0};
    char *sec_websock_key = h2o_mem_alloc_pool(pool, char, 25);

    /**
     * GET /chat HTTP/1.1
     * Host: server.example.com
     * Upgrade: websocket
     * Connection: Upgrade
     * Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
     * Sec-WebSocket-Protocol: chat, superchat
     * Sec-WebSocket-Version: 13
     * Origin: http://example.com
     **/
    h2o_add_header(pool, &headers, H2O_TOKEN_UPGRADE, NULL, H2O_STRLIT("websocket"));
    h2o_add_header(pool, &headers, H2O_TOKEN_CONNECTION, NULL, H2O_STRLIT("upgrade"));

    create_sec_websock_key(sec_websock_key, fd);
    h2o_add_header_by_str(pool, &headers, H2O_STRLIT("sec-websocket-key"), 0, NULL, sec_websock_key, 24);
    h2o_add_header_by_str(pool, &headers, H2O_STRLIT("sec-webSocket-protocol"), 0, NULL, H2O_STRLIT("chat, superchat"));
    h2o_add_header_by_str(pool, &headers, H2O_STRLIT("sec-webSocket-version"), 0, NULL, H2O_STRLIT("13"));

    if (_sec_websock_key) {
        *_sec_websock_key = sec_websock_key;
    }
    *_headers = headers.entries;
    return headers.size;
}

static void create_accept_key(char *dst, const char *sec_websock_key)
{
    uint8_t sha1buf[20], key_src[60];

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    memcpy(key_src, sec_websock_key, 24);
    memcpy(key_src + 24, WS_GUID, 36);
    SHA1(key_src, sizeof(key_src), sha1buf);
    h2o_base64_encode(dst, sha1buf, sizeof(sha1buf), 0);
    dst[28] = '\0';
#undef WS_GUID
}

int h2o_is_websocket_respheader(int version, int status, const char *sec_websock_key, h2o_header_t *_headers, size_t num_headers)
{
    size_t hidx;
    h2o_headers_t headers;
    char accept_key[29];

    /* only for http1 connection */
    assert(version < 0x200);

    /**
     * HTTP/1.1 101 Switching Protocols
     * Upgrade: websocket
     * Connection: Upgrade
     * Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=
     * Sec-WebSocket-Protocol: chat
     */
    if (status != 101) {
        return -1;
    }

    headers.entries = _headers;
    headers.size = num_headers;
    /* headers.capacity = num_headers; */

    /* connection header */
    if ((hidx = h2o_find_header(&headers, H2O_TOKEN_CONNECTION, -1)) == -1) {
        return -1;
    }

    /* upgrade header */
    if ((hidx = h2o_find_header(&headers, H2O_TOKEN_UPGRADE, -1)) == -1) {
        return -1;
    }
    if (h2o_strstr(headers.entries[hidx].value.base, headers.entries[hidx].value.len, H2O_STRLIT("websocket")) == SIZE_MAX) {
        return -1;
    }

    /* sec-websocket-accept header */
    if ((hidx = h2o_find_header_by_str(&headers, H2O_STRLIT("sec-websocket-accept"), -1)) == -1) {
        return -1;
    }
    if (headers.entries[hidx].value.base == NULL || headers.entries[hidx].value.len < sizeof(accept_key) - 1) {
        return -1;
    }
    create_accept_key(accept_key, sec_websock_key);
    if (memcmp(accept_key, headers.entries[hidx].value.base, sizeof(accept_key) - 1)) {
        return -1;
    }
    return 0;
}

void h2o_websocket_client_close(h2o_websocket_client_conn_t *conn)
{
    if (conn->sock != NULL)
        h2o_socket_close(conn->sock);
    free_write_buf(conn);
    wslay_event_context_free(conn->ws_ctx);
    free(conn);
}

void h2o_websocket_client_proceed(h2o_websocket_client_conn_t *conn)
{
    int handled;

    /* run the loop until getting to a point where no more progress can be achieved */
    do {
        handled = 0;
        if (!h2o_socket_is_writing(conn->sock) && wslay_event_want_write(conn->ws_ctx)) {
            if (wslay_event_send(conn->ws_ctx) != 0) {
                goto Close;
            }
            /* avoid infinite loop when user want send more bufers count than ours in on_msg_callback() */
            if (conn->_write_buf.cnt < sizeof(conn->_write_buf.bufs) / sizeof(conn->_write_buf.bufs[0])) {
                handled = 1;
            }
        }
        if (conn->sock->input->size != 0 && wslay_event_want_read(conn->ws_ctx)) {
            if (wslay_event_recv(conn->ws_ctx) != 0) {
                goto Close;
            }
            handled = 1;
        }
    } while (handled);

    if (!h2o_socket_is_writing(conn->sock) && conn->_write_buf.cnt > 0) {
        /* write */
        h2o_socket_write(conn->sock, conn->_write_buf.bufs, conn->_write_buf.cnt, on_write_complete);
    }

    if (wslay_event_want_read(conn->ws_ctx)) {
        h2o_socket_read_start(conn->sock, on_recv);
    } else if (h2o_socket_is_writing(conn->sock) || wslay_event_want_write(conn->ws_ctx)) {
        h2o_socket_read_stop(conn->sock);
    } else {
        /* nothing is going on... close the socket */
        goto Close;
    }

    return;

Close:
    on_close(conn);
}
