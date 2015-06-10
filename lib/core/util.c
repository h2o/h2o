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
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

static void on_ssl_handshake_complete(h2o_socket_t *sock, int status)
{
    const h2o_iovec_t *ident;
    h2o_context_t *ctx = sock->data;
    h2o_hostconf_t **hosts = sock->data2;
    sock->data = NULL;
    sock->data2 = NULL;

    h2o_iovec_t proto;
    if (status != 0) {
        h2o_socket_close(sock);
        return;
    }

    proto = h2o_socket_ssl_get_selected_protocol(sock);
    for (ident = h2o_http2_alpn_protocols; ident->len != 0; ++ident) {
        if (proto.len == ident->len && memcmp(proto.base, ident->base, proto.len) == 0) {
            goto Is_Http2;
        }
    }
    /* connect as http1 */
    h2o_http1_accept(ctx, hosts, sock);
    return;

Is_Http2:
    /* connect as http2 */
    h2o_http2_accept(ctx, hosts, sock);
}

void h2o_accept_ssl(h2o_context_t *ctx, h2o_hostconf_t **hosts, h2o_socket_t *sock, SSL_CTX *ssl_ctx)
{
    sock->data = ctx;
    sock->data2 = hosts;
    h2o_socket_ssl_server_handshake(sock, ssl_ctx, on_ssl_handshake_complete);
}

size_t h2o_stringify_protocol_version(char *dst, int version)
{
    char *p = dst;

    if (version < 0x200) {
        assert(version <= 0x109);
#define PREFIX "HTTP/1."
        memcpy(p, PREFIX, sizeof(PREFIX) - 1);
        p += sizeof(PREFIX) - 1;
#undef PREFIX
        *p++ = '0' + (version & 0xff);
    } else {
#define PROTO "HTTP/2"
        memcpy(p, PROTO, sizeof(PROTO) - 1);
        p += sizeof(PROTO) - 1;
#undef PROTO
    }

    *p = '\0';
    return p - dst;
}
