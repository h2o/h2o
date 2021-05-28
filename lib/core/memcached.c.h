/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Satoh Hiroh
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
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

#undef async_resumption_context
#define async_resumption_context memcached_async_resumption_context

static struct {
    struct {
        h2o_memcached_context_t *ctx;
    } memcached;
    unsigned expiration;
} async_resumption_context;

struct st_h2o_memcached_resumption_accept_data_t {
    struct st_h2o_accept_data_t super;
    h2o_memcached_req_t *get_req;
};

static void on_memcached_accept_timeout(h2o_timer_t *entry);

static struct st_h2o_accept_data_t *create_memcached_accept_data(h2o_accept_ctx_t *ctx, h2o_socket_t *sock,
                                                                 struct timeval connected_at)
{
    struct st_h2o_memcached_resumption_accept_data_t *data = (struct st_h2o_memcached_resumption_accept_data_t *)create_accept_data(
        ctx, sock, connected_at, on_memcached_accept_timeout, sizeof(struct st_h2o_memcached_resumption_accept_data_t));
    data->get_req = NULL;
    return &data->super;
}

static void destroy_memcached_accept_data(struct st_h2o_accept_data_t *_accept_data)
{
    struct st_h2o_memcached_resumption_accept_data_t *accept_data =
        (struct st_h2o_memcached_resumption_accept_data_t *)_accept_data;
    assert(accept_data->get_req == NULL);
    destroy_accept_data(&accept_data->super);
}

static void memcached_resumption_on_get(h2o_iovec_t session_data, void *_accept_data)
{
    struct st_h2o_memcached_resumption_accept_data_t *accept_data = _accept_data;
    accept_data->get_req = NULL;
    h2o_socket_ssl_resume_server_handshake(accept_data->super.sock, session_data);
}

static void memcached_resumption_get(h2o_socket_t *sock, h2o_iovec_t session_id)
{
    struct st_h2o_memcached_resumption_accept_data_t *data = sock->data;

    data->get_req = h2o_memcached_get(async_resumption_context.memcached.ctx, data->super.ctx->libmemcached_receiver, session_id,
                                      memcached_resumption_on_get, data, H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

static void memcached_resumption_new(h2o_socket_t *sock, h2o_iovec_t session_id, h2o_iovec_t session_data)
{
    h2o_memcached_set(async_resumption_context.memcached.ctx, session_id, session_data,
                      (uint32_t)time(NULL) + async_resumption_context.expiration,
                      H2O_MEMCACHED_ENCODE_KEY | H2O_MEMCACHED_ENCODE_VALUE);
}

void h2o_accept_setup_memcached_ssl_resumption(h2o_memcached_context_t *memc, unsigned expiration)
{
    async_resumption_context.memcached.ctx = memc;
    async_resumption_context.expiration = expiration;
    h2o_socket_ssl_async_resumption_init(memcached_resumption_get, memcached_resumption_new);
    accept_data_callbacks.create = create_memcached_accept_data;
    accept_data_callbacks.destroy = destroy_memcached_accept_data;
}

static void on_memcached_accept_timeout(h2o_timer_t *entry)
{
    struct st_h2o_memcached_resumption_accept_data_t *data =
        H2O_STRUCT_FROM_MEMBER(struct st_h2o_memcached_resumption_accept_data_t, super.timeout, entry);
    if (data->get_req != NULL) {
        h2o_memcached_cancel_get(async_resumption_context.memcached.ctx, data->get_req);
        data->get_req = NULL;
    }
    accept_timeout(&data->super);
}
