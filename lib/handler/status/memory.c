/*
 * Copyright (c) 2022 Fastly
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

#include "h2o.h"
#include <inttypes.h>

struct st_recycle_status_t {
    uint64_t chunks;
    uint64_t low_watermark;
};

struct st_memory_status_ctx_t {
    pthread_mutex_t mutex;
    struct st_recycle_status_t mem_pool, socket_ssl, socket_zerocopy;
    size_t socket_zerocopy_inflight;
};

static void recycle_status_per_thread(struct st_recycle_status_t *status, h2o_mem_recycle_t *recycle)
{
    status->chunks += recycle->chunks.size;
    status->low_watermark += recycle->low_watermark;
}

static void memory_status_per_thread(void *priv, h2o_context_t *ctx)
{
    struct st_memory_status_ctx_t *csc = priv;

    pthread_mutex_lock(&csc->mutex);

    recycle_status_per_thread(&csc->mem_pool, &h2o_mem_pool_allocator);
    recycle_status_per_thread(&csc->socket_ssl, &h2o_socket_ssl_buffer_allocator);
    recycle_status_per_thread(&csc->socket_zerocopy, &h2o_socket_zerocopy_buffer_allocator);
    csc->socket_zerocopy_inflight += h2o_socket_num_zerocopy_buffers_inflight;

    pthread_mutex_unlock(&csc->mutex);
}

static void *memory_status_init(void)
{
    struct st_memory_status_ctx_t *ret = h2o_mem_alloc(sizeof(*ret));
    *ret = (struct st_memory_status_ctx_t){PTHREAD_MUTEX_INITIALIZER};
    return ret;
}

static h2o_iovec_t memory_status_json(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    struct st_memory_status_ctx_t *csc = priv;
    h2o_iovec_t ret;

#define BUFSIZE 512
#define FMT(prefix)                                                                                                                \
    " \"memory." H2O_TO_STR(prefix) ".chunks\": %" PRIu64 ",\n \"memory." H2O_TO_STR(prefix) ".low_watermark\": %" PRIu64 ",\n"
#define ARGS(prefix) csc->prefix.chunks, csc->prefix.low_watermark
    ret.base = h2o_mem_alloc_pool(&req->pool, char, BUFSIZE);
    ret.len = snprintf(ret.base, BUFSIZE,
                       ",\n" FMT(mem_pool) FMT(socket.ssl) FMT(socket.zerocopy) " \"memory.socket.zerocopy.inflight\": %zu\n",
                       ARGS(mem_pool), ARGS(socket_ssl), ARGS(socket_zerocopy),
                       csc->socket_zerocopy_inflight * h2o_socket_zerocopy_buffer_allocator.conf->memsize);
#undef FMT
#undef ARGS
#undef BUFSIZE

    pthread_mutex_destroy(&csc->mutex);
    free(csc);
    return ret;
}

h2o_status_handler_t h2o_memory_status_handler = {
    {H2O_STRLIT("memory")},
    memory_status_json,
    memory_status_init,
    memory_status_per_thread,
};
