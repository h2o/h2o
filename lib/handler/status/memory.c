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

struct st_memory_status_ctx_t {
    struct {
        uint64_t chunks;
        uint64_t low_watermark;
    } mem_pool, socket_ssl, socket_zerocopy;
    pthread_mutex_t mutex;
};

static void memory_status_per_thread(void *priv, h2o_context_t *ctx)
{
    struct st_memory_status_ctx_t *csc = priv;

    pthread_mutex_lock(&csc->mutex);

    csc->mem_pool.chunks += h2o_mem_pool_allocator.chunks.size;
    csc->mem_pool.low_watermark += h2o_mem_pool_allocator.low_watermark;
    csc->socket_ssl.chunks += h2o_socket_ssl_buffer_allocator.chunks.size;
    csc->socket_ssl.low_watermark += h2o_socket_ssl_buffer_allocator.chunks.size;
    csc->socket_zerocopy.chunks += h2o_socket_zerocopy_buffer_allocator.chunks.size;
    csc->socket_zerocopy.low_watermark += h2o_socket_zerocopy_buffer_allocator.chunks.size;


    pthread_mutex_unlock(&csc->mutex);
}

static void *memory_status_init(void)
{
    struct st_memory_status_ctx_t *ret = h2o_mem_alloc(sizeof(*ret));
    *ret = (struct st_memory_status_ctx_t){{}, {}, {}, PTHREAD_MUTEX_INITIALIZER};
    return ret;
}

static h2o_iovec_t memory_status_json(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    struct st_memory_status_ctx_t *csc = priv;
    h2o_iovec_t ret;

#define BUFSIZE 512
    ret.base = h2o_mem_alloc_pool(&req->pool, char, BUFSIZE);
    ret.len = snprintf(ret.base, BUFSIZE,
                       ",\n"
                       " \"memory.mem_pool.chunks\": %" PRIu64 ",\n"
                       " \"memory.mem_pool.low_watermark\": %" PRIu64 ",\n"
                       " \"memory.socket.ssl.chunks\": %" PRIu64 ",\n"
                       " \"memory.socket.ssl.low_watermark\": %" PRIu64 ",\n"
                       " \"memory.socket.zerocopy.chunks\": %" PRIu64 ",\n"
                       " \"memory.socket.zerocopy.low_watermark\": %" PRIu64 "\n",
                       csc->mem_pool.chunks,
                       csc->mem_pool.low_watermark,
                       csc->socket_ssl.chunks,
                       csc->socket_ssl.low_watermark,
                       csc->socket_zerocopy.chunks,
                       csc->socket_zerocopy.low_watermark);
    pthread_mutex_destroy(&csc->mutex);
#undef BUFSIZE
    free(csc);
    return ret;
}

h2o_status_handler_t h2o_memory_status_handler = {
    {H2O_STRLIT("memory")},
    memory_status_json,
    memory_status_init,
    memory_status_per_thread,
};
