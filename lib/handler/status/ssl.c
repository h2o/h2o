/*
 * Copyright (c) 2018 Fastly Inc, Ichito Nagata
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

struct st_ssl_status_ctx_t {
    uint64_t alpn_h1;
    uint64_t alpn_h2;
    uint64_t handshake_full;
    uint64_t handshake_resume;
    uint64_t handshake_accum_time_full;
    uint64_t handshake_accum_time_resume;
    pthread_mutex_t mutex;
};

static void ssl_status_per_thread(void *_ssc, h2o_context_t *ctx)
{
    struct st_ssl_status_ctx_t *ssc = _ssc;

    pthread_mutex_lock(&ssc->mutex);

    ssc->alpn_h1 += ctx->ssl.alpn_h1;
    ssc->alpn_h2 += ctx->ssl.alpn_h2;
    ssc->handshake_full += ctx->ssl.handshake_full;
    ssc->handshake_resume += ctx->ssl.handshake_resume;
    ssc->handshake_accum_time_full += ctx->ssl.handshake_accum_time_full;
    ssc->handshake_accum_time_resume += ctx->ssl.handshake_accum_time_resume;

    pthread_mutex_unlock(&ssc->mutex);
}

static void *ssl_status_init(void)
{
    struct st_ssl_status_ctx_t *ssc = h2o_mem_alloc(sizeof(*ssc));
    *ssc = (struct st_ssl_status_ctx_t){0};
    pthread_mutex_init(&ssc->mutex, NULL);
    return ssc;
}

static h2o_iovec_t ssl_status_final(void *_ssc, h2o_globalconf_t *globalconf, h2o_req_t *req)
{
    struct st_ssl_status_ctx_t *ssc = _ssc;
    h2o_iovec_t buf;

#define BUFSIZE (1024)
    buf.base = h2o_mem_alloc_pool(&req->pool, char, BUFSIZE);
    buf.len = snprintf(buf.base, BUFSIZE,
                       ",\n"
                       " \"ssl.alpn.h1\": %" PRIu64 ",\n"
                       " \"ssl.alpn.h2\": %" PRIu64 ",\n"
                       " \"ssl.handshake.full\": %" PRIu64 ",\n"
                       " \"ssl.handshake.resume\": %" PRIu64 ",\n"
                       " \"ssl.handshake.accumulated-time.full\": %" PRIu64 ",\n"
                       " \"ssl.handshake.accumulated-time.resume\": %" PRIu64 "\n",
                       ssc->alpn_h1, ssc->alpn_h2, ssc->handshake_full, ssc->handshake_resume, ssc->handshake_accum_time_full,
                       ssc->handshake_accum_time_resume);
    pthread_mutex_destroy(&ssc->mutex);
    free(ssc);
    return buf;
#undef BUFSIZE
}

h2o_status_handler_t h2o_ssl_status_handler = {{H2O_STRLIT("ssl")}, ssl_status_final, ssl_status_init, ssl_status_per_thread};
