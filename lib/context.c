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
#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include "h2o.h"

static void on_context_init(h2o_context_t *ctx, h2o_pathconf_t *pathconf)
{
#define DOIT(type, list) \
    do { \
        size_t i; \
        for (i = 0; i != pathconf->list.size; ++i) { \
            type *o = pathconf->list.entries[i]; \
            if (o->on_context_init != NULL) \
                ctx->_module_configs[o->_config_slot] = o->on_context_init(o, ctx); \
        } \
    } while (0)

    DOIT(h2o_handler_t, handlers);
    DOIT(h2o_filter_t, filters);
    DOIT(h2o_logger_t, loggers);

#undef DOIT
}

static void on_context_dispose(h2o_context_t *ctx, h2o_pathconf_t *pathconf)
{
#define DOIT(type, list) \
    do { \
        size_t i; \
        for (i = 0; i != pathconf->list.size; ++i) { \
            type *o = pathconf->list.entries[i]; \
            if (o->on_context_dispose != NULL) \
                o->on_context_dispose(o, ctx); \
        } \
    } while (0)

    DOIT(h2o_handler_t, handlers);
    DOIT(h2o_filter_t, filters);
    DOIT(h2o_logger_t, loggers);

#undef DOIT
}

void h2o_context_init(h2o_context_t *ctx, h2o_loop_t *loop, h2o_globalconf_t *config)
{
    size_t i, j;

    assert(config->hosts.size != 0);

    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    ctx->globalconf = config;
    h2o_timeout_init(ctx->loop, &ctx->zero_timeout, 0);
    h2o_timeout_init(ctx->loop, &ctx->req_timeout, config->req_timeout);

    ctx->_module_configs = h2o_mem_alloc(sizeof(*ctx->_module_configs) * config->_num_config_slots);
    memset(ctx->_module_configs, 0, sizeof(*ctx->_module_configs) * config->_num_config_slots);
    for (i = 0; i != config->hosts.size; ++i) {
        h2o_hostconf_t *hostconf = config->hosts.entries + i;
        for (j = 0; j != hostconf->paths.size; ++j) {
            h2o_pathconf_t *pathconf = hostconf->paths.entries + j;
            on_context_init(ctx, pathconf);
        }
        on_context_init(ctx, &hostconf->fallback_path);
    }
}

void h2o_context_dispose(h2o_context_t *ctx)
{
    h2o_globalconf_t *config = ctx->globalconf;
    size_t i, j;

    for (i = 0; i != config->hosts.size; ++i) {
        h2o_hostconf_t *hostconf = config->hosts.entries + i;
        for (j = 0; j != hostconf->paths.size; ++j) {
            h2o_pathconf_t *pathconf = hostconf->paths.entries + i;
            on_context_dispose(ctx, pathconf);
        }
    }
    free(ctx->_module_configs);
    h2o_timeout_dispose(ctx->loop, &ctx->zero_timeout);
    h2o_timeout_dispose(ctx->loop, &ctx->req_timeout);

#if H2O_USE_LIBUV
    /* make sure the handles released by h2o_timeout_dispose get freed */
    uv_run(ctx->loop, UV_RUN_NOWAIT);
#endif
}

void h2o_get_timestamp(h2o_context_t *ctx, h2o_mem_pool_t *pool, h2o_timestamp_t *ts)
{
    uint64_t now = h2o_now(ctx->loop);

    if (ctx->_timestamp_cache.uv_now_at != now) {
        time_t prev_sec = ctx->_timestamp_cache.tv_at.tv_sec;
        ctx->_timestamp_cache.uv_now_at = now;
        gettimeofday(&ctx->_timestamp_cache.tv_at, NULL);
        if (ctx->_timestamp_cache.tv_at.tv_sec != prev_sec) {
            /* update the string cache */
            if (ctx->_timestamp_cache.value != NULL)
                h2o_mem_release_shared(ctx->_timestamp_cache.value);
            ctx->_timestamp_cache.value = h2o_mem_alloc_shared(NULL, sizeof(h2o_timestamp_string_t), NULL);
            h2o_time2str_rfc1123(ctx->_timestamp_cache.value->rfc1123, ctx->_timestamp_cache.tv_at.tv_sec);
            h2o_time2str_log(ctx->_timestamp_cache.value->log, ctx->_timestamp_cache.tv_at.tv_sec);
        }
    }

    ts->at = ctx->_timestamp_cache.tv_at;
    h2o_mem_link_shared(pool, ctx->_timestamp_cache.value);
    ts->str = ctx->_timestamp_cache.value;
}
