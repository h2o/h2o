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
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "h2o.h"

void h2o_context_init(h2o_context_t *ctx, h2o_loop_t *loop)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    h2o_timeout_init(ctx->loop, &ctx->zero_timeout, 0);
    h2o_timeout_init(ctx->loop, &ctx->req_timeout, H2O_DEFAULT_REQ_TIMEOUT);
    h2o_linklist_init_anchor(&ctx->handlers);
    h2o_linklist_init_anchor(&ctx->filters);
    h2o_linklist_init_anchor(&ctx->loggers);
    h2o_linklist_init_anchor(&ctx->configurators);
    h2o_register_chunked_filter(ctx);
    h2o_init_mimemap(&ctx->mimemap, H2O_DEFAULT_MIMETYPE);
    ctx->server_name = h2o_buf_init(H2O_STRLIT("h2o/0.1"));
    ctx->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    ctx->http1_upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    ctx->http2_max_concurrent_requests_per_connection = H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION;
}

void h2o_context_dispose(h2o_context_t *ctx)
{
#define CLEANUP(type, anchor) do { \
    while (! h2o_linklist_is_empty(&anchor)) { \
        type *e = H2O_STRUCT_FROM_MEMBER(type, _link, anchor.next); \
        h2o_linklist_unlink(&e->_link); \
        if (e->destroy != NULL) \
            e->destroy(e); \
    } \
} while (0)

    CLEANUP(h2o_configurator_t, ctx->configurators);
    CLEANUP(h2o_handler_t, ctx->handlers);
    CLEANUP(h2o_filter_t, ctx->filters);
    CLEANUP(h2o_logger_t, ctx->loggers);
    h2o_dispose_mimemap(&ctx->mimemap);

#undef CLEANUP
}

h2o_configurator_t *h2o_context_get_configurator(h2o_context_t *context, const char *cmd)
{
    h2o_linklist_t *node;

    for (node = context->configurators.next; node != &context->configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if (strcmp(configurator->cmd, cmd) == 0)
            return configurator;
    }

    return NULL;
}

int h2o_context_configure(h2o_context_t *context, const char *config_file, yoml_t *config_node)
{
    size_t i;

    h2o_context__init_global_configurators(context);

    /* apply the configuration */
    if (config_node->type != YOML_TYPE_MAPPING) {
        h2o_context_print_config_error(NULL, config_file, config_node, "root node must be a MAPPING");
        return -1;
    }
    for (i = 0; i != config_node->data.mapping.size; ++i) {
        yoml_t *key = config_node->data.mapping.elements[i].key;
        yoml_t *value = config_node->data.mapping.elements[i].value;
        h2o_configurator_t *configurator;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_context_print_config_error(NULL, config_file, key, "command must be a string");
            return -1;
        }
        if ((configurator = h2o_context_get_configurator(context, key->data.scalar)) == NULL) {
            h2o_context_print_config_error(NULL, config_file, key, "unknown command: %s", key->data.scalar);
            return -1;
        }
        if (configurator->on_cmd(configurator, context, config_file, value) != 0)
            return -1;
    }

    { /* call the complete callback */
        h2o_linklist_t *node;
        for (node = context->configurators.next; node != &context->configurators; node = node->next) {
            h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
            if (configurator->on_complete != NULL)
                if (configurator->on_complete(configurator, context) != 0)
                    return -1;
        }
    }

    return 0;
}

void h2o_context_print_config_error(h2o_configurator_t *configurator, const char *config_file, yoml_t *config_node, const char *reason, ...)
{
    va_list args;

    fprintf(stderr, "[%s:%zu] ", config_file, config_node->line + 1);
    if (configurator != NULL)
        fprintf(stderr, "in command %s, ", configurator->cmd);
    va_start(args, reason);
    vfprintf(stderr, reason, args);
    va_end(args);
    fputc('\n', stderr);
}

void h2o_get_timestamp(h2o_context_t *ctx, h2o_mempool_t *pool, h2o_timestamp_t *ts)
{
    uint64_t now = h2o_now(ctx->loop);

    if (ctx->_timestamp_cache.uv_now_at != now) {
        time_t prev_sec = ctx->_timestamp_cache.tv_at.tv_sec;
        ctx->_timestamp_cache.uv_now_at = now;
        gettimeofday(&ctx->_timestamp_cache.tv_at, NULL);
        if (ctx->_timestamp_cache.tv_at.tv_sec != prev_sec) {
            /* update the string cache */
            if (ctx->_timestamp_cache.value != NULL)
                h2o_mempool_release_shared(ctx->_timestamp_cache.value);
            ctx->_timestamp_cache.value = h2o_mempool_alloc_shared(NULL, sizeof(h2o_timestamp_string_t));
            h2o_time2str_rfc1123(ctx->_timestamp_cache.value->rfc1123, ctx->_timestamp_cache.tv_at.tv_sec);
            h2o_time2str_log(ctx->_timestamp_cache.value->log, ctx->_timestamp_cache.tv_at.tv_sec);
        }
    }

    ts->at = ctx->_timestamp_cache.tv_at;
    h2o_mempool_link_shared(pool, ctx->_timestamp_cache.value);
    ts->str = ctx->_timestamp_cache.value;
}
