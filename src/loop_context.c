#include <stddef.h>
#include <stdlib.h>
#include <sys/time.h>
#include "h2o.h"
#include "h2o/http1.h"

static void default_dispose_filter(h2o_filter_t *filter)
{
    if (filter->next != NULL)
        filter->next->dispose(filter->next);
}

void h2o_loop_context_init(h2o_loop_context_t *ctx, uv_loop_t *loop)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    h2o_timeout_init(&ctx->zero_timeout, 0, loop);
    h2o_timeout_init(&ctx->req_timeout, 10000, loop);
    h2o_add_chunked_encoder(ctx);
    h2o_init_mimemap(&ctx->mimemap, "application/octet-stream");
    ctx->server_name = uv_buf_init(H2O_STRLIT("h2o/0.1"));
    ctx->max_request_entity_size = 1024 * 1024 * 1024;
    ctx->http2_max_concurrent_requests_per_connection = 16;
}

void h2o_loop_context_dispose(h2o_loop_context_t *ctx)
{
    if (ctx->filters != NULL) {
        ctx->filters->dispose(ctx->filters);
    }
    h2o_dispose_mimemap(&ctx->mimemap);
}

h2o_filter_t *h2o_define_filter(h2o_loop_context_t *context, size_t sz)
{
    h2o_filter_t *filter;

    if ((filter = malloc(sz)) == NULL)
        h2o_fatal("no memory");
    memset(filter, 0, sz);
    filter->next = context->filters;
    filter->dispose = default_dispose_filter;
    filter->on_start_response = NULL; /* filters should always set this */

    context->filters = filter;

    return filter;
}

void h2o_get_timestamp(h2o_loop_context_t *ctx, h2o_mempool_t *pool, h2o_timestamp_t *ts)
{
    uint64_t now = uv_now(ctx->loop);

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
