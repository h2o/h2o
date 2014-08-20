#include <stddef.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"

static void proceed_response_cb(h2o_timeout_entry_t *entry)
{
    h2o_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_req_t, _timeout_entry, entry);
    h2o_proceed_response(req, 0);
}

static void default_dispose_filter(h2o_filter_t *filter)
{
    if (filter->next != NULL)
        filter->next->dispose(filter->next);
}

void h2o_schedule_proceed_response(h2o_req_t *req)
{
    h2o_timeout_link_entry(&req->ctx->request_next_timeout, &req->_timeout_entry);
}

void h2o_loop_context_init(h2o_loop_context_t *ctx, uv_loop_t *loop)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    h2o_timeout_init(&ctx->request_next_timeout, 0, proceed_response_cb, loop);
    h2o_timeout_init(&ctx->http1_req_timeout, 10000, h2o_http1_on_timeout, loop);
    h2o_add_chunked_encoder(ctx);
    h2o_init_mimemap(&ctx->mimemap, "application/octet-stream");
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
