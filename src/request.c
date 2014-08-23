#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

#define INITIAL_INBUFSZ 8192

static void deferred_proceed_cb(h2o_timeout_entry_t *entry)
{
    h2o_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_req_t, _timeout_entry, entry);
    h2o_proceed_response(req, 0);
}

void h2o_init_request(h2o_req_t *req, void *conn, h2o_loop_context_t *ctx, h2o_req_t *src)
{
    if (conn != NULL) {
        req->conn = conn;
        req->ctx = ctx;
        h2o_mempool_init(&req->pool);
        memset(&req->_timeout_entry, 0, sizeof(req->_timeout_entry));
        req->_timeout_entry.cb = deferred_proceed_cb;
    } else {
        h2o_timeout_unlink_entry(&req->ctx->zero_timeout, &req->_timeout_entry);
        h2o_mempool_clear(&req->pool);
    }

    req->authority = NULL;
    req->authority_len = 0;
    req->method = NULL;
    req->method_len = 0;
    req->path = NULL;
    req->path_len = 0;
    req->scheme = NULL;
    req->scheme_len = 0;
    req->version = 0;
    memset(&req->headers, 0, sizeof(req->headers));

    req->res.status = 0;
    req->res.reason = NULL;
    req->res.content_length = SIZE_MAX;
    memset(&req->res.headers, 0, sizeof(req->res.headers));

    req->http1_is_persistent = 0;
    req->upgrade.base = NULL;
    req->upgrade.len = 0;

    req->_generator = NULL;
    req->_ostr_top = NULL;

    if (src != NULL) {
#define COPY(s, len) do { \
    req->s = h2o_mempool_alloc(&req->pool, src->len); \
    memcpy((void*)req->s, src->s, src->len); \
    req->len = src->len; \
} while (0)
        COPY(authority, authority_len);
        COPY(method, method_len);
        COPY(path, path_len);
        COPY(scheme, scheme_len);
        req->version = src->version;
        {
            const h2o_header_t *header = src->headers.entries, * header_end = header + src->headers.size;
            for (; header != header_end; ++header) {
                if (h2o_buf_is_token(header->name.str)) {
                    h2o_add_header(&req->pool, &req->headers, header->name.token, header->value.base, header->value.len);
                } else {
                    h2o_add_header_by_str(&req->pool, &req->headers, header->name.str->base, header->name.str->len, 0, header->value.base, header->value.len);
                }
            }
        }
        req->http1_is_persistent = src->http1_is_persistent;
        if (src->upgrade.base != NULL) {
            COPY(upgrade.base, upgrade.len);
        } else {
            req->upgrade.base = NULL;
            req->upgrade.len = 0;
        }
#undef COPY
    }
}

void h2o_dispose_request(h2o_req_t *req)
{
    /* FIXME close generator and ostreams */
    h2o_timeout_unlink_entry(&req->ctx->zero_timeout, &req->_timeout_entry);
    h2o_mempool_clear(&req->pool);
}

void h2o_prepare_response(h2o_req_t *req)
{
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_vector_reserve(&req->pool, (h2o_vector_t*)&req->res.headers, sizeof(h2o_header_t), 8);
    req->res.content_length = SIZE_MAX;
}

h2o_generator_t *h2o_start_response(h2o_req_t *req, size_t sz)
{
    req->_generator = h2o_mempool_alloc(&req->pool, sz);
    req->_generator->proceed = NULL;

    /* setup response filters */
    if (req->ctx->filters != NULL) {
        req->ctx->filters->on_start_response(req->ctx->filters, req);
    }

    return req->_generator;
}

h2o_ostream_t *h2o_prepend_output_filter(h2o_req_t *req, size_t sz)
{
    h2o_ostream_t *ostr = h2o_mempool_alloc(&req->pool, sz);
    ostr->next = req->_ostr_top;
    ostr->do_send = NULL;

    req->_ostr_top = ostr;

    return ostr;
}

void h2o_schedule_proceed_response(h2o_req_t *req)
{
    h2o_timeout_link_entry(&req->ctx->zero_timeout, &req->_timeout_entry);
}
