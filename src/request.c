#include <stdlib.h>
#include "h2o.h"

#define INITIAL_INBUFSZ 8192

void h2o_init_request(h2o_req_t *req, void *conn, h2o_loop_context_t *ctx, h2o_req_t *src)
{
    if (conn != NULL) {
        req->conn = conn;
        req->ctx = ctx;
        memset(&req->pool, 0, sizeof(req->pool));
        memset(&req->_timeout_entry, 0, sizeof(req->_timeout_entry));
    } else {
        h2o_timeout_unlink_entry(&req->ctx->request_next_timeout, &req->_timeout_entry);
        h2o_mempool_destroy(&req->pool, 1);
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
    h2o_clear_headers(&req->headers);

    req->res.status = 0;
    req->res.reason = NULL;
    req->res.content_length = SIZE_MAX;
    h2o_clear_headers(&req->res.headers);

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
            h2o_header_iterator_t iter;
            uv_buf_t *name;
            for (iter.value = NULL; (iter = h2o_next_header(&src->headers, iter, &name)).value != NULL; ) {
                if (h2o_buf_is_token(name)) {
                    h2o_add_header(&req->pool, &req->headers, H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, name), iter.value->base, iter.value->len);
                } else {
                    h2o_add_header_by_str(&req->pool, &req->headers, name->base, name->len, 0, iter.value->base, iter.value->len);
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
    h2o_timeout_unlink_entry(&req->ctx->request_next_timeout, &req->_timeout_entry);
    h2o_mempool_destroy(&req->pool, 0);
}

void h2o_prepare_response(h2o_req_t *req)
{
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_init_headers(&req->pool, &req->res.headers, NULL, 0, 8, NULL, NULL, NULL);
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
