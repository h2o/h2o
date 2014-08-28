#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

#define INITIAL_INBUFSZ 8192

static void deferred_proceed_cb(h2o_timeout_entry_t *entry)
{
    h2o_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_req_t, _timeout_entry, entry);
    h2o_proceed_response(req);
}

void h2o_init_request(h2o_req_t *req, void *conn, h2o_loop_context_t *ctx, h2o_req_t *src)
{
    if (conn != NULL) {
        req->conn = conn;
        h2o_mempool_init(&req->pool);
        memset(&req->_timeout_entry, 0, sizeof(req->_timeout_entry));
        req->_timeout_entry.cb = deferred_proceed_cb;
    } else {
        /* reinit */
        h2o_dispose_request(req);
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
    req->entity = uv_buf_init(NULL, 0);

    req->res.status = 0;
    req->res.reason = NULL;
    req->res.content_length = SIZE_MAX;
    memset(&req->res.headers, 0, sizeof(req->res.headers));
    req->bytes_sent = 0;

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
        h2o_vector_reserve(&req->pool, (h2o_vector_t*)&req->headers, sizeof(h2o_header_t), src->headers.size);
        memcpy(req->headers.entries, src->headers.entries, src->headers.size);
        req->headers.size = src->headers.size;
        req->entity = src->entity;
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
    if (req->_generator != NULL) {
        /* close generator */
        req->_generator->proceed(req->_generator, req, 1);
        req->_generator = NULL;
    }
    /* FIXME close ostreams */
    h2o_timeout_unlink_entry(&req->conn->ctx->zero_timeout, &req->_timeout_entry);

    if (req->version != 0 && req->conn->ctx->access_log != NULL) {
        req->conn->ctx->access_log->log(req->conn->ctx->access_log, req);
    }

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
    if (req->conn->ctx->filters != NULL) {
        req->conn->ctx->filters->on_start_response(req->conn->ctx->filters, req);
    }

    return req->_generator;
}

void h2o_send(h2o_req_t *req, uv_buf_t *bufs, size_t bufcnt, int is_final)
{
    size_t i;

    assert(req->_generator != NULL);

    if (is_final)
        req->_generator = NULL;

    for (i = 0; i != bufcnt; ++i)
        req->bytes_sent += bufs[i].len;

    req->_ostr_top->do_send(req->_ostr_top, req, bufs, bufcnt, is_final);
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
    h2o_timeout_link_entry(&req->conn->ctx->zero_timeout, &req->_timeout_entry);
}
