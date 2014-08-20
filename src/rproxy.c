#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct rproxy_t {
    h2o_ostream_t super;
    h2o_filter_t *filter;
    const char *reproxy_url;
};

static int parse_url(h2o_mempool_t *pool, const char *url, char const **host, uint16_t *port, char const **path)
{
    const char *hp_start, *hp_end, *colon_at;

    /* check and skip scheme */
    if (strncmp(url, "http://", 7) != 0) {
        return 0;
    }
    hp_start = url + 7;
    /* locate the end of hostport */
    if ((hp_end = strchr(hp_start, '/')) != NULL) {
        *path = hp_end;
    } else {
        hp_end = hp_start + strlen(hp_start);
        *path = "/";
    }
    /* parse hostport */
    for (colon_at = hp_start; colon_at != hp_end; ++colon_at)
        if (*colon_at == ':')
            break;
    if (colon_at != hp_end) {
        *host = h2o_strdup(pool, hp_start, colon_at - hp_start).base;
        if ((*port = strtol(colon_at + 1, NULL, 10)) == 0)
            return 0;
    } else {
        *host = h2o_strdup(pool, hp_start, hp_end - hp_start).base;
        *port = 80;
    }
    /* success */
    return 1;
}

static void send_chunk(h2o_ostream_t *_self, h2o_req_t *req, uv_buf_t *inbufs, size_t inbufcnt, int is_final)
{
    struct rproxy_t *self = (void*)_self;
    const char *host, *path;
    uint16_t port;

    /* throw away all data */
    if (! is_final) {
        h2o_schedule_proceed_response(req);
        return;
    }

    /* end of the original stream, start retreiving the data from the reproxy-url */
    if (! parse_url(&req->pool, self->reproxy_url, &host, &port, &path)) {
        host = NULL;
        path = NULL;
        port = 0;
    }

    /* NOT IMPLEMENTED!!! */
    uv_buf_t body = h2o_sprintf(
        &req->pool,
        "reproxy request to URL: %s\n"
        "  host: %s\n"
        "  port: %u\n"
        "  path: %s\n",
        self->reproxy_url,
        host,
        (int)port,
        path);
    req->res.status = 500;
    req->res.reason = "Internal Server Error";
    req->res.content_length = body.len;
    h2o_set_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"), 1);

    if (self->filter->next != NULL)
        self->filter->next->on_start_response(self->filter->next, req);

    assert(is_final);
    h2o_ostream_send_next(&self->super, req, &body, 1, is_final);
}

static void on_start_response(h2o_filter_t *self, h2o_req_t *req)
{
    struct rproxy_t *rproxy;
    h2o_header_iterator_t reproxy_header;

    /* do nothing unless 200 */
    if (req->res.status != 200)
        goto SkipMe;
    if ((reproxy_header = h2o_find_header(&req->res.headers, H2O_TOKEN_X_REPROXY_URL)).value == NULL)
        goto SkipMe;
    h2o_delete_header(&req->res.headers, reproxy_header);

    /* setup */
    rproxy = (void*)h2o_prepend_output_filter(req, sizeof(struct rproxy_t));
    rproxy->filter = self;
    rproxy->super.do_send = send_chunk;
    rproxy->reproxy_url = h2o_strdup(&req->pool, reproxy_header.value->base, reproxy_header.value->len).base;

    /* next ostream is setup when send_chunk receives EOS */
    return;

SkipMe:
    if (self->next != NULL)
        self->next->on_start_response(self->next, req);
}

void h2o_add_reproxy_url(h2o_loop_context_t *context)
{
    h2o_filter_t *filter = h2o_define_filter(context, sizeof(h2o_filter_t));
    filter->on_start_response = on_start_response;
}
