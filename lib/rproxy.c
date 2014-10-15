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

static void send_chunk(h2o_ostream_t *_self, h2o_req_t *req, h2o_buf_t *inbufs, size_t inbufcnt, int is_final)
{
    struct rproxy_t *self = (void*)_self;
    const char *host, *path;
    uint16_t port;

    /* throw away all data */
    if (! is_final) {
        h2o_ostream_send_next(&self->super, req, NULL, 0, 0);
        return;
    }

    /* end of the original stream, start retreiving the data from the reproxy-url */
    if (! parse_url(&req->pool, self->reproxy_url, &host, &port, &path)) {
        host = NULL;
        path = NULL;
        port = 0;
    }

    /* NOT IMPLEMENTED!!! */
    h2o_buf_t body;
    body.len = snprintf(NULL, 0,
        "reproxy request to URL: %s\n"
        "  host: %s\n"
        "  port: %u\n"
        "  path: %s\n",
        self->reproxy_url,
        host,
        (int)port,
        path);
    body.base = h2o_mempool_alloc(&req->pool, body.len + 1);
    sprintf(body.base,
        "reproxy request to URL: %s\n"
        "  host: %s\n"
        "  port: %u\n"
        "  path: %s\n",
        self->reproxy_url,
        host,
        (int)port,
        path);
    req->res.status = 200;
    req->res.reason = "Internal Server Error";
    req->res.content_length = SIZE_MAX;
    h2o_set_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"), 1);

    h2o_setup_next_ostream(self->filter, req, &self->super.next);

    assert(is_final);
    h2o_ostream_send_next(&self->super, req, &body, 1, is_final);
}

static void on_setup_ostream(h2o_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct rproxy_t *rproxy;
    ssize_t reproxy_header_index;
    h2o_buf_t reproxy_url;

    /* do nothing unless 200 */
    if (req->res.status != 200)
        goto SkipMe;
    if ((reproxy_header_index = h2o_find_header(&req->res.headers, H2O_TOKEN_X_REPROXY_URL, -1)) == -1)
        goto SkipMe;
    reproxy_url = req->res.headers.entries[reproxy_header_index].value;
    h2o_delete_header(&req->res.headers, reproxy_header_index);

    /* setup */
    rproxy = (void*)h2o_add_ostream(req, sizeof(struct rproxy_t), slot);
    rproxy->filter = self;
    rproxy->super.do_send = send_chunk;
    rproxy->reproxy_url = h2o_strdup(&req->pool, reproxy_url.base, reproxy_url.len).base;

    /* next ostream is setup when send_chunk receives EOS */
    return;

SkipMe:
    h2o_setup_next_ostream(self, req, slot);
}

void h2o_register_reproxy_filter(h2o_hostconf_t *host_config)
{
    h2o_filter_t *self = h2o_malloc(sizeof(*self));

    memset(self, 0, sizeof(*self));
    self->destroy = (void*)free;
    self->on_setup_ostream = on_setup_ostream;

    /* insert at the head! */
    h2o_linklist_insert(host_config->filters.next, &self->_link);
}
