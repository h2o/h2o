/*
 * Copyright (c) 2022 Fastly, Inc, Goro Fuji, Kazuho Oku
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
#include "h2o/http1.h"

struct st_h2olog_params_t {
    float sample_ratio;
    char *trace;
    char *sni;
    char *address;
    int appdata;
};

static void destroy_params(struct st_h2olog_params_t *params)
{
    free(params->trace);
    free(params->sni);
    free(params->address);
    free(params);
}

static void on_upgrade_complete(void *_params, h2o_socket_t *sock, size_t reqsize)
{
    struct st_h2olog_params_t *params = _params;

    if (sock != NULL) {
        h2o_socket_export_t info;
        if (h2o_socket_export(sock, &info) != 0)
            h2o_fatal("h2o_socket_export failed");
        /* register log fd after writing HTTP response, as log is written by multiple threads */
        if (ptls_log_add_fd(info.fd, params->sample_ratio, params->trace, params->sni, params->address, params->appdata) != 0)
            h2o_fatal("failed to add fd to h2olog");
    }

    destroy_params(params);
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct sockaddr_storage local;
    struct st_h2olog_params_t *params = h2o_mem_alloc(sizeof(*params));
    *params = (struct st_h2olog_params_t){.sample_ratio = 1,
                                          .trace = h2o_mem_alloc(req->path.len + 2 /* should be enough */),
                                          .sni = h2o_mem_alloc(req->path.len + 2 /* should be enough */),
                                          .address = h2o_mem_alloc(req->path.len + 2 /* should be enough */)};
    char *trace_tail = params->trace, *sni_tail = params->sni, *address_tail = params->address;
    int ret;

    /* delegate the request to the next handler unless the request is accepted on a UNIX socket */
    if (!(req->conn->callbacks->get_sockname(req->conn, (struct sockaddr *)&local) > 0 && local.ss_family == AF_UNIX)) {
        ret = -1;
        goto Fail;
    }

    /* parse params */
    if (req->query_at != SIZE_MAX) {
        h2o_iovec_t iter = h2o_iovec_init(req->path.base + req->query_at + 1, req->path.len - (req->query_at + 1)), value;
        const char *name;
        size_t name_len;
        while ((name = h2o_next_token(&iter, '&', '&', &name_len, &value)) != NULL) {
            if (h2o_memis(name, name_len, H2O_STRLIT("sample-ratio"))) {
                h2o_iovec_t unescaped = h2o_uri_unescape(&req->pool, value.base, value.len);
                if (unescaped.base == NULL || sscanf(unescaped.base, "%f", &params->sample_ratio) != 1 ||
                    !(0 <= params->sample_ratio && params->sample_ratio <= 1)) {
                    h2o_send_error_400(req, "Bad Request", "sample-rate must be a number between 0 and 1", 0);
                    ret = 0;
                    goto Fail;
                }
            } else if (h2o_memis(name, name_len, H2O_STRLIT("trace"))) {
                h2o_iovec_t unescaped = h2o_uri_unescape(&req->pool, value.base, value.len);
                h2o_memcpy(trace_tail, unescaped.base, unescaped.len);
                trace_tail += unescaped.len;
                *trace_tail++ = '\0';
            } else if (h2o_memis(name, name_len, H2O_STRLIT("sni"))) {
                h2o_iovec_t unescaped = h2o_uri_unescape(&req->pool, value.base, value.len);
                h2o_memcpy(sni_tail, unescaped.base, unescaped.len);
                sni_tail += unescaped.len;
                *sni_tail++ = '\0';
            } else if (h2o_memis(name, name_len, H2O_STRLIT("address"))) {
                h2o_iovec_t unescaped = h2o_uri_unescape(&req->pool, value.base, value.len);
                h2o_memcpy(address_tail, unescaped.base, unescaped.len);
                address_tail += unescaped.len;
                *address_tail++ = '\0';
            } else if (h2o_memis(name, name_len, H2O_STRLIT("application-data"))) {
                params->appdata = 1;
            }
        }
    }

    /* termninate lists */
    *trace_tail = '\0';
    *sni_tail = '\0';
    *address_tail = '\0';

    if (!(req->version < 0x200 && req->input.scheme == &H2O_URL_SCHEME_HTTP)) {
        h2o_send_error_400(req, "Bad Request", "h2olog is available only for cleartext HTTP/1", 0);
        ret = 0;
        goto Fail;
    }

    /* send the response, then take over the socket */
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_http1_upgrade(req, NULL, 0, on_upgrade_complete, params);
    return 0;

Fail:
    destroy_params(params);
    return ret;
}

void h2o_log_register(h2o_hostconf_t *hostconf)
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, H2O_LOG_URI_PATH, 0);
    h2o_handler_t *self = h2o_create_handler(pathconf, sizeof(*self));
    self->on_req = on_req;
}
