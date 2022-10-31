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

struct st_h2o_log_handler_t {
    h2o_handler_t super;
} h2o_log_handler;

static h2o_iovec_t get_query_param(const h2o_req_t *req, const char *name, size_t name_len)
{
    if (req->query_at == SIZE_MAX)
        goto NotFound;
    const char *query = req->path.base + req->query_at;
    const char *end = req->path.base + req->path.len;
    while (query != end) {
        const char *eq = strchr(query, '=');
        if (eq == NULL)
            goto NotFound;

        if (h2o_memis(query, query - eq, name, name_len) == 0) {
            const char *value = eq + 1;
            const char *next_and = strchr(value, '&');
            size_t value_len = next_and == NULL ? ((req->path.base + req->path.len) - value) : (next_and - value);
            return h2o_iovec_init(value, value_len);
        }
        query = strchr(query, '&');
        if (query == NULL)
            goto NotFound;
        query += 1;
    }

NotFound:
    return h2o_iovec_init(NULL, 0);
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    if (req->conn->callbacks->steal_socket == NULL)
        goto Error;
    int req_version = req->version;
    if (req_version != 0x100 && req_version != 0x101 && req->scheme->is_ssl)
        goto Error;

    int include_appdata;
    {
        h2o_iovec_t appdata = get_query_param(req, H2O_STRLIT("appdata"));
        // TODO: this parameter changes the global flag forever, but it would be better if the flag is per-connection.
        if (appdata.base != NULL)
            ptls_log.include_appdata = !h2o_memis(appdata.base, appdata.len, H2O_STRLIT("0"));
    }

    h2o_socket_t *sock = req->conn->callbacks->steal_socket(req->conn);

    h2o_socket_export_t export_info;
    h2o_socket_export(sock, &export_info);

    if (req_version == 0x100) {
        (void)write(export_info.fd, H2O_STRLIT("HTTP/1.0 200 OK\r\n\r\n"));
    } else {
        (void)write(export_info.fd, H2O_STRLIT("HTTP/1.1 200 OK\r\n\r\n"));
    }

    int ret;
    if ((ret = ptls_log_add_fd(export_info.fd)) != 0) {
        h2o_error_printf("failed to add fd to h2olog: %d\n", ret);
        close(export_info.fd);
        return 0;
    }
    return 0;

Error:
    req->res.status = 400;
    static h2o_generator_t generator;
    h2o_start_response(req, &generator);
    h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
    return 0;
}

void h2o_log_register(h2o_pathconf_t *conf)
{
    struct st_h2o_log_handler_t *self = (void *)h2o_create_handler(conf, sizeof(*self));
    self->super.on_req = on_req;
}
