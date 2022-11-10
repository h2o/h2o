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

static struct {
    uint32_t rate;

    // TODO: addresses, snis
} h2o_log_sampling;

struct st_h2o_log_handler_t {
    h2o_handler_t super;
} h2o_log_handler;

struct st_query_param_iter_t {
    struct {
        h2o_iovec_t path;
        size_t query_at;
    } input;

    struct {
        char *cur;
        char *end;
    } cursor;
};

int h2o_log_skip_tracing(const struct sockaddr *local, const struct sockaddr *remote)
{
    int skip_tracing = 0;

    if (h2o_log_sampling.rate != 0) {
        skip_tracing = h2o_rand() % h2o_log_sampling.rate != 0;
    }

    // TODO: use h2o_log_sampling.addresses
    return skip_tracing;
}

int h2o_log_skip_tracing_sni(const char *server_name, size_t server_name_len)
{
    // TODO: use h2o_log_sampling.snis
    return 0;
}

static void query_param_iter_init(struct st_query_param_iter_t *iter, h2o_iovec_t path, size_t query_at)
{
    assert(query_at != SIZE_MAX);

    *iter = (struct st_query_param_iter_t){
        .input =
            {
                .path = path,
                .query_at = query_at,
            },
        .cursor =
            {
                .cur = path.base + query_at + 1,
                .end = path.base + path.len,
            },
    };
}

static int query_param_iter_next(struct st_query_param_iter_t *iter, h2o_iovec_t *name, h2o_iovec_t *value)
{
    if (iter->cursor.cur != iter->cursor.end) {
        char *eq = memchr(iter->cursor.cur, '=', iter->input.path.len);
        if (eq == NULL)
            return 0;

        *name = (h2o_iovec_t){iter->cursor.cur, eq - iter->cursor.cur};

        char *v = eq + 1;
        const char *next_and = memchr(v, '&', iter->input.path.len);
        size_t v_len = next_and == NULL ? (iter->cursor.end - v) : (next_and - v);
        *value = (h2o_iovec_t){v, v_len};

        iter->cursor.cur = v + v_len + 1;

        return 1;
    }

    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    if (req->conn->callbacks->steal_socket == NULL)
        goto Error;

    if (req->query_at != SIZE_MAX) {
        struct st_query_param_iter_t iter;
        query_param_iter_init(&iter, req->path, req->query_at);

        h2o_iovec_t name, value;
        while (query_param_iter_next(&iter, &name, &value)) {
            if (h2o_memis(name.base, name.len, H2O_STRLIT("sampling_rate"))) {
                char src[value.len + 1];
                memcpy(src, value.base, value.len);
                src[value.len] = '\0'; // strtoul(3) requires a null-terminated string
                char *end;
                unsigned long v = strtoul(src, &end, 10);
                if ((src + value.len) != end && (0 < v && v <= UINT32_MAX)) {
                    h2o_log_sampling.rate = v;
                } else {
                    h2o_error_printf("h2olog: sampling_rate must be a positive integer (0 < N <= UINT32_MAX), but got: %.*s\n", (int)value.len, value.base);
                }
            } else if (h2o_memis(name.base, name.len, H2O_STRLIT("sampling_address"))) {
                // h2olog -A <sampring_addr>
                // TODO
            } else if (h2o_memis(name.base, name.len, H2O_STRLIT("sampling_sni"))) {
                // h2olog -N <sampring_sni>
                // TODO
            } else {
                h2o_error_printf("h2olog: unrecognized parameter: %.*s=%.*s\n", (int)name.len, name.base, (int)value.len,
                                 value.base);
            }
        }
    }

    h2o_socket_t *sock = req->conn->callbacks->steal_socket(req->conn);
    if (sock == NULL)
        goto Error;

    int ret;
    if ((ret = ptls_log_add_fd(h2o_socket_get_fd(sock))) != 0) {
        h2o_error_printf("failed to add fd to h2olog: %d\n", ret);
        goto Error;
    }

    h2o_socket_export_t export_info;
    h2o_socket_export(sock, &export_info);
    (void)write(export_info.fd, H2O_STRLIT("HTTP/1.1 200 OK\r\n\r\n"));
    return 0;

Error:
    h2o_send_error_400(req, "Bad Request", "h2olog is available only for cleartext HTTP/1", 0);
    return 0;
}

void h2o_log_register(h2o_hostconf_t *hostconf)
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, H2O_LOG_ENDPOINT, 0);
    struct st_h2o_log_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_req = on_req;
}
