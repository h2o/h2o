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

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    if (req->conn->callbacks->steal_socket == NULL)
        goto Error;

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
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, H2O_LOG_URI_PATH, 0);
    struct st_h2o_log_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_req = on_req;
}
