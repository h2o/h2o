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

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct sockaddr_storage local;
    h2o_socket_t *sock;
    h2o_socket_export_t export_info;

    /* delegate the request to the next handler unless the request is accepted on a UNIX socket */
    if (!(req->conn->callbacks->get_sockname(req->conn, (struct sockaddr *)&local) > 0 && local.ss_family == AF_UNIX))
        return -1;

    if (req->conn->callbacks->steal_socket == NULL || (sock = req->conn->callbacks->steal_socket(req->conn)) == NULL) {
        h2o_send_error_400(req, "Bad Request", "h2olog is available only for cleartext HTTP/1", 0);
        return 0;
    }

    if (h2o_socket_export(sock, &export_info) != 0)
        h2o_fatal("h2o_socket_export failed");

    (void)write(export_info.fd, H2O_STRLIT("HTTP/1.1 200 OK\r\n\r\n"));

    /* register log fd after writing HTTP response, as log is written by multiple threads */
    if (ptls_log_add_fd(export_info.fd) != 0)
        h2o_fatal("failed to add fd to h2olog");

    return 0;
}

void h2o_log_register(h2o_hostconf_t *hostconf)
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, H2O_LOG_URI_PATH, 0);
    h2o_handler_t *self = h2o_create_handler(pathconf, sizeof(*self));
    self->on_req = on_req;
}
