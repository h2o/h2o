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

struct st_h2o_default_access_log_t {
    h2o_access_log_t super;
    uv_file fd;
};

static void access_log(h2o_access_log_t *_self, h2o_req_t *req)
{
    struct st_h2o_default_access_log_t *self = (struct st_h2o_default_access_log_t*)_self;
    char peername[sizeof("255.255.255.255")];
    struct sockaddr sa;
    int sa_len = sizeof(sa);
    uv_buf_t line;
    uv_fs_t fsreq;

    if (req->conn->getpeername(req->conn, &sa, &sa_len) == 0 && sa.sa_family == AF_INET) {
        uint32_t addr = htonl(((struct sockaddr_in*)&sa)->sin_addr.s_addr);
        sprintf(peername, "%d.%d.%d.%d", addr >> 24, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255);
    } else {
        strcpy(peername, "-");
    }

    line = h2o_sprintf(
        &req->pool,
        "%s - - [%.*s] \"%.*s %.*s HTTP/%d.%d\" %d %llu\n",
        peername,
        (int)H2O_TIMESTR_LOG_LEN, req->processed_at.str->log,
        (int)req->method_len, req->method,
        (int)req->path_len, req->path,
        (int)(req->version >> 8),
        (int)(req->version & 255),
        req->res.status,
        (unsigned long long)req->bytes_sent);

    uv_fs_write(req->conn->ctx->loop, &fsreq, self->fd, line.base, line.len, -1, NULL);
    uv_fs_req_cleanup(&fsreq);
}

h2o_access_log_t *h2o_open_access_log(uv_loop_t *loop, const char *path)
{
    struct st_h2o_default_access_log_t *self = h2o_malloc(sizeof(*self));
    uv_fs_t fsreq;

    self->super.log = access_log;
    self->fd = uv_fs_open(loop, &fsreq, path, O_CREAT | O_WRONLY | O_APPEND, 0644, NULL);
    uv_fs_req_cleanup(&fsreq);
    if (self->fd == -1)
        return NULL;

    return &self->super;
}
