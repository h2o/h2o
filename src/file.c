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

#define MAX_BUF_SIZE 65536

struct sendfile_t {
    h2o_generator_t super;
    int fd;
    h2o_req_t *req;
    size_t bytesleft;
    char buf[1];
};

static void sendfile_proceed(h2o_generator_t *_self, h2o_req_t *req, int status)
{
    struct sendfile_t *self = (void*)_self;
    uv_fs_t fsreq;
    size_t rlen;
    uv_buf_t buf;
    int is_final;

    if (status != 0) {
        is_final = 1;
        goto Exit;
    }

    /* read the file */
    rlen = self->bytesleft;
    if (rlen > MAX_BUF_SIZE)
        rlen = MAX_BUF_SIZE;
    uv_fs_read(req->conn->ctx->loop, &fsreq, self->fd, self->buf, rlen, -1, NULL);
    uv_fs_req_cleanup(&fsreq);
    if (fsreq.result <= 0) {
        /* TODO notify the error downstream */
        is_final = 1;
        goto Exit;
    }
    self->bytesleft -= fsreq.result;
    is_final = self->bytesleft == 0;

    /* send */
    buf.base = self->buf;
    buf.len = fsreq.result;
    h2o_send(req, &buf, 1, is_final);

Exit:
    if (is_final) {
        uv_fs_close(req->conn->ctx->loop, &fsreq, self->fd, NULL);
        uv_fs_req_cleanup(&fsreq);
    }
}

int h2o_send_file(h2o_req_t *req, int status, const char *reason, const char *path, uv_buf_t *mime_type)
{
    struct sendfile_t *self;
    uv_buf_t mime_type_buf;
    int fd;
    uv_fs_t fsreq;
    size_t bufsz;
    size_t bytesleft;

    if (mime_type == NULL)
        *(mime_type = &mime_type_buf) = h2o_get_mimetype(&req->conn->ctx->mimemap, h2o_get_filext(path, strlen(path)));

    /* open file and stat */
    fd = uv_fs_open(req->conn->ctx->loop, &fsreq, path, O_RDONLY, 0, NULL);
    uv_fs_req_cleanup(&fsreq);
    if (fd == -1)
        return -1;
    uv_fs_fstat(req->conn->ctx->loop, &fsreq, fd, NULL);
    uv_fs_req_cleanup(&fsreq);
    bytesleft = fsreq.statbuf.st_size;

    /* build response */
    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = bytesleft;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, mime_type->base, mime_type->len);

    /* instantiate the generator */
    bufsz = MAX_BUF_SIZE;
    if (bytesleft < bufsz)
        bufsz = bytesleft;
    self = (void*)h2o_start_response(req, offsetof(struct sendfile_t, buf) + bufsz);
    self->super.proceed = sendfile_proceed;
    self->fd = fd;
    self->req = req;
    self->bytesleft = bytesleft;

    /* send data */
    sendfile_proceed(&self->super, req, 0);

    return 0;
}
