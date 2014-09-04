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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
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
    size_t rlen;
    ssize_t rret;
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
    while ((rret = read(self->fd, self->buf, rlen)) == -1 && errno == EINTR)
        ;
    if (rret == -1) {
        is_final = 1;
        goto Exit;
    }
    self->bytesleft -= rret;
    is_final = self->bytesleft == 0;

    /* send */
    buf.base = self->buf;
    buf.len = rret;
    h2o_send(req, &buf, 1, is_final);

Exit:
    if (is_final)
        close(self->fd);
}

int h2o_send_file(h2o_req_t *req, int status, const char *reason, const char *path, uv_buf_t *mime_type)
{
    struct sendfile_t *self;
    uv_buf_t mime_type_buf;
    int fd;
    struct stat st;
    size_t bufsz;

    if (mime_type == NULL)
        *(mime_type = &mime_type_buf) = h2o_get_mimetype(&req->conn->ctx->mimemap, h2o_get_filext(path, strlen(path)));

    /* open file and stat */
    if ((fd = open(path, O_RDONLY)) == -1)
        return -1;
    if (fstat(fd, &st) != 0) {
        assert(!"FIMXE");
        close(fd);
        return -1;
    }

    /* build response */
    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = st.st_size;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, mime_type->base, mime_type->len);

    /* instantiate the generator */
    bufsz = MAX_BUF_SIZE;
    if (st.st_size < bufsz)
        bufsz = st.st_size;
    self = (void*)h2o_start_response(req, offsetof(struct sendfile_t, buf) + bufsz);
    self->super.proceed = sendfile_proceed;
    self->fd = fd;
    self->req = req;
    self->bytesleft = st.st_size;

    /* send data */
    sendfile_proceed(&self->super, req, 0);

    return 0;
}
