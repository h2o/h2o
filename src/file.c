#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct sendfile_t {
    h2o_generator_t super;
    uv_fs_t *fsreq;
    int fd;
    h2o_req_t *req;
    size_t bytesleft;
    char buf[65536 - 4096];
};

static void sendfile_do_send(struct sendfile_t *self, uv_buf_t *bufs, size_t bufcnt, int is_final)
{
    h2o_req_t *req = self->req;

    if (is_final) {
        uv_fs_close(req->ctx->loop, self->fsreq, self->fd, NULL);
        uv_fs_req_cleanup(self->fsreq);
        self->fsreq = NULL;
        if (is_final == -1) {
            /* is closing due to an error */
            return;
        }
    }
    h2o_send(req, bufs, bufcnt, is_final);
}

static void sendfile_on_read(struct sendfile_t *self)
{
    uv_buf_t wbuf;

    uv_fs_req_cleanup(self->fsreq);

    switch (self->fsreq->result) {
    case -1: /* I/O error */
        /* TODO log */
        sendfile_do_send(self, NULL, 0, -1);
        return;
    case 0: /* EOF */
        /* TODO log (unexpected EOF) */
        sendfile_do_send(self, NULL, 0, -1);
        return;
    default:
        break;
    }

    wbuf.base = self->buf;
    wbuf.len = self->fsreq->result;

    self->bytesleft -= self->fsreq->result;
    sendfile_do_send(self, &wbuf, 1, self->bytesleft == 0);
}

static void sendfile_setup_next(struct sendfile_t *self)
{
#if 0 /* TODO: keep LRU of the filenames and use sync mode if is has recently been read (likely in memory) */
    uv_fs_read(self->req->ctx->loop, self->fsreq, self->fd, self->buf, sizeof(self->buf), -1, (uv_fs_cb)sendfile_on_read);
#else
    uv_fs_read(self->req->ctx->loop, self->fsreq, self->fd, self->buf, sizeof(self->buf), -1, NULL);
    sendfile_on_read(self);
#endif
}

static void sendfile_proceed(h2o_generator_t *_self, h2o_req_t *req, int status)
{
    struct sendfile_t *self = (void*)_self;

    if (status != 0) {
        sendfile_do_send(self, NULL, 0, -1);
        return;
    }

    sendfile_setup_next(self);
}

int h2o_send_file(h2o_req_t *req, int status, const char *reason, const char *path, uv_buf_t *mime_type)
{
    struct sendfile_t *self;
    uv_buf_t mime_type_buf;
    uv_fs_t *fsreq;
    int fd;
    size_t bytesleft;

    if (mime_type == NULL)
        *(mime_type = &mime_type_buf) = h2o_get_mimetype(&req->ctx->mimemap, h2o_get_filext(path, strlen(path)));

    /* open file and stat */
    fsreq = h2o_mempool_alloc(&req->pool, sizeof(*fsreq));
    fd = uv_fs_open(req->ctx->loop, fsreq, path, O_RDONLY, 0, NULL);
    uv_fs_req_cleanup(fsreq);
    if (fd == -1) {
        return -1; /* file not found */
    }

    /* stat the file */
    uv_fs_fstat(req->ctx->loop, fsreq, fd, NULL);
    uv_fs_req_cleanup(fsreq);
    bytesleft = fsreq->statbuf.st_size;

    /* build response */
    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = bytesleft;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, mime_type->base, mime_type->len);

    /* instantiate the generator */
    self = (void*)h2o_start_response(req, sizeof(*self));
    self->super.proceed = sendfile_proceed;
    self->fsreq = fsreq;
    self->fd = fd;
    self->req = req;
    self->bytesleft = bytesleft;

    /* send data */
    if (bytesleft != 0) {
        sendfile_setup_next(self);
    } else {
        sendfile_do_send(self, NULL, 0, 1);
    }

    return 0;
}
