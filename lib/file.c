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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "h2o.h"

#define MAX_BUF_SIZE 65536

struct st_h2o_sendfile_generator_t {
    h2o_generator_t super;
    int fd;
    h2o_req_t *req;
    size_t bytesleft;
    char last_modified_buf[H2O_TIMESTR_RFC1123_LEN + 1];
    char etag_buf[sizeof("\"deadbeef-deadbeefdeadbeef\"")];
    size_t etag_len;
    char buf[1];
};

struct st_h2o_file_handler_t {
    h2o_handler_t super;
    h2o_buf_t virtual_path; /* has "/" appended at last */
    h2o_buf_t real_path; /* has "/" appended at last */
    h2o_buf_t index_file;
};

static void do_close(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void*)_self;
    close(self->fd);
}

static void do_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void*)_self;
    size_t rlen;
    ssize_t rret;
    h2o_buf_t vec;
    int is_final;

    /* read the file */
    rlen = self->bytesleft;
    if (rlen > MAX_BUF_SIZE)
        rlen = MAX_BUF_SIZE;
    while ((rret = read(self->fd, self->buf, rlen)) == -1 && errno == EINTR)
        ;
    if (rret == -1) {
        is_final = 1;
        req->http1_is_persistent = 0; /* FIXME need a better interface to dispose an errored response w. content-length */
        h2o_send(req, NULL, 0, 1);
        do_close(&self->super, req);
        return;
    }
    self->bytesleft -= rret;
    is_final = self->bytesleft == 0;

    /* send (and close if done) */
    vec.base = self->buf;
    vec.len = rret;
    h2o_send(req, &vec, 1, is_final);
    if (is_final)
        do_close(&self->super, req);
}

static struct st_h2o_sendfile_generator_t *create_generator(h2o_mempool_t *pool, const char *path)
{
    struct st_h2o_sendfile_generator_t *self;
    int fd;
    struct stat st;
    size_t bufsz;

    if ((fd = open(path, O_RDONLY)) == -1)
        return NULL;
    if (fstat(fd, &st) != 0) {
        assert(!"FIMXE");
        close(fd);
        return NULL;
    }

    bufsz = MAX_BUF_SIZE;
    if (st.st_size < bufsz)
        bufsz = st.st_size;
    self = h2o_mempool_alloc(pool, offsetof(struct st_h2o_sendfile_generator_t, buf) + bufsz);
    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->fd = fd;
    self->req = NULL;
    self->bytesleft = st.st_size;

    h2o_time2str_rfc1123(self->last_modified_buf, st.st_mtime);
    self->etag_len = sprintf(self->etag_buf, "\"%08x-%zx\"", (unsigned)st.st_mtime, (size_t)st.st_size);

    return self;
}

static void do_send_file(struct st_h2o_sendfile_generator_t *self, h2o_req_t *req, int status, const char *reason, h2o_buf_t mime_type)
{
    /* link the request */
    self->req = req;

    /* setup response */
    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = self->bytesleft;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, mime_type.base, mime_type.len);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LAST_MODIFIED, self->last_modified_buf, H2O_TIMESTR_RFC1123_LEN);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ETAG, self->etag_buf, self->etag_len);

    /* send data */
    h2o_start_response(req, &self->super);
    do_proceed(&self->super, req);
}

int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_buf_t mime_type)
{
    struct st_h2o_sendfile_generator_t *self;

    if ((self = create_generator(&req->pool, path)) == NULL)
        return -1;
    do_send_file(self, req, status, reason, mime_type);
    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct st_h2o_file_handler_t *self = (void*)_self;
    h2o_buf_t vpath, mime_type;
    char *dir_path;
    size_t dir_path_len;
    struct st_h2o_sendfile_generator_t *generator;
    size_t if_modified_since_header_index, if_none_match_header_index;

    /* only accept GET (TODO accept HEAD as well) */
    if (! h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    /* prefix match */
    if (req->path.len < self->virtual_path.len
        || memcmp(req->path.base, self->virtual_path.base, self->virtual_path.len) != 0)
        return -1;

    /* normalize path */
    vpath = h2o_normalize_path(&req->pool, req->path.base, req->path.len);
    if (vpath.len > PATH_MAX)
        return -1;

    /* build path */
    dir_path = alloca(
        self->real_path.len
        + (vpath.len - 1) /* exclude "/" at the head */
        + self->index_file.len
        + 1);
    dir_path_len = 0;
    memcpy(dir_path + dir_path_len, self->real_path.base, self->real_path.len);
    dir_path_len += self->real_path.len;
    memcpy(dir_path + dir_path_len, vpath.base + 1, vpath.len - 1);
    dir_path_len += vpath.len - 1;
    if (dir_path[dir_path_len - 1] == '/') {
        memcpy(dir_path + dir_path_len, self->index_file.base, self->index_file.len);
        dir_path_len += self->index_file.len;
    }
    dir_path[dir_path_len] = '\0';

    /* build generator (or return an error response) */
    if ((generator = create_generator(&req->pool, dir_path)) == NULL) {
        if (errno == ENOENT) {
            h2o_send_error(req, 404, "File Not Found", "file not found");
        } else {
            h2o_send_error(req, 403, "Access Forbidden", "access forbidden");
        }
        return 0;
    }

    if ((if_none_match_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_NONE_MATCH, SIZE_MAX)) != -1) {
        h2o_buf_t *if_none_match = &req->headers.entries[if_none_match_header_index].value;
        if (h2o_memis(if_none_match->base, if_none_match->len, generator->etag_buf, generator->etag_len))
            goto NotModified;
    } else if ((if_modified_since_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_MODIFIED_SINCE, SIZE_MAX)) != -1) {
        h2o_buf_t *if_modified_since = &req->headers.entries[if_modified_since_header_index].value;
        if (h2o_memis(if_modified_since->base, if_modified_since->len, generator->last_modified_buf, H2O_TIMESTR_RFC1123_LEN))
            goto NotModified;
    }

    /* obtain mime type */
    mime_type = h2o_get_mimetype(&req->host_config->mimemap, h2o_get_filext(dir_path, dir_path_len));

    /* return file */
    do_send_file(generator, req, 200, "OK", mime_type);
    return 0;

NotModified:
    req->res.status = 304;
    req->res.reason = "Not Modified";
    h2o_send_inline(req, NULL, 0);
    do_close(&generator->super, req);
    return 0;
}

static void on_dispose(h2o_handler_t *_self)
{
    struct st_h2o_file_handler_t *self = (void*)_self;

    free(self->virtual_path.base);
    free(self->real_path.base);
    free(self->index_file.base);
}

static h2o_buf_t append_slash_and_dup(const char *path)
{
    char *buf;
    size_t path_len = strlen(path);
    int needs_slash = 0;

    if (path_len == 0 || path[path_len - 1] != '/')
        needs_slash = 1;
    buf = h2o_malloc(path_len + 1 + needs_slash);
    memcpy(buf, path, path_len);
    if (needs_slash)
        buf[path_len++] = '/';
    buf[path_len] = '\0';

    return h2o_buf_init(buf, path_len);
}

void h2o_file_register(h2o_hostconf_t *host_config, const char *virtual_path, const char *real_path, const char *index_file)
{
    struct st_h2o_file_handler_t *self = (void*)h2o_create_handler(host_config, sizeof(*self));

    self->super.dispose = on_dispose;
    self->super.on_req = on_req;

    self->virtual_path = append_slash_and_dup(virtual_path);
    self->real_path = append_slash_and_dup(real_path);
    self->index_file = h2o_strdup(NULL, index_file, SIZE_MAX);
}
