/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Domingo Alvarez Duarte, Tatsuhiko Kubo, Nick Desaulniers, Marc Hoersken
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "h2o.h"

#define MAX_BUF_SIZE 65000

struct st_h2o_sendfile_generator_t {
    h2o_generator_t super;
    int fd;
    h2o_req_t *req;
    size_t bytesleft;
    char last_modified_buf[H2O_TIMESTR_RFC1123_LEN + 1];
    char etag_buf[sizeof("\"deadbeef-deadbeefdeadbeef\"")];
    size_t etag_len;
    char is_gzip;
    char send_vary;
    char *buf;
};

struct st_h2o_file_handler_t {
    h2o_handler_t super;
    h2o_iovec_t real_path; /* has "/" appended at last */
    h2o_mimemap_t *mimemap;
    int flags;
    size_t max_index_file_len;
    h2o_iovec_t index_files[1];
};

static const char *default_index_files[] = {"index.html", "index.htm", "index.txt", NULL};

const char **h2o_file_default_index_files = default_index_files;

#include "file/templates.c.h"

static void do_close(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    close(self->fd);
}

static void do_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    size_t rlen;
    ssize_t rret;
    h2o_iovec_t vec;
    int is_final;

    /* read the file */
    rlen = self->bytesleft;
    if (rlen > MAX_BUF_SIZE)
        rlen = MAX_BUF_SIZE;
    while ((rret = read(self->fd, self->buf, rlen)) == -1 && errno == EINTR)
        ;
    if (rret == -1) {
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

static int do_pull(h2o_generator_t *_self, h2o_req_t *req, h2o_iovec_t *buf)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    ssize_t rret;

    if (self->bytesleft < buf->len)
        buf->len = self->bytesleft;
    while ((rret = read(self->fd, buf->base, buf->len)) == -1 && errno == EINTR)
        ;
    if (rret <= 0) {
        req->http1_is_persistent = 0; /* FIXME need a better interface to dispose an errored response w. content-length */
        buf->len = 0;
        self->bytesleft = 0;
    } else {
        buf->len = rret;
        self->bytesleft -= rret;
    }

    if (self->bytesleft != 0)
        return 0;
    do_close(&self->super, req);
    return 1;
}

static struct st_h2o_sendfile_generator_t *create_generator(h2o_req_t *req, const char *path, size_t path_len, int *is_dir,
                                                            int flags)
{
    struct st_h2o_sendfile_generator_t *self;
    int fd, is_gzip;
    struct stat st;

    *is_dir = 0;

    if ((flags & H2O_FILE_FLAG_SEND_GZIP) != 0 && req->version >= 0x101) {
        ssize_t header_index;
        if ((header_index = h2o_find_header(&req->headers, H2O_TOKEN_ACCEPT_ENCODING, -1)) != -1 &&
            h2o_contains_token(req->headers.entries[header_index].value.base, req->headers.entries[header_index].value.len,
                               H2O_STRLIT("gzip"))) {
            char *gzpath = h2o_mem_alloc_pool(&req->pool, path_len + 4);
            memcpy(gzpath, path, path_len);
            strcpy(gzpath + path_len, ".gz");
            if ((fd = open(gzpath, O_RDONLY | O_CLOEXEC)) != -1) {
                is_gzip = 1;
                goto Opened;
            }
        }
    }
    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
        return NULL;
    is_gzip = 0;

Opened:
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return NULL;
    }
    if (S_ISDIR(st.st_mode)) {
        close(fd);
        *is_dir = 1;
        return NULL;
    }

    self = h2o_mem_alloc_pool(&req->pool, sizeof(*self));
    self->super.proceed = do_proceed;
    self->super.stop = do_close;
    self->fd = fd;
    self->req = NULL;
    self->bytesleft = st.st_size;

    h2o_time2str_rfc1123(self->last_modified_buf, st.st_mtime);
    if ((flags & H2O_FILE_FLAG_NO_ETAG) != 0) {
        self->etag_len = 0;
    } else {
        self->etag_len = sprintf(self->etag_buf, "\"%08x-%zx\"", (unsigned)st.st_mtime, (size_t)st.st_size);
    }
    self->is_gzip = is_gzip;
    self->send_vary = (flags & H2O_FILE_FLAG_SEND_GZIP) != 0;

    return self;
}

static void do_send_file(struct st_h2o_sendfile_generator_t *self, h2o_req_t *req, int status, const char *reason,
                         h2o_iovec_t mime_type, int is_get)
{
    /* link the request */
    self->req = req;

    /* setup response */
    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = self->bytesleft;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, mime_type.base, mime_type.len);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LAST_MODIFIED, self->last_modified_buf, H2O_TIMESTR_RFC1123_LEN);
    if (self->etag_len != 0)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ETAG, self->etag_buf, self->etag_len);
    if (self->send_vary)
        h2o_add_header_token(&req->pool, &req->res.headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
    if (self->is_gzip)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, H2O_STRLIT("gzip"));

    /* send headers */
    if (!is_get) {
        h2o_send_inline(req, NULL, 0);
        do_close(&self->super, req);
        return;
    }

    /* send data */
    h2o_start_response(req, &self->super);

    if (req->_ostr_top->start_pull != NULL) {
        req->_ostr_top->start_pull(req->_ostr_top, do_pull);
    } else {
        size_t bufsz = MAX_BUF_SIZE;
        if (self->bytesleft < bufsz)
            bufsz = self->bytesleft;
        self->buf = h2o_mem_alloc_pool(&req->pool, bufsz);
        do_proceed(&self->super, req);
    }
}

int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_iovec_t mime_type, int flags)
{
    struct st_h2o_sendfile_generator_t *self;
    int is_dir;

    if ((self = create_generator(req, path, strlen(path), &is_dir, flags)) == NULL)
        return -1;
    /* note: is_dir is not handled */
    do_send_file(self, req, status, reason, mime_type, 1);
    return 0;
}

static int redirect_to_dir(h2o_req_t *req, const char *path, size_t path_len)
{
    static h2o_generator_t generator = {NULL, NULL};
    static const h2o_iovec_t body_prefix = {
        H2O_STRLIT("<!DOCTYPE html><TITLE>301 Moved Permanently</TITLE><P>The document has moved <A HREF=\"")};
    static const h2o_iovec_t body_suffix = {H2O_STRLIT("\">here</A>")};

    h2o_iovec_t url;
    size_t alloc_size;
    h2o_iovec_t bufs[3];

    /* determine the size of the memory needed */
    alloc_size = sizeof(":///") + req->scheme.len + req->authority.len + path_len;

    /* allocate and build url */
    url.base = h2o_mem_alloc_pool(&req->pool, alloc_size);
    url.len = sprintf(url.base, "%.*s://%.*s%.*s/", (int)req->scheme.len, req->scheme.base, (int)req->authority.len,
                      req->authority.base, (int)path_len, path);
    assert(url.len + 1 == alloc_size);

    /* build response header */
    req->res.status = 301;
    req->res.reason = "Moved Permanently";
    memset(&req->res.headers, 0, sizeof(req->res.headers));
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LOCATION, url.base, url.len);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/html; charset=utf-8"));

    /* build response */
    bufs[0] = body_prefix;
    bufs[1] = h2o_htmlescape(&req->pool, url.base, url.len);
    bufs[2] = body_suffix;

    /* send */
    h2o_start_response(req, &generator);
    h2o_send(req, bufs, 3, 1);

    return 0;
}

static int send_dir_listing(h2o_req_t *req, const char *path, size_t path_len, int is_get)
{
    static h2o_generator_t generator = {NULL, NULL};
    DIR *dp;
    h2o_buffer_t *body;
    h2o_iovec_t bodyvec;

    /* build html */
    if ((dp = opendir(path)) == NULL)
        return -1;
    body = build_dir_listing_html(&req->pool, h2o_iovec_init(path, path_len), dp);
    closedir(dp);

    bodyvec = h2o_iovec_init(body->bytes, body->size);
    h2o_buffer_link_to_pool(body, &req->pool);

    /* send response */
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/html; charset=utf-8"));

    /* send headers */
    if (!is_get) {
        h2o_send_inline(req, NULL, 0);
        return 0;
    }

    /* send data */
    h2o_start_response(req, &generator);
    h2o_send(req, &bodyvec, 1, 1);
    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    h2o_file_handler_t *self = (void *)_self;
    h2o_iovec_t mime_type;
    char *rpath;
    size_t rpath_len, req_path_prefix;
    struct st_h2o_sendfile_generator_t *generator = NULL;
    size_t if_modified_since_header_index, if_none_match_header_index;
    int is_dir, is_get;

    /* only accept GET and HEAD */
    if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET"))) {
        is_get = 1;
    } else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"))) {
        is_get = 0;
    } else {
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ALLOW, H2O_STRLIT("GET, HEAD"));
        h2o_send_error(req, 405, "Method Not Allowed", "method not allowed", H2O_SEND_ERROR_KEEP_HEADERS);
        return 0;
    }

    /* do not handle non-normalized paths */
    if (req->path_normalized.base == NULL)
        return -1;

    /* build path (still unterminated at the end of the block) */
    req_path_prefix = req->pathconf->path.len;
    rpath = alloca(self->real_path.len + (req->path_normalized.len - req_path_prefix) + self->max_index_file_len + 1);
    rpath_len = 0;
    memcpy(rpath + rpath_len, self->real_path.base, self->real_path.len);
    rpath_len += self->real_path.len;
    memcpy(rpath + rpath_len, req->path_normalized.base + req_path_prefix, req->path_normalized.len - req_path_prefix);
    rpath_len += req->path_normalized.len - req_path_prefix;

    /* build generator (as well as terminating the rpath and its length upon success) */
    if (rpath[rpath_len - 1] == '/') {
        h2o_iovec_t *index_file;
        for (index_file = self->index_files; index_file->base != NULL; ++index_file) {
            memcpy(rpath + rpath_len, index_file->base, index_file->len);
            rpath[rpath_len + index_file->len] = '\0';
            if ((generator = create_generator(req, rpath, rpath_len + index_file->len, &is_dir, self->flags)) != NULL) {
                rpath_len += index_file->len;
                goto Opened;
            }
            if (is_dir) {
                /* note: apache redirects "path/" to "path/index.txt/" if index.txt is a dir */
                char *path = alloca(req->path.len + index_file->len + 1);
                size_t path_len =
                    sprintf(path, "%.*s%.*s", (int)req->path.len, req->path.base, (int)index_file->len, index_file->base);
                return redirect_to_dir(req, path, path_len);
            }
            if (errno != ENOENT)
                break;
        }
        if (index_file->base == NULL && (self->flags & H2O_FILE_FLAG_DIR_LISTING) != 0) {
            rpath[rpath_len] = '\0';
            if (send_dir_listing(req, rpath, rpath_len, is_get) == 0)
                return 0;
        }
    } else {
        rpath[rpath_len] = '\0';
        if ((generator = create_generator(req, rpath, rpath_len, &is_dir, self->flags)) != NULL)
            goto Opened;
        if (is_dir)
            return redirect_to_dir(req, req->path.base, req->path.len);
    }
    /* failed to open */
    if (errno == ENOENT) {
        h2o_send_error(req, 404, "File Not Found", "file not found", 0);
    } else {
        h2o_send_error(req, 403, "Access Forbidden", "access forbidden", 0);
    }
    return 0;

Opened:
    if ((if_none_match_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_NONE_MATCH, SIZE_MAX)) != -1) {
        h2o_iovec_t *if_none_match = &req->headers.entries[if_none_match_header_index].value;
        if (h2o_memis(if_none_match->base, if_none_match->len, generator->etag_buf, generator->etag_len))
            goto NotModified;
    } else if ((if_modified_since_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_MODIFIED_SINCE, SIZE_MAX)) != -1) {
        h2o_iovec_t *if_modified_since = &req->headers.entries[if_modified_since_header_index].value;
        if (h2o_memis(if_modified_since->base, if_modified_since->len, generator->last_modified_buf, H2O_TIMESTR_RFC1123_LEN))
            goto NotModified;
    }

    /* obtain mime type */
    mime_type = h2o_mimemap_get_type(self->mimemap, h2o_get_filext(rpath, rpath_len));

    /* return file */
    do_send_file(generator, req, 200, "OK", mime_type, is_get);
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
    h2o_file_handler_t *self = (void *)_self;
    size_t i;

    free(self->real_path.base);
    h2o_mem_release_shared(self->mimemap);
    for (i = 0; self->index_files[i].base != NULL; ++i)
        free(self->index_files[i].base);
}

h2o_file_handler_t *h2o_file_register(h2o_pathconf_t *pathconf, const char *real_path, const char **index_files,
                                      h2o_mimemap_t *mimemap, int flags)
{
    h2o_file_handler_t *self;
    size_t i;

    if (index_files == NULL)
        index_files = default_index_files;

    /* allocate memory */
    for (i = 0; index_files[i] != NULL; ++i)
        ;
    self =
        (void *)h2o_create_handler(pathconf, offsetof(h2o_file_handler_t, index_files[0]) + sizeof(self->index_files[0]) * (i + 1));

    /* setup callbacks */
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;

    /* setup attributes */
    self->real_path = h2o_strdup_slashed(NULL, real_path, SIZE_MAX);
    if (mimemap != NULL) {
        h2o_mem_addref_shared(mimemap);
        self->mimemap = mimemap;
    } else {
        self->mimemap = h2o_mimemap_create();
    }
    self->flags = flags;
    for (i = 0; index_files[i] != NULL; ++i) {
        self->index_files[i] = h2o_strdup(NULL, index_files[i], SIZE_MAX);
        if (self->max_index_file_len < self->index_files[i].len)
            self->max_index_file_len = self->index_files[i].len;
    }

    return self;
}

h2o_mimemap_t *h2o_file_get_mimemap(h2o_file_handler_t *handler)
{
    return handler->mimemap;
}
