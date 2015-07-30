/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Domingo Alvarez Duarte,
 *                         Tatsuhiko Kubo, Nick Desaulniers, Marc Hoersken,
 *                         Justin Zhu
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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "h2o.h"

#define MAX_BUF_SIZE 65000
#define BOUNDARY_SIZE 20
#define FIXED_PART_SIZE (sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("\r\nContent-Range: bytes=-/\r\nContent-Type: \r\n\r\n") - 1)

struct st_h2o_sendfile_generator_t {
    h2o_generator_t super;
    int fd;
    h2o_req_t *req;
    size_t bytesleft;
    struct {
        uint64_t packed;
        char buf[H2O_TIMESTR_RFC1123_LEN + 1];
    } last_modified;
    char etag_buf[sizeof("\"deadbeef-deadbeefdeadbeef\"")];
    size_t etag_len;
    char is_gzip;
    char send_vary;
    char *buf;
    struct {
        size_t filesize;
        size_t range_count;
        size_t *range_infos;  /* size_t shows in pair. first is start offset, then length */
        h2o_iovec_t boundary; /* boundary used for multipart/byteranges */
        h2o_iovec_t mimetype; /* original mimetype for multipart */
        size_t current_range; /* range that processing now */
    } ranged;
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

static uint64_t time2packed(struct tm *tm)
{
    return (uint64_t)(tm->tm_year + 1900) << 40 /* year:  24-bits */
           | (uint64_t)tm->tm_mon << 32         /* month:  8-bits */
           | (uint64_t)tm->tm_mday << 24        /* mday:   8-bits */
           | (uint64_t)tm->tm_hour << 16        /* hour:   8-bits */
           | (uint64_t)tm->tm_min << 8          /* min:    8-bits */
           | (uint64_t)tm->tm_sec;              /* sec:    8-bits */
}

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

static void do_multirange_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    size_t rlen, used_buf = 0;
    ssize_t rret, vecarrsize;
    h2o_iovec_t vec[2];
    int is_finished;

    if (self->bytesleft == 0) {
        size_t *range_cur = self->ranged.range_infos + 2 * self->ranged.current_range;
        size_t range_end = *range_cur + *(range_cur + 1) - 1;
        if (H2O_LIKELY(self->ranged.current_range != 0))
            used_buf =
                sprintf(self->buf, "\r\n--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zd-%zd/%zd\r\n\r\n",
                        self->ranged.boundary.base, self->ranged.mimetype.base, *range_cur, range_end, self->ranged.filesize);
        else
            used_buf =
                sprintf(self->buf, "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zd-%zd/%zd\r\n\r\n",
                        self->ranged.boundary.base, self->ranged.mimetype.base, *range_cur, range_end, self->ranged.filesize);
        self->ranged.current_range++;
        rret = lseek(self->fd, *range_cur, SEEK_SET);
        if (rret == -1)
            goto Error;
        self->bytesleft = *++range_cur;
    }
    rlen = self->bytesleft;
    if (rlen + used_buf > MAX_BUF_SIZE)
        rlen = MAX_BUF_SIZE - used_buf;
    while ((rret = read(self->fd, self->buf + used_buf, rlen)) == -1 && errno == EINTR)
        ;
    if (rret == -1)
        goto Error;
    self->bytesleft -= rret;

    vec[0].base = self->buf;
    vec[0].len = rret + used_buf;
    if (self->ranged.current_range == self->ranged.range_count && self->bytesleft == 0) {
        vec[1].base = h2o_mem_alloc_pool(&req->pool, sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("--\r\n"));
        vec[1].len = sprintf(vec[1].base, "\r\n--%s--\r\n", self->ranged.boundary.base);
        vecarrsize = 2;
        is_finished = 1;
    } else {
        vecarrsize = 1;
        is_finished = 0;
    }
    h2o_send(req, vec, vecarrsize, is_finished);
    return;

Error:
    req->http1_is_persistent = 0;
    h2o_send(req, NULL, 0, 1);
    do_close(&self->super, req);
    return;
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
    struct tm last_modified_gmt;

    *is_dir = 0;

    if ((flags & H2O_FILE_FLAG_SEND_GZIP) != 0 && req->version >= 0x101) {
        ssize_t header_index;
        if ((header_index = h2o_find_header(&req->headers, H2O_TOKEN_ACCEPT_ENCODING, -1)) != -1 &&
            h2o_contains_token(req->headers.entries[header_index].value.base, req->headers.entries[header_index].value.len,
                               H2O_STRLIT("gzip"), ',')) {
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
    self->ranged.range_count = 0;
    self->ranged.range_infos = NULL;

    gmtime_r(&st.st_mtime, &last_modified_gmt);
    self->last_modified.packed = time2packed(&last_modified_gmt);
    h2o_time2str_rfc1123(self->last_modified.buf, &last_modified_gmt);
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

    if (self->ranged.range_count > 1) {
        mime_type.base = h2o_mem_alloc_pool(&req->pool, 52);
        mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
    }
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, mime_type.base, mime_type.len);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LAST_MODIFIED, self->last_modified.buf, H2O_TIMESTR_RFC1123_LEN);
    if (self->etag_len != 0)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ETAG, self->etag_buf, self->etag_len);
    if (self->send_vary)
        h2o_add_header_token(&req->pool, &req->res.headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
    if (self->is_gzip)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, H2O_STRLIT("gzip"));
    if (self->ranged.range_count == 0)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ACCEPT_RANGES, H2O_STRLIT("bytes"));
    else if (self->ranged.range_count == 1) {
        h2o_iovec_t content_range;
        content_range.base = h2o_mem_alloc_pool(&req->pool, 128);
        content_range.len = sprintf(content_range.base, "bytes %zd-%zd/%zd", self->ranged.range_infos[0],
                                    self->ranged.range_infos[0] + self->ranged.range_infos[1] - 1, self->ranged.filesize);
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, content_range.base, content_range.len);
    }

    /* special path for cases where we do not need to send any data */
    if (!is_get || self->bytesleft == 0) {
        static h2o_generator_t generator = {NULL, NULL};
        h2o_start_response(req, &generator);
        h2o_send(req, NULL, 0, 1);
        do_close(&self->super, req);
        return;
    }

    /* send data */
    h2o_start_response(req, &self->super);

    if (self->ranged.range_count == 1) {
        ssize_t rret;
        rret = lseek(self->fd, self->ranged.range_infos[0], SEEK_SET);
        if (rret == -1) {
            req->http1_is_persistent = 0;
            h2o_send(req, NULL, 0, 1);
            do_close(&self->super, req);
            return;
        }
    }
    if (req->_ostr_top->start_pull != NULL && self->ranged.range_count < 2) {
        req->_ostr_top->start_pull(req->_ostr_top, do_pull);
    } else {
        size_t bufsz = MAX_BUF_SIZE;
        if (self->bytesleft < bufsz)
            bufsz = self->bytesleft;
        self->buf = h2o_mem_alloc_pool(&req->pool, bufsz);
        if (self->ranged.range_count < 2)
            do_proceed(&self->super, req);
        else {
            self->bytesleft = 0;
            self->super.proceed = do_multirange_proceed;
            do_multirange_proceed(&self->super, req);
        }
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

static int send_dir_listing(h2o_req_t *req, const char *path, size_t path_len, int is_get)
{
    static h2o_generator_t generator = {NULL, NULL};
    DIR *dp;
    h2o_buffer_t *body;
    h2o_iovec_t bodyvec;

    /* build html */
    if ((dp = opendir(path)) == NULL)
        return -1;
    body = build_dir_listing_html(&req->pool, req->path_normalized, dp);
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

static size_t *process_range(h2o_mem_pool_t *pool, h2o_iovec_t *range_value, size_t file_size, size_t *ret)
{
#define CHECK_EOF()                                                                                                                \
    if (buf == buf_end)                                                                                                            \
        return NULL;

#define CHECK_OVERFLOW(range)                                                                                                      \
    if (range == SIZE_MAX)                                                                                                         \
        return NULL;

    size_t range_start = SIZE_MAX, range_count = 0;
    char *buf = range_value->base, *buf_end = buf + range_value->len;
    int needs_comma = 0;
    H2O_VECTOR(size_t) ranges = {};

    if (range_value->len < 6 || memcmp(buf, "bytes=", 6) != 0)
        return NULL;

    buf += 6;
    CHECK_EOF();

    /* most range requests contain only one range */
    do {
        while (1) {
            if (*buf != ',') {
                if (needs_comma)
                    return NULL;
                break;
            }
            needs_comma = 0;
            buf++;
            while (H2O_UNLIKELY(*buf == ' ') || H2O_UNLIKELY(*buf == '\t')) {
                buf++;
                CHECK_EOF();
            }
        }
        if (H2O_UNLIKELY(buf == buf_end))
            break;
        if (H2O_LIKELY((range_start = h2o_strtosizefwd(&buf, buf_end - buf)) != SIZE_MAX)) {
            CHECK_EOF();
            if (*buf++ != '-')
                return NULL;
            range_count = h2o_strtosizefwd(&buf, buf_end - buf);
            if (H2O_UNLIKELY(range_start >= file_size)) {
                range_start = SIZE_MAX;
            } else if (H2O_LIKELY(range_count != SIZE_MAX)) {
                if (H2O_UNLIKELY(range_count > file_size - 1))
                    range_count = file_size - 1;
                if (H2O_LIKELY(range_start <= range_count))
                    range_count -= range_start - 1;
                else
                    range_start = SIZE_MAX;
            } else {
                range_count = file_size - range_start;
            }
        } else if (H2O_LIKELY(*buf++ == '-')) {
            CHECK_EOF();
            range_count = h2o_strtosizefwd(&buf, buf_end - buf);
            if (H2O_UNLIKELY(range_count == SIZE_MAX))
                return NULL;
            if (H2O_LIKELY(range_count != 0)) {
                if (H2O_UNLIKELY(range_count > file_size))
                    range_count = file_size;
                range_start = file_size - range_count;
            } else {
                range_start = SIZE_MAX;
            }
        } else {
            return NULL;
        }

        if (H2O_LIKELY(range_start != SIZE_MAX)) {
            h2o_vector_reserve(pool, (void *)&ranges, sizeof(ranges.entries[0]), ranges.size + 2);
            ranges.entries[ranges.size++] = range_start;
            ranges.entries[ranges.size++] = range_count;
        }
        if (buf != buf_end)
            while (H2O_UNLIKELY(*buf == ' ') || H2O_UNLIKELY(*buf == '\t')) {
                buf++;
                CHECK_EOF();
            }
        needs_comma = 1;
    } while (H2O_UNLIKELY(buf < buf_end));
    *ret = ranges.size / 2;
    return ranges.entries;
#undef CHECK_EOF
#undef CHECK_OVERFLOW
}

static void gen_rand_string(h2o_iovec_t *s)
{
    int i;
    static const char alphanum[] = "0123456789"
                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";

    for (i = 0; i < s->len; ++i) {
        s->base[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s->base[s->len] = 0;
}

static int delegate_dynamic_request(h2o_req_t *req, size_t url_path_len, const char *local_path, size_t local_path_len,
                                    h2o_mimemap_type_t *mime_type)
{
    h2o_filereq_t *filereq;
    h2o_handler_t *handler;

    assert(mime_type->data.dynamic.pathconf.handlers.size == 1);

    filereq = h2o_mem_alloc_pool(&req->pool, sizeof(*filereq));
    filereq->url_path_len = url_path_len;
    filereq->local_path = h2o_strdup(&req->pool, local_path, local_path_len);

    req->pathconf = &mime_type->data.dynamic.pathconf;
    req->filereq = filereq;

    handler = mime_type->data.dynamic.pathconf.handlers.entries[0];
    return handler->on_req(handler, req);
}

static int try_dynamic_request(h2o_file_handler_t *self, h2o_req_t *req, char *rpath, size_t rpath_len)
{
    /* we have full local path in {rpath,rpath_len}, and need to split it into name and path_info */
    struct stat st;
    size_t slash_at = self->real_path.len;

    while (1) {
        /* find the next slash (or return -1 if failed) */
        for (++slash_at;; ++slash_at) {
            if (slash_at >= rpath_len)
                return -1;
            if (rpath[slash_at] == '/')
                break;
        }
        /* change the slash to '\0', and check if the file exists */
        rpath[slash_at] = '\0';
        if (stat(rpath, &st) != 0)
            return -1;
        if (!S_ISDIR(st.st_mode))
            break;
        /* restore slash, and continue the search */
        rpath[slash_at] = '/';
    }

    /* file found! */
    h2o_mimemap_type_t *mime_type = h2o_mimemap_get_type(self->mimemap, h2o_get_filext(rpath, slash_at));
    switch (mime_type->type) {
    case H2O_MIMEMAP_TYPE_MIMETYPE:
        return -1;
    case H2O_MIMEMAP_TYPE_DYNAMIC:
        return delegate_dynamic_request(req, req->pathconf->path.len + slash_at - self->real_path.len, rpath, slash_at, mime_type);
    }
}

static void send_method_not_allowed(h2o_req_t *req)
{
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ALLOW, H2O_STRLIT("GET, HEAD"));
    h2o_send_error(req, 405, "Method Not Allowed", "method not allowed", H2O_SEND_ERROR_KEEP_HEADERS);
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    h2o_file_handler_t *self = (void *)_self;
    h2o_mimemap_type_t *mime_type;
    char *rpath;
    size_t rpath_len, req_path_prefix;
    struct st_h2o_sendfile_generator_t *generator = NULL;
    size_t if_modified_since_header_index, if_none_match_header_index;
    size_t range_header_index;
    int is_dir;
    enum { METHOD_IS_GET, METHOD_IS_HEAD, METHOD_IS_OTHER } method_type;

    /* only accept GET and HEAD */
    if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET"))) {
        method_type = METHOD_IS_GET;
    } else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"))) {
        method_type = METHOD_IS_HEAD;
    } else {
        method_type = METHOD_IS_OTHER;
    }

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
                h2o_iovec_t dest = h2o_concat(&req->pool, req->path_normalized, *index_file, h2o_iovec_init(H2O_STRLIT("/")));
                h2o_send_redirect(req, 301, "Moved Permantently", dest.base, dest.len);
                return 0;
            }
            if (errno != ENOENT)
                break;
        }
        if (index_file->base == NULL && (self->flags & H2O_FILE_FLAG_DIR_LISTING) != 0) {
            rpath[rpath_len] = '\0';
            if (method_type == METHOD_IS_OTHER) {
                send_method_not_allowed(req);
                return 0;
            }
            if (send_dir_listing(req, rpath, rpath_len, method_type == METHOD_IS_GET) == 0)
                return 0;
        }
    } else {
        rpath[rpath_len] = '\0';
        if ((generator = create_generator(req, rpath, rpath_len, &is_dir, self->flags)) != NULL)
            goto Opened;
        if (is_dir) {
            h2o_iovec_t dest = h2o_concat(&req->pool, req->path_normalized, h2o_iovec_init(H2O_STRLIT("/")));
            h2o_send_redirect(req, 301, "Moved Permanently", dest.base, dest.len);
            return 0;
        }
    }
    /* failed to open */

    if (errno == ENFILE || errno == EMFILE) {
        h2o_send_error(req, 503, "Service Unavailable", "please try again later", 0);
    } else {
        if (h2o_mimemap_has_dynamic_type(self->mimemap) && try_dynamic_request(self, req, rpath, rpath_len) == 0)
            return 0;
        if (errno == ENOENT) {
            return -1;
        } else {
            h2o_send_error(req, 403, "Access Forbidden", "access forbidden", 0);
        }
    }
    return 0;

Opened:
    if ((if_none_match_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_NONE_MATCH, SIZE_MAX)) != -1) {
        h2o_iovec_t *if_none_match = &req->headers.entries[if_none_match_header_index].value;
        if (h2o_memis(if_none_match->base, if_none_match->len, generator->etag_buf, generator->etag_len))
            goto NotModified;
    } else if ((if_modified_since_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_MODIFIED_SINCE, SIZE_MAX)) != -1) {
        h2o_iovec_t *ims_vec = &req->headers.entries[if_modified_since_header_index].value;
        struct tm ims_tm;
        if (h2o_time_parse_rfc1123(ims_vec->base, ims_vec->len, &ims_tm) == 0 &&
            generator->last_modified.packed <= time2packed(&ims_tm))
            goto NotModified;
    }

    /* obtain mime type */
    mime_type = h2o_mimemap_get_type(self->mimemap, h2o_get_filext(rpath, rpath_len));
    switch (mime_type->type) {
    case H2O_MIMEMAP_TYPE_MIMETYPE:
        break;
    case H2O_MIMEMAP_TYPE_DYNAMIC:
        do_close(&generator->super, req);
        return delegate_dynamic_request(req, req->path_normalized.len, rpath, rpath_len, mime_type);
    }

    /* only allow GET or POST for static files */
    if (method_type == METHOD_IS_OTHER) {
        do_close(&generator->super, req);
        send_method_not_allowed(req);
        return 0;
    }

    /* check if range request */
    if ((range_header_index = h2o_find_header(&req->headers, H2O_TOKEN_RANGE, SIZE_MAX)) != -1) {
        h2o_iovec_t *range = &req->headers.entries[range_header_index].value;
        size_t *range_infos, range_count;
        range_infos = process_range(&req->pool, range, generator->bytesleft, &range_count);
        if (range_infos == NULL) {
            h2o_iovec_t content_range;
            content_range.base = h2o_mem_alloc_pool(&req->pool, 32);
            content_range.len = sprintf(content_range.base, "bytes */%zu", generator->bytesleft);
            h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, content_range.base, content_range.len);
            h2o_send_error(req, 416, "Request Range Not Satisfiable", "requested range not satisfiable",
                           H2O_SEND_ERROR_KEEP_HEADERS);
            goto Close;
        }
        generator->ranged.range_count = range_count;
        generator->ranged.range_infos = range_infos;
        generator->ranged.current_range = 0;
        generator->ranged.filesize = generator->bytesleft;

        /* set content-length according to range */
        if (range_count == 1)
            generator->bytesleft = range_infos[1];
        else {
            generator->ranged.mimetype = h2o_strdup(&req->pool, mime_type->data.mimetype.base, mime_type->data.mimetype.len);
            size_t final_content_len = 0, size_tmp = 0, size_fixed_each_part, i;
            generator->ranged.boundary.base = h2o_mem_alloc_pool(&req->pool, BOUNDARY_SIZE + 1);
            generator->ranged.boundary.len = BOUNDARY_SIZE;
            gen_rand_string(&generator->ranged.boundary);
            i = generator->bytesleft;
            while (i) {
                i /= 10;
                size_tmp++;
            }
            size_fixed_each_part = FIXED_PART_SIZE + mime_type->data.mimetype.len + size_tmp;
            for (i = 0; i < range_count; i++) {
                size_tmp = *range_infos++;
                if (size_tmp == 0)
                    final_content_len++;
                while (size_tmp) {
                    size_tmp /= 10;
                    final_content_len++;
                }

                size_tmp = *(range_infos - 1);
                final_content_len += *range_infos;

                size_tmp += *range_infos++ - 1;
                if (size_tmp == 0)
                    final_content_len++;
                while (size_tmp) {
                    size_tmp /= 10;
                    final_content_len++;
                }
            }
            final_content_len += sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("--\r\n") - 1 + size_fixed_each_part * range_count -
                                 (sizeof("\r\n") - 1);
            generator->bytesleft = final_content_len;
        }
        do_send_file(generator, req, 206, "Partial Content", mime_type->data.mimetype, method_type == METHOD_IS_GET);
        return 0;
    }

    if (req->path.len == 1 || (req->path.len >= 2 && memcmp(req->path.base, "/?", 2) == 0)) {
        /* is request to "/", set pushs */
        h2o_vector_reserve(NULL, (void *)&req->http2_push_paths, sizeof(req->http2_push_paths.entries[0]),
                           req->http2_push_paths.size + 13);
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/assets/css/bootstrap.css"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/assets/css/magnific-popup.css"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/assets/css/font-awesome.css"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/assets/css/header.css"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/assets/css/main.css"));
#if 0
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/jquery-1.11.0.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/jquery-ui.min.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/bootstrap.min.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/jquery.magnific-popup.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/shuffle.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/jquery.shapeshift.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/homepage.js"));
        req->http2_push_paths.entries[req->http2_push_paths.size++] = h2o_iovec_init(H2O_STRLIT("/js/profiler.js"));
#endif

    }

    /* return file */
    do_send_file(generator, req, 200, "OK", mime_type->data.mimetype, method_type == METHOD_IS_GET);
    return 0;

NotModified:
    req->res.status = 304;
    req->res.reason = "Not Modified";
    h2o_send_inline(req, NULL, 0);
Close:
    do_close(&generator->super, req);
    return 0;
}

static void on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    h2o_file_handler_t *self = (void *)_self;

    h2o_mimemap_on_context_init(self->mimemap, ctx);
}

static void on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    h2o_file_handler_t *self = (void *)_self;

    h2o_mimemap_on_context_dispose(self->mimemap, ctx);
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
    self->super.on_context_init = on_context_init;
    self->super.on_context_dispose = on_context_dispose;
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
