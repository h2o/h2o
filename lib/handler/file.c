/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Domingo Alvarez Duarte,
 *                         Tatsuhiko Kubo, Nick Desaulniers, Marc Hoersken,
 *                         Justin Zhu, Tatsuhiro Tsujikawa
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
#if defined(__linux__)
#include <sys/sendfile.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "h2o.h"
#if H2O_USE_IO_URING
#include "h2o/io_uring.h"
#endif

#define MAX_BUF_SIZE 65000
#define BOUNDARY_SIZE 20
#define FIXED_PART_SIZE (sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("\r\nContent-Range: bytes=-/\r\nContent-Type: \r\n\r\n") - 1)

struct st_h2o_sendfile_generator_t {
    h2o_generator_t super;
    struct {
        h2o_filecache_ref_t *ref;
        off_t off;
    } file;
    size_t bytesleft;
    h2o_iovec_t content_encoding;
    unsigned send_vary : 1;
    unsigned send_etag : 1;
    unsigned gunzip : 1;
    struct {
        char *multirange_buf; /* multi-range mode uses push */
        size_t filesize;
        size_t range_count;
        size_t *range_infos;  /* size_t shows in pair. first is start offset, then length */
        h2o_iovec_t boundary; /* boundary used for multipart/byteranges */
        h2o_iovec_t mimetype; /* original mimetype for multipart */
        size_t current_range; /* range that processing now */
    } ranged;
    struct {
        char last_modified[H2O_TIMESTR_RFC1123_LEN + 1];
        char etag[H2O_FILECACHE_ETAG_MAXLEN + 1];
    } header_bufs;
#if H2O_USE_IO_URING
    /**
     * back pointer to the request which is necessary for splicing async; becomes NULL when the generator is stopped
     */
    h2o_req_t *src_req;
    int splice_fds[2];
#endif
};

struct st_h2o_file_handler_t {
    h2o_handler_t super;
    h2o_iovec_t conf_path; /* has "/" appended at last */
    h2o_iovec_t real_path; /* has "/" appended at last */
    h2o_mimemap_t *mimemap;
    int flags;
    size_t max_index_file_len;
    h2o_iovec_t index_files[1];
};

struct st_h2o_specific_file_handler_t {
    h2o_handler_t super;
    h2o_iovec_t real_path;
    h2o_mimemap_type_t *mime_type;
    int flags;
};

struct st_gzip_decompress_t {
    h2o_ostream_t super;
    h2o_compress_context_t *decompressor;
};

static const char *default_index_files[] = {"index.html", "index.htm", "index.txt", NULL};

const char **h2o_file_default_index_files = default_index_files;

#include "file/templates.c.h"

static int tm_is_lessthan(struct tm *x, struct tm *y)
{
#define CMP(f)                                                                                                                     \
    if (x->f < y->f)                                                                                                               \
        return 1;                                                                                                                  \
    else if (x->f > y->f)                                                                                                          \
        return 0;
    CMP(tm_year);
    CMP(tm_mon);
    CMP(tm_mday);
    CMP(tm_hour);
    CMP(tm_min);
    CMP(tm_sec);
    return 0;
#undef CMP
}

static void close_file(struct st_h2o_sendfile_generator_t *self)
{
    if (self->file.ref != NULL) {
        h2o_filecache_close_file(self->file.ref);
        self->file.ref = NULL;
    }
#if H2O_USE_IO_URING
    if (self->splice_fds[0] != -1) {
        if (self->src_req != NULL) {
            h2o_context_return_spare_pipe(self->src_req->conn->ctx, self->splice_fds);
        } else {
            /* TODO return pipe upon abrupt close too? maybe that's not need */
            close(self->splice_fds[0]);
            close(self->splice_fds[1]);
        }
        self->splice_fds[0] = -1;
        self->splice_fds[1] = -1;
    }
#endif
}

static void on_generator_dispose(void *_self)
{
    struct st_h2o_sendfile_generator_t *self = _self;
    close_file(self);
}

#if H2O_USE_IO_URING

static void do_stop_async_splice(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    self->src_req = NULL;
}

static void do_proceed_on_splice_complete(h2o_io_uring_cmd_t *cmd)
{
    struct st_h2o_sendfile_generator_t *self = cmd->cb.data;

    if (self->src_req == NULL) {
        h2o_mem_release_shared(self);
        return;
    }

    h2o_mem_release_shared(self);

    if (cmd->result <= 0) {
        assert(cmd->result != -EINTR); /* could this ever happen? */
        h2o_send(self->src_req, NULL, 0, H2O_SEND_STATE_ERROR);
        return;
    }

    self->file.off += cmd->result;
    self->bytesleft -= cmd->result;

    h2o_send_from_pipe(self->src_req, self->splice_fds[0], cmd->result,
                       self->bytesleft != 0 ? H2O_SEND_STATE_IN_PROGRESS : H2O_SEND_STATE_FINAL);
}

#endif

static int do_pread(h2o_sendvec_t *src, void *dst, size_t len)
{
    struct st_h2o_sendfile_generator_t *self = (void *)src->cb_arg[0];
    uint64_t *file_chunk_at = &src->cb_arg[1];
    size_t bytes_read = 0;
    ssize_t rret;

    /* read */
    while (bytes_read < len) {
        while ((rret = pread(self->file.ref->fd, dst + bytes_read, len - bytes_read, *file_chunk_at)) == -1 && errno == EINTR)
            ;
        if (rret <= 0)
            return 0;
        bytes_read += rret;
        *file_chunk_at += rret;
        src->len -= rret;
    }

    return 1;
}

#if defined(__linux__)
static size_t do_sendfile(int sockfd, int filefd, off_t off, size_t len)
{
    off_t iooff = off;
    ssize_t ret;
    while ((ret = sendfile(sockfd, filefd, &iooff, len)) == -1 && errno == EINTR)
        ;
    if (ret <= 0)
        return ret == -1 && errno == EAGAIN ? 0 : SIZE_MAX;
    return ret;
}
#elif defined(__APPLE__)
static size_t do_sendfile(int sockfd, int filefd, off_t off, size_t len)
{
    off_t iolen = len;
    int ret;
    while ((ret = sendfile(filefd, sockfd, off, &iolen, NULL, 0)) != 0 && errno == EINTR)
        ;
    if (ret != 0 && errno != EAGAIN)
        return SIZE_MAX;
    return iolen;
}
#elif defined(__FreeBSD__)
static size_t do_sendfile(int sockfd, int filefd, off_t off, size_t len)
{
    off_t outlen;
    int ret;
    while ((ret = sendfile(filefd, sockfd, off, len, NULL, &outlen, 0)) != 0 && errno == EINTR)
        ;
    if (ret != 0 && errno != EAGAIN)
        return SIZE_MAX;
    return outlen;
}
#else
#define sendvec_sendfile NULL
#endif
#if !defined(sendvec_sendfile)
static size_t sendvec_sendfile(h2o_sendvec_t *src, int sockfd, size_t len)
{
    struct st_h2o_sendfile_generator_t *self = (void *)src->cb_arg[0];
    ssize_t bytes_sent = do_sendfile(sockfd, self->file.ref->fd, (off_t)src->cb_arg[1], len);
    if (bytes_sent > 0) {
        src->cb_arg[1] += bytes_sent;
        src->len -= bytes_sent;
    }
    return bytes_sent;
}
#endif

static void do_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    size_t bytes_to_send = self->bytesleft < H2O_PULL_SENDVEC_MAX_SIZE ? self->bytesleft : H2O_PULL_SENDVEC_MAX_SIZE;

    /* if io_uring is to be used, addref so that the self would not be released, then call `h2o_io_uring_splice_file` */
#if H2O_USE_IO_URING
    if (self->splice_fds[0] != -1) {
        h2o_mem_addref_shared(self);
        h2o_io_uring_splice(self->src_req->conn->ctx->loop, self->file.ref->fd, self->file.off, self->splice_fds[1], -1,
                            bytes_to_send, 0, do_proceed_on_splice_complete, self);
        return;
    }
#endif

    static const h2o_sendvec_callbacks_t sendvec_callbacks = {.read_ = do_pread, .send_ = sendvec_sendfile};
    h2o_sendvec_t vec = {
        .callbacks = &sendvec_callbacks, .len = bytes_to_send, .cb_arg[0] = (uint64_t)self, .cb_arg[1] = self->file.off};

    self->file.off += vec.len;
    self->bytesleft -= vec.len;

    h2o_sendvec(req, &vec, 1, self->bytesleft != 0 ? H2O_SEND_STATE_IN_PROGRESS : H2O_SEND_STATE_FINAL);
}

static void do_multirange_proceed(h2o_generator_t *_self, h2o_req_t *req)
{
    struct st_h2o_sendfile_generator_t *self = (void *)_self;
    size_t rlen, used_buf = 0;
    ssize_t rret, vecarrsize;
    h2o_iovec_t vec[2];
    h2o_send_state_t send_state;

    if (self->bytesleft == 0) {
        size_t *range_cur = self->ranged.range_infos + 2 * self->ranged.current_range;
        size_t range_end = *range_cur + *(range_cur + 1) - 1;
        if (H2O_LIKELY(self->ranged.current_range != 0))
            used_buf =
                sprintf(self->ranged.multirange_buf, "\r\n--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zd-%zd/%zd\r\n\r\n",
                        self->ranged.boundary.base, self->ranged.mimetype.base, *range_cur, range_end, self->ranged.filesize);
        else
            used_buf =
                sprintf(self->ranged.multirange_buf, "--%s\r\nContent-Type: %s\r\nContent-Range: bytes %zd-%zd/%zd\r\n\r\n",
                        self->ranged.boundary.base, self->ranged.mimetype.base, *range_cur, range_end, self->ranged.filesize);
        self->ranged.current_range++;
        self->file.off = *range_cur;
        self->bytesleft = *++range_cur;
    }
    rlen = self->bytesleft;
    if (rlen + used_buf > MAX_BUF_SIZE)
        rlen = MAX_BUF_SIZE - used_buf;
    while ((rret = pread(self->file.ref->fd, self->ranged.multirange_buf + used_buf, rlen, self->file.off)) == -1 && errno == EINTR)
        ;
    if (rret == -1)
        goto Error;
    self->file.off += rret;
    self->bytesleft -= rret;

    vec[0].base = self->ranged.multirange_buf;
    vec[0].len = rret + used_buf;
    if (self->ranged.current_range == self->ranged.range_count && self->bytesleft == 0) {
        vec[1].base = h2o_mem_alloc_pool(&req->pool, char, sizeof("\r\n--") - 1 + BOUNDARY_SIZE + sizeof("--\r\n"));
        vec[1].len = sprintf(vec[1].base, "\r\n--%s--\r\n", self->ranged.boundary.base);
        vecarrsize = 2;
        send_state = H2O_SEND_STATE_FINAL;
    } else {
        vecarrsize = 1;
        send_state = H2O_SEND_STATE_IN_PROGRESS;
    }
    h2o_send(req, vec, vecarrsize, send_state);
    return;

Error:
    h2o_send(req, NULL, 0, H2O_SEND_STATE_ERROR);
    return;
}

static struct st_h2o_sendfile_generator_t *create_generator(h2o_req_t *req, const char *path, size_t path_len, int *is_dir,
                                                            int flags)
{
    struct st_h2o_sendfile_generator_t *self;
    h2o_filecache_ref_t *fileref;
    h2o_iovec_t content_encoding = (h2o_iovec_t){NULL};
    unsigned gunzip = 0;

    *is_dir = 0;

    if ((flags & H2O_FILE_FLAG_SEND_COMPRESSED) != 0 && req->version >= 0x101) {
        int compressible_types = h2o_get_compressible_types(&req->headers);
        if (compressible_types != 0) {
            char *variant_path = h2o_mem_alloc_pool(&req->pool, *variant_path, path_len + sizeof(".gz"));
            memcpy(variant_path, path, path_len);
#define TRY_VARIANT(mask, enc, ext)                                                                                                \
    if ((compressible_types & mask) != 0) {                                                                                        \
        strcpy(variant_path + path_len, ext);                                                                                      \
        if ((fileref = h2o_filecache_open_file(req->conn->ctx->filecache, variant_path, O_RDONLY | O_CLOEXEC)) != NULL) {          \
            content_encoding = h2o_iovec_init(enc, sizeof(enc) - 1);                                                               \
            goto Opened;                                                                                                           \
        }                                                                                                                          \
    }
            TRY_VARIANT(H2O_COMPRESSIBLE_BROTLI, "br", ".br");
            TRY_VARIANT(H2O_COMPRESSIBLE_ZSTD, "zstd", ".zst");
            TRY_VARIANT(H2O_COMPRESSIBLE_GZIP, "gzip", ".gz");

            // Deprecated
            TRY_VARIANT(H2O_COMPRESSIBLE_ZSTD, "zstd", ".zstd");
#undef TRY_VARIANT
        }
    }
    if ((fileref = h2o_filecache_open_file(req->conn->ctx->filecache, path, O_RDONLY | O_CLOEXEC)) != NULL) {
        goto Opened;
    }
    if ((flags & H2O_FILE_FLAG_GUNZIP) != 0 && req->version >= 0x101) {
        char *variant_path = h2o_mem_alloc_pool(&req->pool, *variant_path, path_len + sizeof(".gz"));
        memcpy(variant_path, path, path_len);
        strcpy(variant_path + path_len, ".gz");
        if ((fileref = h2o_filecache_open_file(req->conn->ctx->filecache, variant_path, O_RDONLY | O_CLOEXEC)) != NULL) {
            gunzip = 1;
            goto Opened;
        }
    }
    return NULL;

Opened:
    if (S_ISDIR(fileref->st.st_mode)) {
        h2o_filecache_close_file(fileref);
        *is_dir = 1;
        return NULL;
    }

    self = h2o_mem_alloc_shared(&req->pool, sizeof(*self), on_generator_dispose);
    self->super.proceed = do_proceed;
    self->super.stop = NULL;
    self->file.ref = fileref;
    self->file.off = 0;
    self->bytesleft = self->file.ref->st.st_size;
    self->ranged.range_count = 0;
    self->ranged.range_infos = NULL;
    self->content_encoding = content_encoding;
    self->send_vary = (flags & H2O_FILE_FLAG_SEND_COMPRESSED) != 0;
    self->send_etag = (flags & H2O_FILE_FLAG_NO_ETAG) == 0;
    self->gunzip = gunzip;
#if H2O_USE_IO_URING
    int try_async_splice = (flags & H2O_FILE_FLAG_IO_URING) != 0 && self->bytesleft != 0;
    if (try_async_splice && h2o_context_new_pipe(req->conn->ctx, self->splice_fds)) {
        self->super.stop = do_stop_async_splice;
        self->src_req = req;
    } else {
        if (try_async_splice)
            h2o_req_log_error(req, "lib/handler/file.c", "failed to allocate a pipe for async I/O; falling back to blocking I/O");
        self->splice_fds[0] = -1;
        self->splice_fds[1] = -1;
    }
#endif

    return self;
}

static void add_headers_unconditional(struct st_h2o_sendfile_generator_t *self, h2o_req_t *req)
{
    /* RFC 7232 4.1: The server generating a 304 response MUST generate any of the following header fields that would have been sent
     * in a 200 (OK) response to the same request: Cache-Control, Content-Location, Date, ETag, Expires, and Vary (snip) a sender
     * SHOULD NOT generate representation metadata other than the above listed fields unless said metadata exists for the purpose of
     * guiding cache updates. */
    if (self->send_etag) {
        size_t etag_len = h2o_filecache_get_etag(self->file.ref, self->header_bufs.etag);
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ETAG, NULL, self->header_bufs.etag, etag_len);
    }
    if (self->send_vary)
        h2o_set_header_token(&req->pool, &req->res.headers, H2O_TOKEN_VARY, H2O_STRLIT("accept-encoding"));
}

static void send_decompressed(h2o_ostream_t *_self, h2o_req_t *req, h2o_sendvec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    if (inbufcnt == 0 && h2o_send_state_is_in_progress(state)) {
        h2o_ostream_send_next(_self, req, inbufs, inbufcnt, state);
        return;
    }

    struct st_gzip_decompress_t *self = (void *)_self;
    h2o_sendvec_t *outbufs;
    size_t outbufcnt;

    state = h2o_compress_transform(self->decompressor, req, inbufs, inbufcnt, state, &outbufs, &outbufcnt);
    h2o_ostream_send_next(&self->super, req, outbufs, outbufcnt, state);
}

static void do_send_file(struct st_h2o_sendfile_generator_t *self, h2o_req_t *req, int status, const char *reason,
                         h2o_iovec_t mime_type, h2o_mime_attributes_t *mime_attr, int is_get)
{
    /* setup response */
    req->res.status = status;
    req->res.reason = reason;
    req->res.content_length = self->gunzip ? SIZE_MAX : self->bytesleft;
    req->res.mime_attr = mime_attr;

    if (self->ranged.range_count > 1) {
        mime_type.base = h2o_mem_alloc_pool(&req->pool, char, 52);
        mime_type.len = sprintf(mime_type.base, "multipart/byteranges; boundary=%s", self->ranged.boundary.base);
    }
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, mime_type.base, mime_type.len);
    h2o_filecache_get_last_modified(self->file.ref, self->header_bufs.last_modified);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_LAST_MODIFIED, NULL, self->header_bufs.last_modified,
                   H2O_TIMESTR_RFC1123_LEN);
    add_headers_unconditional(self, req);
    if (self->content_encoding.base != NULL)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_ENCODING, NULL, self->content_encoding.base,
                       self->content_encoding.len);
    if (self->ranged.range_count == 0)
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ACCEPT_RANGES, NULL, H2O_STRLIT("bytes"));
    else if (self->ranged.range_count == 1) {
        h2o_iovec_t content_range;
        content_range.base = h2o_mem_alloc_pool(&req->pool, char, 128);
        content_range.len = sprintf(content_range.base, "bytes %zd-%zd/%zd", self->ranged.range_infos[0],
                                    self->ranged.range_infos[0] + self->ranged.range_infos[1] - 1, self->ranged.filesize);
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
    }

    /* special path for cases where we do not need to send any data */
    if (!is_get || self->bytesleft == 0) {
        static h2o_generator_t generator = {NULL, NULL};
        h2o_start_response(req, &generator);
        h2o_send(req, NULL, 0, H2O_SEND_STATE_FINAL);
        return;
    }

    /* send data */
    h2o_start_response(req, &self->super);

    /* dynamically setup gzip decompress ostream */
    if (self->gunzip) {
        struct st_gzip_decompress_t *decoder =
            (void *)h2o_add_ostream(req, H2O_ALIGNOF(*decoder), sizeof(*decoder), &req->_ostr_top);
        decoder->decompressor = h2o_compress_gunzip_open(&req->pool);
        decoder->super.do_send = send_decompressed;
        /* FIXME disable pull mode */
    }

    if (self->ranged.range_count == 1)
        self->file.off = self->ranged.range_infos[0];

    if (self->ranged.range_count < 2)
        do_proceed(&self->super, req);
    else {
        self->ranged.multirange_buf = h2o_mem_alloc_pool(&req->pool, char, MAX_BUF_SIZE);
        self->bytesleft = 0;
        self->super.proceed = do_multirange_proceed;
        do_multirange_proceed(&self->super, req);
    }
}

int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_iovec_t mime_type, int flags)
{
    struct st_h2o_sendfile_generator_t *self;
    int is_dir;

    if ((self = create_generator(req, path, strlen(path), &is_dir, flags)) == NULL)
        return -1;
    /* note: is_dir is not handled */
    do_send_file(self, req, status, reason, mime_type, NULL, 1);
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

    if (body == NULL) {
        h2o_send_error_503(req, "Service Unavailable", "please try again later", 0);
        return 0;
    }

    bodyvec = h2o_iovec_init(body->bytes, body->size);
    h2o_buffer_link_to_pool(body, &req->pool);

    /* send response */
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("text/html; charset=utf-8"));

    /* send headers */
    if (!is_get) {
        h2o_send_inline(req, NULL, 0);
        return 0;
    }

    /* send data */
    h2o_start_response(req, &generator);
    h2o_send(req, &bodyvec, 1, H2O_SEND_STATE_FINAL);
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
    H2O_VECTOR(size_t) ranges = {NULL};

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
            h2o_vector_reserve(pool, &ranges, ranges.size + 2);
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
        s->base[i] = alphanum[h2o_rand() % (sizeof(alphanum) - 1)];
    }

    s->base[s->len] = 0;
}

static int delegate_dynamic_request(h2o_req_t *req, h2o_iovec_t script_name, h2o_iovec_t path_info, const char *local_path,
                                    size_t local_path_len, h2o_mimemap_type_t *mime_type)
{
    h2o_filereq_t *filereq;

    assert(mime_type->data.dynamic.pathconf.handlers.size == 1);
    assert(mime_type->data.dynamic.pathconf._filters.size == 0);
    assert(mime_type->data.dynamic.pathconf._loggers.size == 0);

    /* setup CGI attributes (e.g., PATH_INFO) */
    filereq = h2o_mem_alloc_pool(&req->pool, *filereq, 1);
    filereq->script_name = script_name;
    filereq->path_info = path_info;
    filereq->local_path = h2o_strdup(&req->pool, local_path, local_path_len);
    req->filereq = filereq;

    /* apply environment */
    if (mime_type->data.dynamic.pathconf.env != NULL)
        h2o_req_apply_env(req, mime_type->data.dynamic.pathconf.env);

    /* call the dynamic handler while retaining current hostconf or pathconf; in other words, filters and loggers of current
     * path level is applied, rather than of the extension level */
    h2o_handler_t *handler = mime_type->data.dynamic.pathconf.handlers.entries[0];
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
    h2o_mimemap_type_t *mime_type = h2o_mimemap_get_type_by_extension(self->mimemap, h2o_get_filext(rpath, slash_at));
    switch (mime_type->type) {
    case H2O_MIMEMAP_TYPE_MIMETYPE:
        return -1;
    case H2O_MIMEMAP_TYPE_DYNAMIC: {
        h2o_iovec_t script_name = h2o_iovec_init(req->path_normalized.base, self->conf_path.len + slash_at - self->real_path.len);
        h2o_iovec_t path_info =
            h2o_iovec_init(req->path_normalized.base + script_name.len, req->path_normalized.len - script_name.len);
        return delegate_dynamic_request(req, script_name, path_info, rpath, slash_at, mime_type);
    }
    }
    h2o_fatal("unknown h2o_miemmap_type_t::type (%d)\n", (int)mime_type->type);
}

static void send_method_not_allowed(h2o_req_t *req)
{
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_ALLOW, NULL, H2O_STRLIT("GET, HEAD"));
    h2o_send_error_405(req, "Method Not Allowed", "method not allowed", H2O_SEND_ERROR_KEEP_HEADERS);
}

static int serve_with_generator(struct st_h2o_sendfile_generator_t *generator, h2o_req_t *req, h2o_iovec_t resolved_path,
                                const char *rpath, size_t rpath_len, h2o_mimemap_type_t *mime_type)
{
    enum { METHOD_IS_GET, METHOD_IS_HEAD, METHOD_IS_OTHER } method_type;
    size_t if_modified_since_header_index, if_none_match_header_index;
    size_t range_header_index, if_range_header_index;

    /* determine the method */
    if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET"))) {
        method_type = METHOD_IS_GET;
    } else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"))) {
        method_type = METHOD_IS_HEAD;
    } else {
        method_type = METHOD_IS_OTHER;
    }

    /* obtain mime type */
    if (mime_type->type == H2O_MIMEMAP_TYPE_DYNAMIC) {
        assert(generator->file.ref != NULL);
        close_file(generator);
        return delegate_dynamic_request(req, resolved_path, h2o_iovec_init(NULL, 0), rpath, rpath_len, mime_type);
    }
    assert(mime_type->type == H2O_MIMEMAP_TYPE_MIMETYPE);

    /* if-non-match and if-modified-since */
    if ((if_none_match_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_NONE_MATCH, -1)) != -1) {
        h2o_iovec_t *if_none_match = &req->headers.entries[if_none_match_header_index].value;
        char etag[H2O_FILECACHE_ETAG_MAXLEN + 1];
        size_t etag_len = h2o_filecache_get_etag(generator->file.ref, etag);
        if (h2o_filecache_compare_etag_strong(if_none_match->base, if_none_match->len, etag, etag_len))
            goto NotModified;
    } else if ((if_modified_since_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_MODIFIED_SINCE, -1)) != -1) {
        h2o_iovec_t *ims_vec = &req->headers.entries[if_modified_since_header_index].value;
        struct tm ims_tm, *last_modified_tm;
        if (h2o_time_parse_rfc1123(ims_vec->base, ims_vec->len, &ims_tm) == 0) {
            last_modified_tm = h2o_filecache_get_last_modified(generator->file.ref, NULL);
            if (!tm_is_lessthan(&ims_tm, last_modified_tm))
                goto NotModified;
        }
    }

    /* only allow GET or HEAD for static files */
    if (method_type == METHOD_IS_OTHER) {
        close_file(generator);
        send_method_not_allowed(req);
        return 0;
    }

    /* range request */
    if ((range_header_index = h2o_find_header(&req->headers, H2O_TOKEN_RANGE, -1)) != -1) {
        /* if range */
        if ((if_range_header_index = h2o_find_header(&req->headers, H2O_TOKEN_IF_RANGE, -1)) != -1) {
            h2o_iovec_t *if_range = &req->headers.entries[if_range_header_index].value;
            /* first try parse if-range as http-date */
            struct tm ir_tm, *last_modified_tm;
            if (h2o_time_parse_rfc1123(if_range->base, if_range->len, &ir_tm) == 0) {
                last_modified_tm = h2o_filecache_get_last_modified(generator->file.ref, NULL);
                if (tm_is_lessthan(&ir_tm, last_modified_tm))
                    goto EntireFile;
            } else { /* treat it as an e-tag */
                char etag[H2O_FILECACHE_ETAG_MAXLEN + 1];
                size_t etag_len = h2o_filecache_get_etag(generator->file.ref, etag);
                if (!h2o_filecache_compare_etag_strong(if_range->base, if_range->len, etag, etag_len))
                    goto EntireFile;
            }
        }
        h2o_iovec_t *range = &req->headers.entries[range_header_index].value;
        size_t *range_infos, range_count;
        range_infos = process_range(&req->pool, range, generator->bytesleft, &range_count);
        if (range_infos == NULL) {
            h2o_iovec_t content_range;
            content_range.base = h2o_mem_alloc_pool(&req->pool, char, 32);
            content_range.len = sprintf(content_range.base, "bytes */%zu", generator->bytesleft);
            h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_RANGE, NULL, content_range.base, content_range.len);
            h2o_send_error_416(req, "Request Range Not Satisfiable", "requested range not satisfiable",
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
            generator->ranged.boundary.base = h2o_mem_alloc_pool(&req->pool, char, BOUNDARY_SIZE + 1);
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
        do_send_file(generator, req, 206, "Partial Content", mime_type->data.mimetype, &h2o_mime_attributes_as_is,
                     method_type == METHOD_IS_GET);
        return 0;
    }

EntireFile:
    /* return file */
    do_send_file(generator, req, 200, "OK", mime_type->data.mimetype, &mime_type->data.attr, method_type == METHOD_IS_GET);
    return 0;

NotModified:
    req->res.status = 304;
    req->res.reason = "Not Modified";
    add_headers_unconditional(generator, req);
    h2o_send_inline(req, NULL, 0);
Close:
    close_file(generator);
    return 0;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    h2o_file_handler_t *self = (void *)_self;
    char *rpath;
    size_t rpath_len, req_path_prefix;
    struct st_h2o_sendfile_generator_t *generator = NULL;
    int is_dir;

    if (req->path_normalized.len < self->conf_path.len) {
        h2o_iovec_t dest = h2o_uri_escape(&req->pool, self->conf_path.base, self->conf_path.len, "/");
        if (req->query_at != SIZE_MAX)
            dest = h2o_concat(&req->pool, dest, h2o_iovec_init(req->path.base + req->query_at, req->path.len - req->query_at));
        h2o_send_redirect(req, 301, "Moved Permanently", dest.base, dest.len);
        return 0;
    }

    /* build path (still unterminated at the end of the block) */
    req_path_prefix = self->conf_path.len;
    rpath = alloca(self->real_path.len + (req->path_normalized.len - req_path_prefix) + self->max_index_file_len + 1);
    rpath_len = 0;
    memcpy(rpath + rpath_len, self->real_path.base, self->real_path.len);
    rpath_len += self->real_path.len;
    memcpy(rpath + rpath_len, req->path_normalized.base + req_path_prefix, req->path_normalized.len - req_path_prefix);
    rpath_len += req->path_normalized.len - req_path_prefix;

    h2o_resp_add_date_header(req);

    h2o_iovec_t resolved_path = req->path_normalized;

    /* build generator (as well as terminating the rpath and its length upon success) */
    if (rpath[rpath_len - 1] == '/') {
        h2o_iovec_t *index_file;
        for (index_file = self->index_files; index_file->base != NULL; ++index_file) {
            memcpy(rpath + rpath_len, index_file->base, index_file->len);
            rpath[rpath_len + index_file->len] = '\0';
            if ((generator = create_generator(req, rpath, rpath_len + index_file->len, &is_dir, self->flags)) != NULL) {
                rpath_len += index_file->len;
                resolved_path = h2o_concat(&req->pool, req->path_normalized, *index_file);
                goto Opened;
            }
            if (is_dir) {
                /* note: apache redirects "path/" to "path/index.txt/" if index.txt is a dir */
                h2o_iovec_t dest = h2o_concat(&req->pool, req->path_normalized, *index_file, h2o_iovec_init(H2O_STRLIT("/")));
                dest = h2o_uri_escape(&req->pool, dest.base, dest.len, "/");
                if (req->query_at != SIZE_MAX)
                    dest =
                        h2o_concat(&req->pool, dest, h2o_iovec_init(req->path.base + req->query_at, req->path.len - req->query_at));
                h2o_send_redirect(req, 301, "Moved Permantently", dest.base, dest.len);
                return 0;
            }
            if (errno != ENOENT)
                break;
        }
        if (index_file->base == NULL && (self->flags & H2O_FILE_FLAG_DIR_LISTING) != 0) {
            rpath[rpath_len] = '\0';
            int is_get = 0;
            if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET"))) {
                is_get = 1;
            } else if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("HEAD"))) {
                /* ok */
            } else {
                send_method_not_allowed(req);
                return 0;
            }
            if (send_dir_listing(req, rpath, rpath_len, is_get) == 0)
                return 0;
        }
    } else {
        rpath[rpath_len] = '\0';
        if ((generator = create_generator(req, rpath, rpath_len, &is_dir, self->flags)) != NULL)
            goto Opened;
        if (is_dir) {
            h2o_iovec_t dest = h2o_concat(&req->pool, req->path_normalized, h2o_iovec_init(H2O_STRLIT("/")));
            dest = h2o_uri_escape(&req->pool, dest.base, dest.len, "/");
            if (req->query_at != SIZE_MAX)
                dest = h2o_concat(&req->pool, dest, h2o_iovec_init(req->path.base + req->query_at, req->path.len - req->query_at));
            h2o_send_redirect(req, 301, "Moved Permanently", dest.base, dest.len);
            return 0;
        }
    }
    /* failed to open */

    if (errno == ENFILE || errno == EMFILE) {
        h2o_send_error_503(req, "Service Unavailable", "please try again later", 0);
    } else {
        if (h2o_mimemap_has_dynamic_type(self->mimemap) && try_dynamic_request(self, req, rpath, rpath_len) == 0)
            return 0;
        if (errno == ENOENT || errno == ENOTDIR) {
            return -1;
        } else {
            h2o_send_error_403(req, "Access Forbidden", "access forbidden", 0);
        }
    }
    return 0;

Opened:
    return serve_with_generator(generator, req, resolved_path, rpath, rpath_len,
                                h2o_mimemap_get_type_by_extension(self->mimemap, h2o_get_filext(rpath, rpath_len)));
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

static void on_handler_dispose(h2o_handler_t *_self)
{
    h2o_file_handler_t *self = (void *)_self;
    size_t i;

    free(self->conf_path.base);
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
    self->super.dispose = on_handler_dispose;
    self->super.on_req = on_req;

    /* setup attributes */
    self->conf_path = h2o_strdup_slashed(NULL, pathconf->path.base, pathconf->path.len);
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

static void specific_handler_on_context_init(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct st_h2o_specific_file_handler_t *self = (void *)_self;

    if (self->mime_type->type == H2O_MIMEMAP_TYPE_DYNAMIC)
        h2o_context_init_pathconf_context(ctx, &self->mime_type->data.dynamic.pathconf);
}

static void specific_handler_on_context_dispose(h2o_handler_t *_self, h2o_context_t *ctx)
{
    struct st_h2o_specific_file_handler_t *self = (void *)_self;

    if (self->mime_type->type == H2O_MIMEMAP_TYPE_DYNAMIC)
        h2o_context_dispose_pathconf_context(ctx, &self->mime_type->data.dynamic.pathconf);
}

static void specific_handler_on_dispose(h2o_handler_t *_self)
{
    struct st_h2o_specific_file_handler_t *self = (void *)_self;

    free(self->real_path.base);
    h2o_mem_release_shared(self->mime_type);
}

static int specific_handler_on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    struct st_h2o_specific_file_handler_t *self = (void *)_self;
    struct st_h2o_sendfile_generator_t *generator;
    int is_dir;

    /* open file (or send error or return -1) */
    if ((generator = create_generator(req, self->real_path.base, self->real_path.len, &is_dir, self->flags)) == NULL) {
        if (is_dir) {
            h2o_send_error_403(req, "Access Forbidden", "access forbidden", 0);
        } else if (errno == ENOENT) {
            return -1;
        } else if (errno == ENFILE || errno == EMFILE) {
            h2o_send_error_503(req, "Service Unavailable", "please try again later", 0);
        } else {
            h2o_send_error_403(req, "Access Forbidden", "access forbidden", 0);
        }
        return 0;
    }

    return serve_with_generator(generator, req, req->path_normalized, self->real_path.base, self->real_path.len, self->mime_type);
}

h2o_handler_t *h2o_file_register_file(h2o_pathconf_t *pathconf, const char *real_path, h2o_mimemap_type_t *mime_type, int flags)
{
    struct st_h2o_specific_file_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));

    self->super.on_context_init = specific_handler_on_context_init;
    self->super.on_context_dispose = specific_handler_on_context_dispose;
    self->super.dispose = specific_handler_on_dispose;
    self->super.on_req = specific_handler_on_req;

    self->real_path = h2o_strdup(NULL, real_path, SIZE_MAX);
    h2o_mem_addref_shared(mime_type);
    self->mime_type = mime_type;
    self->flags = flags;

    return &self->super;
}
