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
    size_t max_index_file_len;
    h2o_buf_t index_files[1];
};

struct st_h2o_file_config_vars_t {
    const char **index_files;
};

struct st_h2o_file_configurator_t {
    h2o_configurator_t super;
    struct st_h2o_file_config_vars_t *vars;
    struct st_h2o_file_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
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
    char *rpath;
    size_t rpath_len;
    struct st_h2o_sendfile_generator_t *generator = NULL;
    size_t if_modified_since_header_index, if_none_match_header_index;

    /* only accept GET (TODO accept HEAD as well) */
    if (! h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    /* prefix match */
    if (req->path.len < self->virtual_path.len
        || memcmp(req->path.base, self->virtual_path.base, self->virtual_path.len) != 0)
        return -1;

    /* normalize path */
    vpath = h2o_normalize_path(&req->pool, req->path.base + self->virtual_path.len - 1, req->path.len - self->virtual_path.len + 1);
    if (vpath.len > PATH_MAX)
        return -1;

    /* build path (still unterminated at the end of the block) */
    rpath = alloca(
        self->real_path.len
        + (vpath.len - 1) /* exclude "/" at the head */
        + self->max_index_file_len
        + 1);
    rpath_len = 0;
    memcpy(rpath + rpath_len, self->real_path.base, self->real_path.len);
    rpath_len += self->real_path.len;
    memcpy(rpath + rpath_len, vpath.base + 1, vpath.len - 1);
    rpath_len += vpath.len - 1;

    /* build generator (as well as terminating the rpath and its length upon success) */
    if (rpath[rpath_len - 1] == '/') {
        h2o_buf_t *index_file;
        for (index_file = self->index_files; index_file->base != NULL; ++index_file) {
            memcpy(rpath + rpath_len, index_file->base, index_file->len);
            rpath[rpath_len + index_file->len] = '\0';
            if ((generator = create_generator(&req->pool, rpath)) != NULL) {
                rpath_len += index_file->len;
                break;
            }
            if (errno != ENOENT)
                break;
        }
    } else {
        rpath[rpath_len] = '\0';
        generator = create_generator(&req->pool, rpath);
    }
    /* return error if failed */
    if (generator == NULL) {
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
    mime_type = h2o_get_mimetype(&req->host_config->mimemap, h2o_get_filext(rpath, rpath_len));

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
    size_t i;

    free(self->virtual_path.base);
    free(self->real_path.base);
    for (i = 0; self->index_files[i].base != NULL; ++i)
        free(self->index_files[i].base);
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

void h2o_file_register(h2o_hostconf_t *host_config, const char *virtual_path, const char *real_path, const char **index_files)
{
    struct st_h2o_file_handler_t *self;
    size_t i;

    /* allocate memory */
    for (i = 0; index_files[i] != NULL; ++i)
        ;
    self = (void*)h2o_create_handler(host_config, offsetof(struct st_h2o_file_handler_t, index_files[0]) + sizeof(self->index_files[0]) * (i + 1));

    /* setup callbacks */
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;

    /* setup attributes */
    self->virtual_path = append_slash_and_dup(virtual_path);
    self->real_path = append_slash_and_dup(real_path);
    for (i = 0; index_files[i] != NULL; ++i)
        self->index_files[i] = h2o_strdup(NULL, index_files[i], SIZE_MAX);
}

static int on_config_dir(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;

    h2o_file_register(ctx->hostconf, ctx->path->base, node->data.scalar, self->vars->index_files);
    return 0;
}

static int on_config_index(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;
    size_t i;

    free(self->vars->index_files);
    self->vars->index_files = h2o_malloc(sizeof(self->vars->index_files[0]) * (node->data.sequence.size + 1));
    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *element = node->data.sequence.elements[i];
        if (element->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, element, "argument must be a sequence of scalars");
            return -1;
        }
        self->vars->index_files[i] = element->data.scalar;
    }
    self->vars->index_files[i] = NULL;

    return 0;
}

static const char **dup_strlist(const char **s)
{
    size_t i;
    const char **ret;

    for (i = 0; s[i] != NULL; ++i)
        ;
    ret = h2o_malloc(sizeof(*ret) * (i + 1));
    for (i = 0; s[i] != NULL; ++i)
        ret[i] = s[i];
    ret[i] = NULL;

    return ret;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx)
{
    struct st_h2o_file_configurator_t *self = (void*)_self;
    ++self->vars;
    self->vars[0].index_files = dup_strlist(self->vars[-1].index_files);
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx)
{
    struct st_h2o_file_configurator_t *self = (void*)_self;
    free(self->vars->index_files);
    --self->vars;
    return 0;
}

void h2o_file_register_configurator(h2o_globalconf_t *globalconf)
{
    static const char *default_index_files[] = {
        "index.html",
        "index.htm",
        "index.txt",
        NULL
    };

    struct st_h2o_file_configurator_t *self = (void*)h2o_config_create_configurator(globalconf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->vars = self->_vars_stack;
    self->vars->index_files = default_index_files;

    h2o_config_define_command(
        &self->super, "file.dir",
        H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_DEFERRED,
        on_config_dir,
        "directory under which to serve the target path");
    h2o_config_define_command(
        &self->super, "file.index",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
        on_config_index,
        "sequence of index file names (default: index.html index.htm index.txt)");
}

#ifdef H2O_UNITTEST

#include "t/test.h"

void test_lib__file_c()
{
    h2o_globalconf_t globalconf;
    h2o_hostconf_t *hostconf;
    h2o_context_t ctx;

    static const char *index_files[] = {
        "index.html",
        "index.htm",
        "index.txt",
        NULL
    };

    h2o_config_init(&globalconf);
    hostconf = h2o_config_register_host(&globalconf, "default");
    h2o_file_register(hostconf, "/", "t/00unit/file", index_files);

    h2o_context_init(&ctx, test_loop, &globalconf);

    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_buf_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_buf_init(H2O_STRLIT("/"));
        conn->req.version = 0x100;
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello html\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_buf_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_buf_init(H2O_STRLIT("/index.html"));
        conn->req.version = 0x100;
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello html\n")));
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_buf_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_buf_init(H2O_STRLIT("/1000.txt"));
        conn->req.version = 0x100;
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(conn->body->size == 1000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "dfd3ae1f5c475555fad62efe42e07309fa45f2ed") == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_buf_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_buf_init(H2O_STRLIT("/1000000.txt"));
        conn->req.version = 0x100;
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(conn->body->size == 1000000);
        ok(strcmp(sha1sum(conn->body->bytes, conn->body->size), "00c8ab71d0914dce6a1ec2eaa0fda0df7044b2a2") == 0);
        h2o_loopback_destroy(conn);
    }
    {
        h2o_loopback_conn_t *conn = h2o_loopback_create(&ctx);
        conn->req.method = h2o_buf_init(H2O_STRLIT("GET"));
        conn->req.path = h2o_buf_init(H2O_STRLIT("/index_txt/"));
        conn->req.version = 0x100;
        h2o_loopback_run_loop(conn);
        ok(conn->req.res.status == 200);
        ok(h2o_memis(conn->body->bytes, conn->body->size, H2O_STRLIT("hello text\n")));
        h2o_loopback_destroy(conn);
    }

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&globalconf);
}

#endif
