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
#include "h2o/configurator.h"

#define MAX_BUF_SIZE 65000

struct st_h2o_sendfile_generator_t {
    h2o_generator_t super;
    int fd;
    h2o_req_t *req;
    size_t bytesleft;
    char last_modified_buf[H2O_TIMESTR_RFC1123_LEN + 1];
    char etag_buf[sizeof("\"deadbeef-deadbeefdeadbeef\"")];
    size_t etag_len;
    char *buf;
};

struct st_h2o_file_handler_t {
    h2o_handler_t super;
    h2o_iovec_t virtual_path; /* has "/" appended at last */
    h2o_iovec_t real_path; /* has "/" appended at last */
    h2o_mimemap_t *mimemap;
    int flags;
    size_t max_index_file_len;
    h2o_iovec_t index_files[1];
};

struct st_h2o_file_config_vars_t {
    const char **index_files;
    h2o_mimemap_t *mimemap;
    int flags;
};

struct st_h2o_file_configurator_t {
    h2o_configurator_t super;
    struct st_h2o_file_config_vars_t *vars;
    struct st_h2o_file_config_vars_t _vars_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

static const char *default_index_files[] = {
    "index.html",
    "index.htm",
    "index.txt",
    NULL
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
    h2o_iovec_t vec;
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

static int do_pull(h2o_generator_t *_self, h2o_req_t *req, h2o_iovec_t *buf)
{
    struct st_h2o_sendfile_generator_t *self = (void*)_self;
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

static struct st_h2o_sendfile_generator_t *create_generator(h2o_mempool_t *pool, const char *path, int *is_dir, int flags)
{
    struct st_h2o_sendfile_generator_t *self;
    int fd;
    struct stat st;
    size_t bufsz;

    *is_dir = 0;

    if ((fd = open(path, O_RDONLY)) == -1)
        return NULL;
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

    bufsz = MAX_BUF_SIZE;
    if (st.st_size < bufsz)
        bufsz = st.st_size;
    self = h2o_mempool_alloc(pool, sizeof(*self));
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

    return self;
}

static void do_send_file(struct st_h2o_sendfile_generator_t *self, h2o_req_t *req, int status, const char *reason, h2o_iovec_t mime_type)
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

    /* send data */
    h2o_start_response(req, &self->super);

    if (req->_ostr_top->start_pull != NULL) {
        req->_ostr_top->start_pull(req->_ostr_top, do_pull);
    } else {
        size_t bufsz = MAX_BUF_SIZE;
        if (self->bytesleft < bufsz)
            bufsz = self->bytesleft;
        self->buf = h2o_mempool_alloc(&req->pool, bufsz);
        do_proceed(&self->super, req);
    }
}

int h2o_file_send(h2o_req_t *req, int status, const char *reason, const char *path, h2o_iovec_t mime_type, int flags)
{
    struct st_h2o_sendfile_generator_t *self;
    int is_dir;

    if ((self = create_generator(&req->pool, path, &is_dir, flags)) == NULL)
        return -1;
    /* note: is_dir is not handled */
    do_send_file(self, req, status, reason, mime_type);
    return 0;
}

static int redirect_to_dir(h2o_req_t *req, const char *path, size_t path_len)
{
    static h2o_generator_t generator = { NULL, NULL };
    static const h2o_iovec_t body_prefix = {
        H2O_STRLIT("<!DOCTYPE html><TITLE>301 Moved Permanently</TITLE><P>The document has moved <A HREF=\"")
    };
    static const h2o_iovec_t body_suffix = {
        H2O_STRLIT("\">here</A>")
    };

    h2o_iovec_t url;
    size_t alloc_size;
    h2o_iovec_t bufs[3];

    /* determine the size of the memory needed */
    alloc_size = sizeof(":///") + req->scheme.len + req->authority.len + path_len;

    /* allocate and build url */
    url.base = h2o_mempool_alloc(&req->pool, alloc_size);
    url.len = sprintf(url.base, "%.*s://%.*s%.*s/", (int)req->scheme.len, req->scheme.base, (int)req->authority.len, req->authority.base, (int)path_len, path);
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

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    h2o_file_handler_t *self = (void*)_self;
    h2o_iovec_t vpath, mime_type;
    char *rpath;
    size_t rpath_len;
    struct st_h2o_sendfile_generator_t *generator = NULL;
    size_t if_modified_since_header_index, if_none_match_header_index;
    int is_dir;

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
        h2o_iovec_t *index_file;
        for (index_file = self->index_files; index_file->base != NULL; ++index_file) {
            memcpy(rpath + rpath_len, index_file->base, index_file->len);
            rpath[rpath_len + index_file->len] = '\0';
            if ((generator = create_generator(&req->pool, rpath, &is_dir, self->flags)) != NULL) {
                rpath_len += index_file->len;
                break;
            }
            if (is_dir) {
                /* note: apache redirects "path/" to "path/index.txt/" if index.txt is a dir */
                char *path = alloca(req->path.len + index_file->len + 1);
                size_t path_len = sprintf(path, "%.*s%.*s", (int)req->path.len, req->path.base, (int)index_file->len, index_file->base);
                return redirect_to_dir(req, path, path_len);
            }
            if (errno != ENOENT)
                break;
        }
    } else {
        rpath[rpath_len] = '\0';
        generator = create_generator(&req->pool, rpath, &is_dir, self->flags);
        if (generator == NULL && is_dir)
            return redirect_to_dir(req, req->path.base, req->path.len);
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
    h2o_file_handler_t *self = (void*)_self;
    size_t i;

    free(self->virtual_path.base);
    free(self->real_path.base);
    h2o_mempool_release_shared(self->mimemap);
    for (i = 0; self->index_files[i].base != NULL; ++i)
        free(self->index_files[i].base);
}

static h2o_iovec_t append_slash_and_dup(const char *path)
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

    return h2o_iovec_init(buf, path_len);
}

h2o_file_handler_t *h2o_file_register(h2o_hostconf_t *host_config, const char *virtual_path, const char *real_path, const char **index_files, h2o_mimemap_t *mimemap, int flags)
{
    h2o_file_handler_t *self;
    size_t i;

    if (index_files == NULL)
        index_files = default_index_files;

    /* allocate memory */
    for (i = 0; index_files[i] != NULL; ++i)
        ;
    self = (void*)h2o_create_handler(host_config, offsetof(h2o_file_handler_t, index_files[0]) + sizeof(self->index_files[0]) * (i + 1));

    /* setup callbacks */
    self->super.dispose = on_dispose;
    self->super.on_req = on_req;

    /* setup attributes */
    self->virtual_path = append_slash_and_dup(virtual_path);
    self->real_path = append_slash_and_dup(real_path);
    if (mimemap != NULL) {
        h2o_mempool_addref_shared(mimemap);
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

static int on_config_dir(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;

    h2o_file_register(ctx->hostconf, ctx->path->base, node->data.scalar, self->vars->index_files, self->vars->mimemap, self->vars->flags);
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

static int assert_is_mimetype(h2o_configurator_command_t *cmd, const char *file, yoml_t *node)
{
    if (node->type != YOML_TYPE_SCALAR) {
        h2o_config_print_error(cmd, file, node, "expected a scalar (mime-type)");
        return -1;
    }
    if (strchr(node->data.scalar, '/') == NULL) {
        h2o_config_print_error(cmd, file, node, "the string \"%s\" does not look like a mime-type", node->data.scalar);
        return -1;
    }
    return 0;
}

static int assert_is_extension(h2o_configurator_command_t *cmd, const char *file, yoml_t *node)
{
    if (node->type != YOML_TYPE_SCALAR) {
        h2o_config_print_error(cmd, file, node, "expected a scalar (extension)");
        return -1;
    }
    if (node->data.scalar[0] != '.') {
        h2o_config_print_error(cmd, file, node, "given extension \"%s\" does not start with a \".\"", node->data.scalar);
        return -1;
    }
    return 0;
}

static int set_mimetypes(h2o_configurator_command_t *cmd, h2o_mimemap_t *mimemap, const char *file, yoml_t *node)
{
    size_t i, j;

    assert(node->type == YOML_TYPE_MAPPING);

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        if (assert_is_mimetype(cmd, file, key) != 0)
            return -1;
        switch (value->type) {
        case YOML_TYPE_SCALAR:
            if (assert_is_extension(cmd, file, value) != 0)
                return -1;
            h2o_mimemap_set_type(mimemap, value->data.scalar + 1, key->data.scalar);
            break;
        case YOML_TYPE_SEQUENCE:
            for (j = 0; j != value->data.sequence.size; ++j) {
                yoml_t *ext_node = value->data.sequence.elements[j];
                if (assert_is_extension(cmd, file, ext_node) != 0)
                    return -1;
                h2o_mimemap_set_type(mimemap, ext_node->data.scalar + 1, key->data.scalar);
            }
            break;
        default:
            h2o_config_print_error(cmd, file, value, "only scalar or sequence of scalar is permitted at the value part of the argument");
            return -1;
        }
    }

    return 0;
}

static int on_config_mime_settypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;
    h2o_mimemap_t *newmap = h2o_mimemap_create();

    h2o_mimemap_set_default_type(newmap, h2o_mimemap_get_default_type(self->vars->mimemap).base);
    if (set_mimetypes(cmd, newmap, file, node) != 0) {
        h2o_mempool_release_shared(newmap);
        return -1;
    }

    h2o_mempool_release_shared(self->vars->mimemap);
    self->vars->mimemap = newmap;
    return 0;
}

static void clone_mimemap_if_clean(struct st_h2o_file_configurator_t *self)
{
    if (self->vars->mimemap != self->vars[-1].mimemap)
        return;
    h2o_mempool_release_shared(self->vars->mimemap);
    self->vars->mimemap = h2o_mimemap_clone(self->vars->mimemap);
}

static int on_config_mime_addtypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;

    clone_mimemap_if_clean(self);

    return set_mimetypes(cmd, self->vars->mimemap, file, node);
}

static int on_config_mime_removetypes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;
    size_t i;

    clone_mimemap_if_clean(self);

    for (i = 0; i != node->data.sequence.size; ++i) {
        yoml_t *ext_node = node->data.sequence.elements[i];
        if (assert_is_extension(cmd, file, ext_node) != 0)
            return -1;
        h2o_mimemap_remove_type(self->vars->mimemap, ext_node->data.scalar + 1);
    }

    return 0;
}

static int on_config_mime_setdefaulttype(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;

    if (assert_is_mimetype(cmd, file, node) != 0)
        return -1;

    clone_mimemap_if_clean(self);
    h2o_mimemap_set_default_type(self->vars->mimemap, node->data.scalar);

    return 0;
}

static int on_config_etag(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)cmd->configurator;

    switch (h2o_config_get_one_of(cmd, file, node, "OFF,ON")) {
    case 0: /* off */
        self->vars->flags |= H2O_FILE_FLAG_NO_ETAG;
        break;
    case 1: /* on */
        self->vars->flags &= ~H2O_FILE_FLAG_NO_ETAG;
        break;
    default: /* error */
        return -1;
    }

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

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)_self;
    ++self->vars;
    self->vars[0].index_files = dup_strlist(self->vars[-1].index_files);
    self->vars[0].mimemap = self->vars[-1].mimemap;
    self->vars[0].flags = self->vars[-1].flags;
    h2o_mempool_addref_shared(self->vars[0].mimemap);
    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    struct st_h2o_file_configurator_t *self = (void*)_self;
    free(self->vars->index_files);
    h2o_mempool_release_shared(self->vars->mimemap);
    --self->vars;
    return 0;
}

void h2o_file_register_configurator(h2o_globalconf_t *globalconf)
{
    struct st_h2o_file_configurator_t *self = (void*)h2o_config_create_configurator(globalconf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->vars = self->_vars_stack;
    self->vars->mimemap = h2o_mimemap_create();
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
    h2o_config_define_command(
        &self->super, "file.mime.settypes",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
        on_config_mime_settypes,
        "map of mime-type -> (extension | sequence-of-extensions)");
    h2o_config_define_command(
        &self->super, "file.mime.addtypes",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
        on_config_mime_addtypes,
        "map of mime-type -> (extension | sequence-of-extensions)");
    h2o_config_define_command(
        &self->super, "file.mime.removetypes",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SEQUENCE,
        on_config_mime_removetypes,
        "sequence of extensions");
    h2o_config_define_command(
        &self->super, "file.mime.setdefaulttype",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_mime_setdefaulttype,
        "default mime-type");
    h2o_config_define_command(
        &self->super, "file.etag",
        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
        on_config_etag,
        "whether or not to send etag (ON or OFF, default: ON)");
}
