/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Ryosuke Matsumoto
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
#include <mruby.h>
#include <mruby/string.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/variable.h>
#include "h2o.h"
#include "h2o/mruby_.h"

static mrb_value h2o_mrb_req_init(mrb_state *mrb, mrb_value self)
{
    return self;
}

static mrb_value h2o_mrb_req_log_error(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value log;

    mrb_get_args(mrb, "o", &log);
    h2o_req_log_error(mruby_ctx->req, H2O_MRUBY_MODULE_NAME, "%.*s", RSTRING_LEN(log), RSTRING_PTR(log));

    return log;
}

static mrb_value h2o_mrb_req_uri(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->path);
}

static mrb_value h2o_mrb_req_hostname(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    h2o_iovec_t hostname;
    uint16_t port;

    if (h2o_url_parse_hostport(mruby_ctx->req->authority.base, mruby_ctx->req->authority.len, &hostname, &port) == NULL)
        return mrb_nil_value();

    return h2o_mrb_str_new(mrb, &hostname);
}

static mrb_value h2o_mrb_req_authority(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->authority);
}

static mrb_value h2o_mrb_req_scheme(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->scheme->name);
}

static mrb_value h2o_mrb_req_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return h2o_mrb_str_new(mrb, &mruby_ctx->req->method);
}

static mrb_value h2o_mrb_req_query(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    h2o_iovec_t *path = &mruby_ctx->req->path;
    size_t offset = mruby_ctx->req->query_at;
    if (offset == SIZE_MAX)
        return mrb_nil_value();

    return mrb_str_new(mrb, path->base + offset, path->len - offset);
}

static mrb_value h2o_mrb_req_get_status(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;

    return mrb_fixnum_value(mruby_ctx->req->res.status);
}

static mrb_value h2o_mrb_req_set_status(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_int status;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    mrb_get_args(mrb, "i", &status);
    mruby_ctx->req->res.status = status;

    return mrb_fixnum_value(status);
}

static mrb_value h2o_mrb_get_class_obj(mrb_state *mrb, mrb_value self, char *obj_id, char *class_name)
{
    mrb_value obj;
    struct RClass *obj_class, *h2o_class;

    obj = mrb_iv_get(mrb, self, mrb_intern_cstr(mrb, obj_id));
    if (mrb_nil_p(obj)) {
        h2o_class = mrb_class_get(mrb, "H2O");
        obj_class = (struct RClass *)mrb_class_ptr(mrb_const_get(mrb, mrb_obj_value(h2o_class), mrb_intern_cstr(mrb, class_name)));
        obj = mrb_obj_new(mrb, obj_class, 0, NULL);
        mrb_iv_set(mrb, self, mrb_intern_cstr(mrb, obj_id), obj);
    }
    return obj;
}

static mrb_value h2o_mrb_headers_in_obj(mrb_state *mrb, mrb_value self)
{
    return h2o_mrb_get_class_obj(mrb, self, "headers_in_obj", "Headers_in");
}

static mrb_value h2o_mrb_headers_out_obj(mrb_state *mrb, mrb_value self)
{
    return h2o_mrb_get_class_obj(mrb, self, "headers_out_obj", "Headers_out");
}

static mrb_value h2o_mrb_http2_push_paths_obj(mrb_state *mrb, mrb_value self)
{
    return h2o_mrb_get_class_obj(mrb, self, "http2_push_paths_obj", "Http2_push_paths");
}

static mrb_value h2o_mrb_get_request_headers_in(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key;
    ssize_t index;
    h2o_header_t *h;

    mrb_get_args(mrb, "o", &key);
    key = mrb_funcall(mrb, key, "downcase", 0);

    index = h2o_find_header_by_str(&mruby_ctx->req->headers, RSTRING_PTR(key), RSTRING_LEN(key), -1);
    if (index == -1)
        return mrb_nil_value();

    h = mruby_ctx->req->headers.entries + index;

    return mrb_str_new(mrb, h->value.base, h->value.len);
}

static mrb_value h2o_mrb_set_request_headers_in(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key, val;
    char *key_cstr, *val_cstr;

    mrb_get_args(mrb, "oo", &key, &val);
    key = mrb_funcall(mrb, key, "downcase", 0);

    key_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(key));
    val_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(val));
    memcpy(key_cstr, RSTRING_PTR(key), RSTRING_LEN(key));
    memcpy(val_cstr, RSTRING_PTR(val), RSTRING_LEN(val));

    h2o_set_header_by_str(&mruby_ctx->req->pool, &mruby_ctx->req->headers, key_cstr, RSTRING_LEN(key), 0, val_cstr,
                          RSTRING_LEN(val), 1);

    return key;
}

static mrb_value h2o_mrb_get_request_headers_out(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key;
    ssize_t index;
    h2o_header_t *h;

    mrb_get_args(mrb, "o", &key);
    key = mrb_funcall(mrb, key, "downcase", 0);

    index = h2o_find_header_by_str(&mruby_ctx->req->res.headers, RSTRING_PTR(key), RSTRING_LEN(key), -1);
    if (index == -1)
        return mrb_nil_value();

    h = mruby_ctx->req->res.headers.entries + index;

    return mrb_str_new(mrb, h->value.base, h->value.len);
}

static mrb_value h2o_mrb_set_request_headers_out(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    mrb_value key, val;
    char *key_cstr, *val_cstr;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    mrb_get_args(mrb, "oo", &key, &val);
    key = mrb_funcall(mrb, key, "downcase", 0);

    key_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(key));
    val_cstr = h2o_mem_alloc_pool(&mruby_ctx->req->pool, RSTRING_LEN(val));
    memcpy(key_cstr, RSTRING_PTR(key), RSTRING_LEN(key));
    memcpy(val_cstr, RSTRING_PTR(val), RSTRING_LEN(val));

    h2o_set_header_by_str(&mruby_ctx->req->pool, &mruby_ctx->req->res.headers, key_cstr, RSTRING_LEN(key), 0, val_cstr,
                          RSTRING_LEN(val), 1);

    return key;
}

static mrb_value h2o_mrb_req_reprocess_request(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    char *s;
    mrb_int len;
    h2o_url_t parsed, base, resolved;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    mrb_get_args(mrb, "s", &s, &len);

    /* resolve the input URL:
     * * uses `hostconf->authority.hostport` as part of base to prevent relative-path internal redirect generating a TCP connection
     * * h2o_url_resolve always copies the memory (so the values will be preserved after mruby GC)
     */
    if (h2o_url_parse_relative(s, (size_t)len, &parsed) != 0)
        mrb_raise(mrb, E_ARGUMENT_ERROR, "failed to parse URL");
    h2o_req_t *req = mruby_ctx->req;
    if (h2o_url_init(&base, req->scheme, req->hostconf->authority.hostport, req->pathconf->path) != 0)
        mrb_raise(mrb, E_RUNTIME_ERROR, "failed to parse current authority");
    h2o_url_resolve(&req->pool, &base, &parsed, &resolved);

    /* request reprocess */
    h2o_reprocess_request_deferred(req, req->method, resolved.scheme, resolved.authority, resolved.path, NULL, 0);
    mruby_ctx->state = H2O_MRUBY_STATE_RESPONSE_SENT;

    return mrb_nil_value();
}

static mrb_value h2o_mrb_req_send(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    char *s;
    mrb_int len;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    mrb_get_args(mrb, "s", &s, &len);

    h2o_mruby_fixup_and_send(mruby_ctx->req, h2o_strdup(&mruby_ctx->req->pool, s, len).base, len);
    mruby_ctx->state = H2O_MRUBY_STATE_RESPONSE_SENT;
    return mrb_nil_value();
}

static mrb_value h2o_mrb_req_send_file(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    char *fn;
    int status;
    h2o_iovec_t content_type;
    int content_type_header_removed = 0;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    mrb_get_args(mrb, "z", &fn);

    /* determine status and reason to be used */
    if ((status = mruby_ctx->req->res.status) == 0)
        status = 200;

    { /* determine content-type (removing existing header, since it is added by h2o_file_send) */
        ssize_t header_index;
        if ((header_index = h2o_find_header(&mruby_ctx->req->res.headers, H2O_TOKEN_CONTENT_TYPE, -1)) != -1) {
            content_type = mruby_ctx->req->res.headers.entries[header_index].value;
            h2o_delete_header(&mruby_ctx->req->res.headers, header_index);
            content_type_header_removed = 1;
        } else {
            const char *ext = h2o_get_filext(fn, strlen(fn));
            h2o_mimemap_type_t *m = h2o_mimemap_get_type_by_extension(mruby_ctx->req->pathconf->mimemap, ext);
            if (m == NULL || m->type != H2O_MIMEMAP_TYPE_MIMETYPE) {
                m = h2o_mimemap_get_default_type(mruby_ctx->req->pathconf->mimemap);
                assert(m->type == H2O_MIMEMAP_TYPE_MIMETYPE);
            }
            content_type = m->data.mimetype;
        }
    }

    if (h2o_file_send(mruby_ctx->req, status, mruby_ctx->req->res.reason, fn, content_type, H2O_FILE_FLAG_SEND_GZIP) == 0) {
        /* succeeded, return true */
        mruby_ctx->state = H2O_MRUBY_STATE_RESPONSE_SENT;
        return mrb_true_value();
    } else {
        /* failed, restore content-type header and return false */
        if (content_type_header_removed)
            h2o_add_header(&mruby_ctx->req->pool, &mruby_ctx->req->res.headers, H2O_TOKEN_CONTENT_TYPE, content_type.base,
                           content_type.len);
        return mrb_false_value();
    }
}

static mrb_value h2o_mrb_push_http2_push_paths(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_internal_context_t *mruby_ctx = (h2o_mruby_internal_context_t *)mrb->ud;
    char *s;
    mrb_int len;

    if (mruby_ctx->state != H2O_MRUBY_STATE_UNDETERMINED)
        mrb_raise(mrb, E_RUNTIME_ERROR, "response already sent");

    mrb_get_args(mrb, "s", &s, &len);

    h2o_vector_reserve(&mruby_ctx->req->pool, (void *)&mruby_ctx->req->http2_push_paths,
                       sizeof(mruby_ctx->req->http2_push_paths.entries[0]), mruby_ctx->req->http2_push_paths.size + 1);
    mruby_ctx->req->http2_push_paths.entries[mruby_ctx->req->http2_push_paths.size++] = h2o_strdup(&mruby_ctx->req->pool, s, len);

    return self;
}

void h2o_mrb_request_class_init(mrb_state *mrb, struct RClass *class)
{
    struct RClass *class_request;
    struct RClass *class_headers_in;
    struct RClass *class_headers_out;
    struct RClass *class_http2_push_paths;

    class_request = mrb_define_class_under(mrb, class, "Request", mrb->object_class);

    mrb_define_method(mrb, class_request, "initialize", h2o_mrb_req_init, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "log_error", h2o_mrb_req_log_error, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_request, "uri", h2o_mrb_req_uri, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "path", h2o_mrb_req_uri, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "hostname", h2o_mrb_req_hostname, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "authority", h2o_mrb_req_authority, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "scheme", h2o_mrb_req_scheme, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "method", h2o_mrb_req_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "query", h2o_mrb_req_query, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "status", h2o_mrb_req_get_status, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "status=", h2o_mrb_req_set_status, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_request, "reprocess_request", h2o_mrb_req_reprocess_request, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_request, "send", h2o_mrb_req_send, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_request, "send_file", h2o_mrb_req_send_file, MRB_ARGS_REQ(1));

    mrb_define_method(mrb, class_request, "headers_in", h2o_mrb_headers_in_obj, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "headers_out", h2o_mrb_headers_out_obj, MRB_ARGS_NONE());
    mrb_define_method(mrb, class_request, "http2_push_paths", h2o_mrb_http2_push_paths_obj, MRB_ARGS_NONE());

    /* request header class */
    class_headers_in = mrb_define_class_under(mrb, class, "Headers_in", mrb->object_class);
    mrb_define_method(mrb, class_headers_in, "[]", h2o_mrb_get_request_headers_in, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_headers_in, "[]=", h2o_mrb_set_request_headers_in, MRB_ARGS_REQ(2));

    /* response header class */
    class_headers_out = mrb_define_class_under(mrb, class, "Headers_out", mrb->object_class);
    mrb_define_method(mrb, class_headers_out, "[]", h2o_mrb_get_request_headers_out, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, class_headers_out, "[]=", h2o_mrb_set_request_headers_out, MRB_ARGS_REQ(2));

    /* http2_push_paths (TODO: define other methods so that it would act like an array) */
    class_http2_push_paths = mrb_define_class_under(mrb, class, "Http2_push_paths", mrb->object_class);
    mrb_define_method(mrb, class_http2_push_paths, "<<", h2o_mrb_push_http2_push_paths, MRB_ARGS_REQ(1));
}
