/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include "picohttpparser.h"
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby_input_stream.h>
#include "h2o/mruby_.h"

struct st_h2o_mruby_http_request_context_t {
    h2o_mruby_generator_t *generator;
    h2o_http1client_t *client;
    mrb_value receiver;
    struct {
        h2o_buffer_t *buf;
        h2o_iovec_t body; /* body.base != NULL indicates that post content exists (and the length MAY be zero) */
        int method_is_head : 1;
        int has_transfer_encoding : 1;
    } req;
    struct {
        h2o_buffer_t *after_closed; /* when client becomes NULL, rest of the data will be stored to this pointer */
        int has_content;
        mrb_value input_stream;
    } resp;
};

static void on_gc_dispose(mrb_state *mrb, void *_ctx)
{
    struct st_h2o_mruby_http_request_context_t *ctx = _ctx;
    if (ctx != NULL)
        ctx->resp.input_stream = mrb_nil_value();
}

const static struct mrb_data_type input_stream_type = {"H2O._HttpOutputStream", on_gc_dispose};

static mrb_value create_downstream_closed_exception(mrb_state *mrb)
{
    return mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "downstream HTTP closed");
}

static mrb_value detach_receiver(struct st_h2o_mruby_http_request_context_t *ctx)
{
    mrb_value ret = ctx->receiver;
    assert(!mrb_nil_p(ret));
    ctx->receiver = mrb_nil_value();
    return ret;
}

static void on_dispose(void *_ctx)
{
    struct st_h2o_mruby_http_request_context_t *ctx = _ctx;

    /* clear the refs */
    if (ctx->client != NULL) {
        h2o_http1client_cancel(ctx->client);
        ctx->client = NULL;
    }
    if (ctx->resp.after_closed != NULL)
        h2o_buffer_dispose(&ctx->resp.after_closed);
    if (!mrb_nil_p(ctx->resp.input_stream))
        DATA_PTR(ctx->resp.input_stream) = NULL;

    /* notify the app, if it is waiting to hear from us */
    if (!mrb_nil_p(ctx->receiver)) {
        mrb_state *mrb = ctx->generator->ctx->mrb;
        int gc_arena = mrb_gc_arena_save(mrb);
        h2o_mruby_run_fiber(ctx->generator, detach_receiver(ctx), create_downstream_closed_exception(mrb), gc_arena, NULL);
    }
}

static void post_response(struct st_h2o_mruby_http_request_context_t *ctx, int status, const struct phr_header *headers_sorted,
                          size_t num_headers)
{
    mrb_state *mrb = ctx->generator->ctx->mrb;
    int gc_arena = mrb_gc_arena_save(mrb);
    size_t i;

    mrb_value resp = mrb_ary_new_capa(mrb, 3);

    /* set status */
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(status));

    /* set headers */
    mrb_value headers_hash = mrb_hash_new_capa(mrb, (int)num_headers);
    for (i = 0; i < num_headers; ++i) {
        /* skip the headers, we determine the eos! */
        if (h2o_memis(headers_sorted[i].name, headers_sorted[i].name_len, H2O_STRLIT("content-length")) ||
            h2o_memis(headers_sorted[i].name, headers_sorted[i].name_len, H2O_STRLIT("transfer-encoding")))
            continue;
        /* build and set the hash entry */
        mrb_value k = mrb_str_new(mrb, headers_sorted[i].name, headers_sorted[i].name_len);
        mrb_value v = mrb_str_new(mrb, headers_sorted[i].value, headers_sorted[i].value_len);
        while (i + 1 < num_headers && h2o_memis(headers_sorted[i].name, headers_sorted[i].name_len, headers_sorted[i + 1].name,
                                                headers_sorted[i + 1].name_len)) {
            ++i;
            v = mrb_str_cat_lit(mrb, v, "\n");
            v = mrb_str_cat(mrb, v, headers_sorted[i].value, headers_sorted[i].value_len);
        }
        mrb_hash_set(mrb, headers_hash, k, v);
    }
    mrb_ary_set(mrb, resp, 1, headers_hash);

    /* set input stream */
    assert(mrb_nil_p(ctx->resp.input_stream));
    struct RClass *klass = mrb_class_ptr(mrb_ary_entry(ctx->generator->ctx->constants, H2O_MRUBY_HTTP_REQUEST_INPUT_STREAM_CLASS));
    struct RData *data = mrb_data_object_alloc(mrb, klass, ctx, &input_stream_type);
    ctx->resp.input_stream = mrb_obj_value(data);
    mrb_ary_set(mrb, resp, 2, ctx->resp.input_stream);

    h2o_mruby_run_fiber(ctx->generator, detach_receiver(ctx), resp, gc_arena, NULL);
}

static void post_error(struct st_h2o_mruby_http_request_context_t *ctx, const char *errstr)
{
    static const struct phr_header headers_sorted[] = {{H2O_STRLIT("content-type"), H2O_STRLIT("text/plain; charset=utf-8")}};

    ctx->client = NULL;
    h2o_buffer_init(&ctx->resp.after_closed, &h2o_socket_buffer_prototype);
    size_t errstr_len = strlen(errstr);
    h2o_buffer_reserve(&ctx->resp.after_closed, errstr_len);
    memcpy(ctx->resp.after_closed->bytes + ctx->resp.after_closed->size, errstr, errstr_len);
    ctx->resp.after_closed->size += errstr_len;
    ctx->resp.has_content = 1;

    post_response(ctx, 500, headers_sorted, sizeof(headers_sorted) / sizeof(headers_sorted[0]));
}

static mrb_value build_chunk(struct st_h2o_mruby_http_request_context_t *ctx)
{
    mrb_value chunk;

    assert(ctx->resp.has_content);

    if (ctx->client != NULL) {
        assert(ctx->client->sock->input->size != 0);
        chunk = mrb_str_new(ctx->generator->ctx->mrb, ctx->client->sock->input->bytes, ctx->client->sock->input->size);
        h2o_buffer_consume(&ctx->client->sock->input, ctx->client->sock->input->size);
        ctx->resp.has_content = 0;
    } else {
        if (ctx->resp.after_closed == NULL || ctx->resp.after_closed->size == 0) {
            chunk = mrb_nil_value();
        } else {
            chunk = mrb_str_new(ctx->generator->ctx->mrb, ctx->resp.after_closed->bytes, ctx->resp.after_closed->size);
            h2o_buffer_dispose(&ctx->resp.after_closed);
        }
        /* has_content is retained as true, so that repeated calls will return nil immediately */
    }

    return chunk;
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        ctx->resp.after_closed = client->sock->input;
        h2o_buffer_init(&client->sock->input, &h2o_socket_buffer_prototype);
        ctx->client = NULL;
        ctx->resp.has_content = 1;
    } else if (client->sock->input->size != 0) {
        ctx->resp.has_content = 1;
    }

    if (ctx->resp.has_content && !mrb_nil_p(ctx->receiver)) {
        int gc_arena = mrb_gc_arena_save(ctx->generator->ctx->mrb);
        mrb_value chunk = build_chunk(ctx);
        h2o_mruby_run_fiber(ctx->generator, detach_receiver(ctx), chunk, gc_arena, NULL);
    }
    return 0;
}

static int headers_sort_cb(const void *_x, const void *_y)
{
    const struct phr_header *x = _x, *y = _y;

    if (x->name_len < y->name_len)
        return -1;
    if (x->name_len > y->name_len)
        return 1;
    return memcmp(x->name, y->name, x->name_len);
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, struct phr_header *headers, size_t num_headers)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        if (errstr != h2o_http1client_error_is_eos) {
            /* error */
            post_error(ctx, errstr);
            return NULL;
        }
        /* closed without body */
        ctx->client = NULL;
        h2o_buffer_init(&ctx->resp.after_closed, &h2o_socket_buffer_prototype);
    }

    qsort(headers, num_headers, sizeof(headers[0]), headers_sort_cb);
    post_response(ctx, status, headers, num_headers);
    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head)
{
    struct st_h2o_mruby_http_request_context_t *ctx = client->data;

    if (errstr != NULL) {
        post_error(ctx, errstr);
        return NULL;
    }

    *reqbufs = h2o_mem_alloc_pool(&ctx->generator->req->pool, sizeof(**reqbufs) * 2);
    **reqbufs = h2o_iovec_init(ctx->req.buf->bytes, ctx->req.buf->size);
    *reqbufcnt = 1;
    if (ctx->req.body.base != NULL)
        (*reqbufs)[(*reqbufcnt)++] = ctx->req.body;
    *method_is_head = ctx->req.method_is_head;
    return on_head;
}

static inline void append_to_buffer(h2o_buffer_t **buf, const void *src, size_t len)
{
    memcpy((*buf)->bytes + (*buf)->size, src, len);
    (*buf)->size += len;
}

static int flatten_request_header(h2o_mruby_context_t *handler_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_ctx)
{
    struct st_h2o_mruby_http_request_context_t *ctx = _ctx;

    if (h2o_lcstris(name.base, name.len, H2O_STRLIT("content-length"))) {
        return 0; /* ignored */
    } else if (h2o_lcstris(name.base, name.len, H2O_STRLIT("transfer-encoding"))) {
        ctx->req.has_transfer_encoding = 1;
    }

    h2o_buffer_reserve(&ctx->req.buf, name.len + value.len + sizeof(": \r\n") - 1);
    append_to_buffer(&ctx->req.buf, name.base, name.len);
    append_to_buffer(&ctx->req.buf, H2O_STRLIT(": "));
    append_to_buffer(&ctx->req.buf, value.base, value.len);
    append_to_buffer(&ctx->req.buf, H2O_STRLIT("\r\n"));

    return 0;
}

mrb_value h2o_mruby_http_request_callback(h2o_mruby_generator_t *generator, mrb_value receiver, mrb_value input, int *next_action)
{
    struct st_h2o_mruby_http_request_context_t *ctx;
    mrb_state *mrb = generator->ctx->mrb;
    h2o_url_t url;

    if (generator->req == NULL)
        return create_downstream_closed_exception(mrb);

    ctx = h2o_mem_alloc_shared(&generator->req->pool, sizeof(*ctx), on_dispose);
    memset(ctx, 0, sizeof(*ctx));
    ctx->generator = generator;
    ctx->receiver = mrb_nil_value();
    h2o_buffer_init(&ctx->req.buf, &h2o_socket_buffer_prototype);
    ctx->resp.input_stream = mrb_nil_value();

    { /* method */
        mrb_value method = h2o_mruby_to_str(mrb, mrb_ary_entry(input, 0));
        if (mrb->exc != NULL)
            goto RaiseException;
        h2o_buffer_reserve(&ctx->req.buf, RSTRING_LEN(method) + 1);
        append_to_buffer(&ctx->req.buf, RSTRING_PTR(method), RSTRING_LEN(method));
        append_to_buffer(&ctx->req.buf, H2O_STRLIT(" "));
        if (h2o_memis(RSTRING_PTR(method), RSTRING_LEN(method), H2O_STRLIT("HEAD")))
            ctx->req.method_is_head = 1;
    }
    { /* uri */
        mrb_value t = h2o_mruby_to_str(mrb, mrb_ary_entry(input, 1));
        if (mrb->exc != NULL)
            goto RaiseException;
        h2o_iovec_t urlstr = h2o_strdup(&generator->req->pool, RSTRING_PTR(t), RSTRING_LEN(t));
        if (h2o_url_parse(urlstr.base, urlstr.len, &url) != 0) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "invaild URL"));
            goto RaiseException;
        }
        if (url.scheme != &H2O_URL_SCHEME_HTTP) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "scheme is not HTTP"));
            goto RaiseException;
        }
        h2o_buffer_reserve(&ctx->req.buf,
                           url.path.len + url.authority.len + sizeof(" HTTP/1.1\r\nConnection: close\r\nHost: \r\n") - 1);
        append_to_buffer(&ctx->req.buf, url.path.base, url.path.len);
        append_to_buffer(&ctx->req.buf, H2O_STRLIT(" HTTP/1.1\r\nConnection: close\r\nHost: "));
        append_to_buffer(&ctx->req.buf, url.authority.base, url.authority.len);
        append_to_buffer(&ctx->req.buf, H2O_STRLIT("\r\n"));
    }
    { /* headers */
        mrb_value headers = mrb_ary_entry(input, 2);
        if (!mrb_nil_p(headers)) {
            if (h2o_mruby_iterate_headers(generator->ctx, headers, flatten_request_header, ctx) != 0)
                goto RaiseException;
        }
    }
    { /* body */
        mrb_value body = mrb_ary_entry(input, 3);
        if (!mrb_nil_p(body)) {
            if (mrb_obj_eq(mrb, body, generator->rack_input)) {
                /* fast path */
                mrb_int pos;
                mrb_input_stream_get_data(mrb, body, NULL, NULL, &pos, NULL, NULL);
                ctx->req.body = generator->req->entity;
                ctx->req.body.base += pos;
                ctx->req.body.len -= pos;
            } else {
                if (!mrb_string_p(body)) {
                    body = mrb_funcall(mrb, body, "read", 0);
                    if (mrb->exc != NULL)
                        goto RaiseException;
                    if (!mrb_string_p(body)) {
                        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "body.read did not return string"));
                        goto RaiseException;
                    }
                }
                ctx->req.body = h2o_strdup(&ctx->generator->req->pool, RSTRING_PTR(body), RSTRING_LEN(body));
            }
            if (!ctx->req.has_transfer_encoding) {
                char buf[64];
                size_t l = (size_t)sprintf(buf, "content-length: %zu\r\n", ctx->req.body.len);
                h2o_buffer_reserve(&ctx->req.buf, l);
                append_to_buffer(&ctx->req.buf, buf, l);
            }
        }
    }

    h2o_buffer_reserve(&ctx->req.buf, 2);
    append_to_buffer(&ctx->req.buf, H2O_STRLIT("\r\n"));

    /* build request and connect */
    h2o_buffer_link_to_pool(ctx->req.buf, &generator->req->pool);
    h2o_http1client_connect(&ctx->client, ctx, &generator->req->conn->ctx->proxy.client_ctx, url.host, h2o_url_get_port(&url),
                            on_connect);

    ctx->receiver = receiver;
    *next_action = H2O_MRUBY_CALLBACK_NEXT_ACTION_ASYNC;
    return mrb_nil_value();

RaiseException:
    h2o_buffer_dispose(&ctx->req.buf);
    {
        mrb_value t = mrb_obj_value(mrb->exc);
        mrb->exc = NULL;
        return t;
    }
}

mrb_value h2o_mruby_http_request_fetch_chunk_callback(h2o_mruby_generator_t *generator, mrb_value receiver, mrb_value args,
                                                      int *next_action)
{
    mrb_state *mrb = generator->ctx->mrb;
    struct st_h2o_mruby_http_request_context_t *ctx;
    mrb_value ret;

    if (generator->req == NULL)
        return create_downstream_closed_exception(mrb);

    if ((ctx = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &input_stream_type)) == NULL)
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "_HttpInputStream#each wrong self");

    if (ctx->resp.has_content) {
        ret = build_chunk(ctx);
    } else {
        ctx->receiver = receiver;
        *next_action = H2O_MRUBY_CALLBACK_NEXT_ACTION_ASYNC;
        ret = mrb_nil_value();
    }

    return ret;
}

void h2o_mruby_http_request_init_context(h2o_mruby_context_t *ctx)
{
    mrb_state *mrb = ctx->mrb;

    h2o_mruby_define_callback(mrb, "http_request", H2O_MRUBY_CALLBACK_ID_HTTP_REQUEST);

    struct RClass *module = mrb_define_module(mrb, "H2O");
    struct RClass *klass = mrb_define_class_under(mrb, module, "HttpInputStream", mrb->object_class);
    mrb_ary_set(mrb, ctx->constants, H2O_MRUBY_HTTP_REQUEST_INPUT_STREAM_CLASS, mrb_obj_value(klass));

    h2o_mruby_define_callback(mrb, "_h2o__http_request_fetch_chunk", H2O_MRUBY_CALLBACK_ID_HTTP_REQUEST_FETCH_CHUNK);
    h2o_mruby_eval_expr(mrb, "module H2O\n"
                             "  class HttpInputStream\n"
                             "    def each\n"
                             "      while c = _h2o__http_request_fetch_chunk(self)\n"
                             "        yield c\n"
                             "      end\n"
                             "    end\n"
                             "  end\n"
                             "end");
    h2o_mruby_assert(mrb);
}
