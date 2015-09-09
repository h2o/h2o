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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/array.h>
#include <mruby/compile.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include "h2o.h"
#include "h2o/mruby_.h"

#define STATUS_FALLTHRU 399

typedef struct st_h2o_mruby_context_t {
    h2o_mruby_handler_t *handler;
    mrb_state *mrb;
    /* TODO: add other hook code */
    mrb_value proc;
} h2o_mruby_context_t;

mrb_value h2o_mruby_compile_code(mrb_state *mrb, h2o_mruby_config_vars_t *config, char *errbuf)
{
    mrbc_context *cxt;
    struct mrb_parser_state *parser;
    struct RProc *proc = NULL;

    /* parse */
    if ((cxt = mrbc_context_new(mrb)) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    if (config->path != NULL)
        mrbc_filename(mrb, cxt, config->path);
    cxt->capture_errors = 1;
    cxt->lineno = config->lineno;
    if ((parser = mrb_parse_nstring(mrb, config->source.base, (mrb_int)config->source.len, cxt)) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    /* return erro if errbuf is supplied, or abort */
    if (parser->nerr != 0) {
        if (errbuf == NULL) {
            fprintf(stderr, "%s: internal error (unexpected state)\n", H2O_MRUBY_MODULE_NAME);
            abort();
        }
        snprintf(errbuf, 256, "line %d:%s", parser->error_buffer[0].lineno, parser->error_buffer[0].message);
        goto Exit;
    }
    /* generate code */
    if ((proc = mrb_generate_code(mrb, parser)) == NULL) {
        fprintf(stderr, "%s: internal error (mrb_generate_code failed)\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }

    mrb_value result = mrb_run(mrb, proc, mrb_top_self(mrb));
    if (mrb->exc) {
        mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
        struct RString *error = mrb_str_ptr(obj);
        snprintf(errbuf, 256, "%s", error->as.heap.ptr);
        mrb->exc = 0;
        result = mrb_nil_value();
        goto Exit;
    } else if (mrb_nil_p(result)) {
        snprintf(errbuf, 256, "returned value is not callable");
        goto Exit;
    }

Exit:
    mrb_parser_free(parser);
    mrbc_context_free(mrb, cxt);
    return result;
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_mem_alloc(sizeof(*handler_ctx));

    handler_ctx->handler = handler;

    /* init mruby in every thread */
    if ((handler_ctx->mrb = mrb_open()) == NULL) {
        fprintf(stderr, "%s: no memory\n", H2O_MRUBY_MODULE_NAME);
        abort();
    }
    /* compile code (must be done for each thread) */
    int arena = mrb_gc_arena_save(handler_ctx->mrb);
    handler_ctx->proc = h2o_mruby_compile_code(handler_ctx->mrb, &handler->config, NULL);
    mrb_gc_arena_restore(handler_ctx->mrb, arena);
    mrb_gc_protect(handler_ctx->mrb, handler_ctx->proc);

    h2o_context_set_handler_context(ctx, &handler->super, handler_ctx);
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &handler->super);

    if (handler_ctx == NULL)
        return;

    mrb_close(handler_ctx->mrb);
    free(handler_ctx);
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    h2o_mruby_handler_t *handler = (void *)_handler;

    free(handler->config.source.base);
    free(handler->config.path);
    free(handler);
}

static void report_exception(h2o_req_t *req, mrb_state *mrb)
{
    mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
    struct RString *error = mrb_str_ptr(obj);
    h2o_req_log_error(req, H2O_MRUBY_MODULE_NAME, "%s: mruby raised: %s\n", H2O_MRUBY_MODULE_NAME, error->as.heap.ptr);
    mrb->exc = NULL;
}

static void stringify_address(h2o_conn_t *conn, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *), mrb_state *mrb,
                              mrb_value *host, mrb_value *port)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    char buf[NI_MAXHOST];

    *host = mrb_nil_value();
    *port = mrb_nil_value();

    if ((sslen = cb(conn, (void *)&ss)) == 0)
        return;
    size_t l = h2o_socket_getnumerichost((void *)&ss, sslen, buf);
    if (l != SIZE_MAX)
        *host = mrb_str_new(mrb, buf, l);
    int32_t p = h2o_socket_getport((void *)&ss);
    if (p != -1) {
        l = (int)sprintf(buf, "%" PRIu16, (uint16_t)p);
        *port = mrb_str_new(mrb, buf, l);
    }
}

static mrb_value build_env(h2o_req_t *req, mrb_state *mrb)
{
    mrb_value env = mrb_hash_new_capa(mrb, 16);
    mrb_int arena = mrb_gc_arena_save(mrb);

    /* environment */
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "REQUEST_METHOD"), mrb_str_new(mrb, req->method.base, req->method.len));
    size_t confpath_len_wo_slash = req->pathconf->path.len - 1;
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "SCRIPT_NAME"), mrb_str_new(mrb, req->pathconf->path.base, confpath_len_wo_slash));
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "PATH_INFO"), mrb_str_new(mrb, req->path_normalized.base + confpath_len_wo_slash,
                                                                          req->path_normalized.len - confpath_len_wo_slash));
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "QUERY_STRING"),
                 req->query_at != SIZE_MAX
                     ? mrb_str_new(mrb, req->path.base + req->query_at + 1, req->path.len - (req->query_at + 1))
                     : mrb_str_new_lit(mrb, ""));
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "SERVER_NAME"),
                 mrb_str_new(mrb, req->hostconf->authority.host.base, req->hostconf->authority.host.len));
    {
        mrb_value h, p;
        stringify_address(req->conn, req->conn->get_sockname, mrb, &h, &p);
        if (!mrb_nil_p(h))
            mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "SERVER_ADDR"), h);
        if (!mrb_nil_p(p))
            mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "SERVER_PORT"), p);
    }
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "HTTP_HOST"), mrb_str_new(mrb, req->authority.base, req->authority.len));
    if (req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", req->entity.len);
        mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "CONTENT_LENGTH"), mrb_str_new(mrb, buf, l));
    }
    {
        mrb_value h, p;
        stringify_address(req->conn, req->conn->get_peername, mrb, &h, &p);
        if (!mrb_nil_p(h))
            mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "REMOTE_ADDR"), h);
        if (!mrb_nil_p(p))
            mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "REMOTE_PORT"), p);
    }
    mrb_gc_arena_restore(mrb, arena);

    /* headers */
    size_t i = 0;
    for (i = 0; i != req->headers.size; ++i) {
        const h2o_header_t *header = req->headers.entries + i;
        if (header->name == &H2O_TOKEN_CONTENT_TYPE->buf) {
            mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "CONTENT_TYPE"), mrb_str_new(mrb, header->value.base, header->value.len));
        } else {
#define KEY_PREFIX "HTTP_"
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1)
            char *keybuf, keybuf_short[256];
            if (header->name->len <= sizeof(keybuf_short) - KEY_PREFIX_LEN) {
                keybuf = keybuf_short;
            } else {
                keybuf = h2o_mem_alloc(header->name->len + KEY_PREFIX_LEN);
            }
            memcpy(keybuf, KEY_PREFIX, KEY_PREFIX_LEN);
            char *d = keybuf + KEY_PREFIX_LEN, *end = d + header->name->len;
            const char *s = header->name->base;
            for (; d != end; ++d, ++s)
                *d = *s == '-' ? '_' : h2o_toupper(*s);
            mrb_hash_set(mrb, env, mrb_str_new(mrb, keybuf, header->name->len + KEY_PREFIX_LEN),
                         mrb_str_new(mrb, header->value.base, header->value.len));
            if (keybuf != keybuf_short)
                free(keybuf);
#undef KEY_PREFIX
#undef KEY_PREFIX_LEN
        }
        mrb_gc_arena_restore(mrb, arena);
    }

    /* rack.* */
    /* TBD rack.version? */
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "rack.url_scheme"),
                 mrb_str_new(mrb, req->scheme->name.base, req->scheme->name.len));
    /* we are using shared-none architecture, and therefore declare ourselves as multiprocess */
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "rack.multithread"), mrb_false_value());
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "rack.multiprocess"), mrb_true_value());
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "rack.run_once"), mrb_false_value());
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "rack.hijack?"), mrb_false_value());

    /* server name */
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "server.name"), mrb_str_new_lit(mrb, "h2o"));
    mrb_hash_set(mrb, env, mrb_str_new_lit(mrb, "server.version"), mrb_str_new_lit(mrb, H2O_VERSION));

    return env;
}

static int parse_rack_headers(h2o_req_t *req, mrb_state *mrb, mrb_value hash)
{
    mrb_value keys = mrb_hash_keys(mrb, hash);
    mrb_int i, len = mrb_ary_len(mrb, keys);

    for (i = 0; i != len; ++i) {
        mrb_value k = mrb_ary_entry(keys, i);
        /* convert to value to string */
        mrb_value v = mrb_hash_get(mrb, hash, k);
        if (!mrb_string_p(v)) {
            v = mrb_str_to_str(mrb, v);
            if (mrb->exc != NULL) {
                report_exception(req, mrb);
                return -1;
            }
        }
        /* convert key to string */
        if (!mrb_string_p(k)) {
            k = mrb_str_to_str(mrb, k);
            if (mrb->exc != NULL) {
                report_exception(req, mrb);
                return -1;
            }
        }
        /* register */
        h2o_iovec_t vdup = h2o_strdup(&req->pool, RSTRING_PTR(v), RSTRING_LEN(v));
        h2o_add_header_by_str(&req->pool, &req->res.headers, RSTRING_PTR(k), RSTRING_LEN(k), 1, vdup.base, vdup.len);
    }

    return 0;
}

static int parse_rack_response(h2o_req_t *req, mrb_state *mrb, mrb_value resp, h2o_iovec_t *content)
{
    if (!mrb_array_p(resp)) {
        h2o_req_log_error(req, H2O_MRUBY_MODULE_NAME, "handler did not return an array");
        return -1;
    }

    { /* fetch status */
        mrb_value v = mrb_to_int(mrb, mrb_ary_entry(resp, 0));
        if (mrb->exc != NULL) {
            report_exception(req, mrb);
            return -1;
        }
        int status = mrb_fixnum(v);
        if (!(100 <= status && status <= 999)) {
            h2o_req_log_error(req, H2O_MRUBY_MODULE_NAME, "status returned by handler is out of range:%d\n", status);
            return -1;
        }
        req->res.status = status;
    }

    { /* fetch and set the headers */
        mrb_value hash = mrb_ary_entry(resp, 1);
        if (!mrb_hash_p(hash)) {
            h2o_req_log_error(req, H2O_MRUBY_MODULE_NAME, "2nd element of the array returned by the handler is not a hash");
            return -1;
        }
        if (parse_rack_headers(req, mrb, hash) != 0)
            return -1;
    }

    { /* convert response to string */
        mrb_value body = mrb_ary_entry(resp, 2);
        if (!mrb_array_p(body)) {
            h2o_req_log_error(req, H2O_MRUBY_MODULE_NAME, "3rd element of the array returned by the handler is not an array");
            return -1;
        }
        mrb_int i, len = mrb_ary_len(mrb, body);
        /* calculate the length of the output, while at the same time converting the elements of the output array to string */
        content->len = 0;
        for (i = 0; i != len; ++i) {
            mrb_value e = mrb_ary_entry(body, i);
            if (!mrb_string_p(e)) {
                e = mrb_str_to_str(mrb, e);
                if (mrb->exc != NULL) {
                    report_exception(req, mrb);
                    return -1;
                }
                mrb_ary_set(mrb, body, i, e);
            }
            content->len += RSTRING_LEN(e);
        }
        /* allocate memory */
        char *dst = content->base = h2o_mem_alloc_pool(&req->pool, content->len);
        for (i = 0; i != len; ++i) {
            mrb_value e = mrb_ary_entry(body, i);
            assert(mrb_string_p(e));
            memcpy(dst, RSTRING_PTR(e), RSTRING_LEN(e));
            dst += RSTRING_LEN(e);
        }
    }

    return 0;
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_context_get_handler_context(req->conn->ctx, &handler->super);
    mrb_state *mrb = handler_ctx->mrb;
    h2o_iovec_t content;

    /* call rack handler */
    mrb_value env = build_env(req, mrb);
    mrb_value resp = mrb_funcall_argv(mrb, handler_ctx->proc, mrb_intern_lit(mrb, "call"), 1, &env);
    if (mrb->exc != NULL) {
        report_exception(req, mrb);
        goto SendInternalError;
    }

    /* parse the resposne */
    if (parse_rack_response(req, mrb, resp, &content) != 0)
        goto SendInternalError;

    /* fall through or send the response */
    if (req->res.status == STATUS_FALLTHRU)
        return -1;
    h2o_send_inline(req, content.base, content.len);
    return 0;

SendInternalError:
    h2o_send_error(req, 500, "Internal Server Error", "Internal Server Error", 0);
    return 0;
}

h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *vars)
{
    h2o_mruby_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->config.source = h2o_strdup(NULL, vars->source.base, vars->source.len);
    if (vars->path != NULL)
        handler->config.path = h2o_strdup(NULL, vars->path, SIZE_MAX).base;

    return handler;
}
