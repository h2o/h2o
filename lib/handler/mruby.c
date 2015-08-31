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
#include <stdio.h>
#include <stdlib.h>
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/compile.h>
#include <mruby/string.h>
#include "h2o.h"
#include "h2o/mruby_.h"

void h2o_mrb_class_init(mrb_state *mrb);

struct st_h2o_mruby_context_t {
    h2o_mruby_handler_t *handler;
    mrb_state *mrb;
    /* TODO: add other hook code */
    struct RProc *proc;
};

typedef struct st_h2o_mruby_context_t h2o_mruby_context_t;

struct RProc *h2o_mruby_compile_code(mrb_state *mrb, h2o_mruby_config_vars_t *config, char *errbuf)
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

Exit:
    mrb_parser_free(parser);
    mrbc_context_free(mrb, cxt);
    return proc;
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
    h2o_mrb_class_init(handler_ctx->mrb);
    /* compile code (must be done for each thread) */
    handler_ctx->proc = h2o_mruby_compile_code(handler_ctx->mrb, &handler->config, NULL);

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

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_context_get_handler_context(req->conn->ctx, &handler->super);
    h2o_mruby_internal_context_t *mruby_ctx;
    mrb_state *mrb = handler_ctx->mrb;
    mrb_value result;
    mrb_int ai;

    if (mrb == NULL || handler_ctx->proc == NULL) {
        fprintf(stderr, "%s: mruby core got unexpected error\n", H2O_MRUBY_MODULE_NAME);
        h2o_send_error(req, 500, "Internal Server Error", "Internal Server Error", 0);
        return 0;
    }

    ai = mrb_gc_arena_save(mrb);

    /* create mruby internal context into mrb state */
    mruby_ctx = h2o_mem_alloc_pool(&req->pool, sizeof(h2o_mruby_internal_context_t));
    mruby_ctx->req = req;
    mruby_ctx->state = H2O_MRUBY_STATE_UNDETERMINED;
    mrb->ud = (void *)mruby_ctx;
    req->res.status = 0;

    result = mrb_run(mrb, handler_ctx->proc, mrb_top_self(mrb));

    if (mrb->exc) {
        mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
        struct RString *error = mrb_str_ptr(obj);
        fprintf(stderr, "%s: mruby raised: %s\n", H2O_MRUBY_MODULE_NAME, error->as.heap.ptr);
        mrb->exc = 0;
        if (mruby_ctx->state == H2O_MRUBY_STATE_UNDETERMINED) {
            h2o_send_error(req, 500, "Internal Server Error", "Internal Server Error", 0);
            mruby_ctx->state = H2O_MRUBY_STATE_RESPONSE_SENT;
        }
    } else if (!mrb_nil_p(result)) {
        if (mruby_ctx->state == H2O_MRUBY_STATE_UNDETERMINED) {
            /* convert to string */
            result = mrb_str_to_str(mrb, result);
            if (req->res.status == 0) {
                req->res.status = 200;
                req->res.reason = "OK";
            }
            if (h2o_find_header(&req->res.headers, H2O_TOKEN_CONTENT_TYPE, -1) == -1)
                h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT(H2O_MRUBY_DEFAULT_CONTENT_TYPE));
            h2o_send_inline(req, h2o_strdup(&req->pool, RSTRING_PTR(result), RSTRING_LEN(result)).base, RSTRING_LEN(result));
            mruby_ctx->state = H2O_MRUBY_STATE_RESPONSE_SENT;
        }
    }

    mrb_gc_arena_restore(mrb, ai);
    return mruby_ctx->state == H2O_MRUBY_STATE_RESPONSE_SENT ? 0 : -1;
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
