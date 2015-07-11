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

#ifdef H2O_USE_MRUBY

#include "h2o.h"
#include "h2o/mruby.h"
#include <mruby.h>
#include <mruby/proc.h>
#include <mruby/compile.h>
#include <mruby/string.h>

#include <errno.h>

void h2o_mrb_class_init(mrb_state *mrb);

enum code_type { H2O_MRUBY_STRING, H2O_MRUBY_FILE };

struct st_h2o_mruby_code_t {
    h2o_iovec_t *path;
    struct RProc *proc;
    mrbc_context *ctx;
    enum code_type type;
    unsigned int cache;
};

typedef struct st_h2o_mruby_code_t h2o_mruby_code_t;

struct st_h2o_mruby_context_t {
    h2o_mruby_handler_t *handler;
    mrb_state *mrb;

    /* TODO: add other hook code */
    h2o_mruby_code_t *h2o_mruby_handler_code;
};

typedef struct st_h2o_mruby_context_t h2o_mruby_context_t;

static void h2o_mruby_compile_code(mrb_state *mrb, h2o_iovec_t *path, h2o_mruby_code_t *code)
{
    struct mrb_parser_state *p;
    FILE *fp;

    if ((fp = fopen(path->base, "r")) == NULL) {
        code->proc = NULL;
        fprintf(stderr, "%s: failed to open mruby script: %s(%s)\n", H2O_MRUBY_MODULE_NAME, path->base, strerror(errno));
        return;
    }

    code->path = path;
    code->ctx = mrbc_context_new(mrb);
    mrbc_filename(mrb, code->ctx, code->path->base);
    if ((p = mrb_parse_file(mrb, fp, code->ctx)) == NULL) {
        code->proc = NULL;
        fclose(fp);
        fprintf(stderr, "%s: failed to mrb_parse_file: %s\n", H2O_MRUBY_MODULE_NAME, path->base);
        return;
    }
    code->proc = mrb_generate_code(mrb, p);

    fclose(fp);
    mrb_pool_close(p->pool);
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_mem_alloc(sizeof(*handler_ctx));

    handler_ctx->handler = handler;

    /* ctx has a mrb_state per thread */
    handler_ctx->mrb = mrb_open();
    h2o_mrb_class_init(handler_ctx->mrb);
    handler_ctx->h2o_mruby_handler_code = h2o_mem_alloc(sizeof(*handler_ctx->h2o_mruby_handler_code));

    if (handler_ctx->mrb) {
        h2o_mruby_compile_code(handler_ctx->mrb, &handler->config.mruby_handler_path, handler_ctx->h2o_mruby_handler_code);
    } else {
        fprintf(stderr, "%s: failed to mrb_open\n", H2O_MRUBY_MODULE_NAME);
    }
    h2o_context_set_handler_context(ctx, &handler->super, handler_ctx);
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_mruby_handler_t *handler = (void *)_handler;
    h2o_mruby_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &handler->super);

    if (handler_ctx == NULL)
        return;

    mrbc_context_free(handler_ctx->mrb, handler_ctx->h2o_mruby_handler_code->ctx);
    mrb_close(handler_ctx->mrb);
    free(handler_ctx);
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    h2o_mruby_handler_t *handler = (void *)_handler;

    free(handler->config.mruby_handler_path.base);
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

    if (mrb == NULL || handler_ctx->h2o_mruby_handler_code->proc == NULL) {
        fprintf(stderr, "%s: mruby core got unexpected error\n", H2O_MRUBY_MODULE_NAME);
        h2o_send_error(req, 500, "Internal Server Error", "Internal Server Error", 0);
        return 0;
    }

    ai = mrb_gc_arena_save(mrb);

    /* create mruby internal context into mrb state */
    mruby_ctx = h2o_mem_alloc_pool(&req->pool, sizeof(h2o_mruby_internal_context_t));
    mruby_ctx->req = req;
    mrb->ud = (void *)mruby_ctx;

    result = mrb_run(mrb, handler_ctx->h2o_mruby_handler_code->proc, mrb_top_self(mrb));

    if (mrb->exc) {
        mrb_value obj = mrb_funcall(mrb, mrb_obj_value(mrb->exc), "inspect", 0);
        struct RString *error = mrb_str_ptr(obj);
        fprintf(stderr, "%s: mruby raised: %s\n", H2O_MRUBY_MODULE_NAME, error->as.heap.ptr);
        mrb->exc = 0;
        h2o_send_error(req, 500, "Internal Server Error", "Internal Server Error", 0);
    } else {
        h2o_send_error(req, 200, "h2o_mruby dayo", mrb_str_to_cstr(mrb, result), 0);
    }
    mrb_gc_arena_restore(mrb, ai);

    return 0;
}

h2o_mruby_handler_t *h2o_mruby_register(h2o_pathconf_t *pathconf, h2o_mruby_config_vars_t *vars)
{
    h2o_mruby_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->config = *vars;
    if (vars->mruby_handler_path.base != NULL) {
        handler->config.mruby_handler_path = h2o_strdup(NULL, vars->mruby_handler_path.base, vars->mruby_handler_path.len);
    }

    return handler;
}

#endif /* H2O_USE_MRUBY */
