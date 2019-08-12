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
#include "h2o.h"

struct st_headers_filter_t {
    h2o_filter_t super;
    h2o_headers_command_t *cmds;
};

struct st_headers_early_hints_handler_t {
    h2o_handler_t super;
    h2o_headers_command_t *cmds;
};

struct st_headers_early_hints_sender_t {
    h2o_req_t *req;
    h2o_headers_command_t *cmds;
    h2o_timer_t deferred_timeout_entry;
};

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_headers_filter_t *self = (void *)_self;
    h2o_headers_command_t *cmd;

    for (cmd = self->cmds; cmd->cmd != H2O_HEADERS_CMD_NULL; ++cmd) {
        if (cmd->when != H2O_HEADERS_CMD_WHEN_EARLY)
            h2o_rewrite_headers(&req->pool, &req->res.headers, cmd);
    }

    h2o_setup_next_ostream(req, slot);
}

static void on_informational(h2o_filter_t *_self, h2o_req_t *req)
{
    struct st_headers_filter_t *self = (void *)_self;
    h2o_headers_command_t *cmd;

    if (req->res.status != 103)
        return;

    for (cmd = self->cmds; cmd->cmd != H2O_HEADERS_CMD_NULL; ++cmd) {
        if (cmd->when != H2O_HEADERS_CMD_WHEN_FINAL)
            h2o_rewrite_headers(&req->pool, &req->res.headers, cmd);
    }
}

static void on_sender_deferred_timeout(h2o_timer_t *entry)
{
    struct st_headers_early_hints_sender_t *sender =
        H2O_STRUCT_FROM_MEMBER(struct st_headers_early_hints_sender_t, deferred_timeout_entry, entry);

    if (sender->req->res.status != 0)
        return;

    sender->req->res.status = 103;

    /* expect on_informational will be called and applies headers commands */
    h2o_send_informational(sender->req);
}

static void on_sender_dispose(void *_sender)
{
    struct st_headers_early_hints_sender_t *sender = (struct st_headers_early_hints_sender_t *)_sender;
    if (h2o_timer_is_linked(&sender->deferred_timeout_entry))
        h2o_timer_unlink(&sender->deferred_timeout_entry);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    struct st_headers_early_hints_handler_t *handler = (void *)_handler;

    struct st_headers_early_hints_sender_t *sender = h2o_mem_alloc_shared(&req->pool, sizeof(*sender), on_sender_dispose);
    sender->req = req;
    sender->cmds = handler->cmds;
    h2o_timer_init(&sender->deferred_timeout_entry, on_sender_deferred_timeout);
    h2o_timer_link(req->conn->ctx->loop, 0, &sender->deferred_timeout_entry);

    return -1;
}

static int requires_early_hints_handler(struct st_headers_filter_t *self)
{
    h2o_headers_command_t *cmd;
    for (cmd = self->cmds; cmd->cmd != H2O_HEADERS_CMD_NULL; ++cmd) {
        if (cmd->cmd != H2O_HEADERS_CMD_UNSET && cmd->when != H2O_HEADERS_CMD_WHEN_FINAL)
            return 1;
    }
    return 0;
}

void h2o_headers_register(h2o_pathconf_t *pathconf, h2o_headers_command_t *cmds)
{
    struct st_headers_filter_t *self = (void *)h2o_create_filter(pathconf, sizeof(*self));

    self->super.on_setup_ostream = on_setup_ostream;
    self->super.on_informational = on_informational;
    self->cmds = cmds;

    if (requires_early_hints_handler(self)) {
        struct st_headers_early_hints_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));
        handler->cmds = cmds;
        handler->super.on_req = on_req;

        /* move this handler to first */
        memmove(pathconf->handlers.entries + 1, pathconf->handlers.entries,
                sizeof(h2o_handler_t *) * (pathconf->handlers.size - 1));
        pathconf->handlers.entries[0] = &handler->super;
    }
}

int h2o_headers_is_prohibited_name(const h2o_token_t *token)
{
    /* prohibit connection-specific headers */
    if (token == H2O_TOKEN_CONNECTION || token == H2O_TOKEN_CONTENT_LENGTH || token == H2O_TOKEN_TRANSFER_ENCODING)
        return 1;
    /* prohibit headers added at protocol layer */
    if (token == H2O_TOKEN_DATE || token == H2O_TOKEN_SERVER)
        return 1;
    /* all others are permitted */
    return 0;
}
