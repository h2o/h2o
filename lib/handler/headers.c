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

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_headers_filter_t *self = (void *)_self;
    h2o_headers_command_t *cmd;

    for (cmd = self->cmds; cmd->cmd != H2O_HEADERS_CMD_NULL; ++cmd)
        h2o_rewrite_headers(&req->pool, &req->res.headers, cmd);

    h2o_setup_next_ostream(req, slot);
}

void h2o_headers_register(h2o_pathconf_t *pathconf, h2o_headers_command_t *cmds)
{
    struct st_headers_filter_t *self = (void *)h2o_create_filter(pathconf, sizeof(*self));

    self->super.on_setup_ostream = on_setup_ostream;
    self->cmds = cmds;
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
