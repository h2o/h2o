/*
 * Copyright (c) 2018 Fastly, Ichito Nagata
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
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"

struct st_server_timing_filter_t {
    h2o_filter_t super;
    unsigned enforce : 1;
};

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_server_timing_filter_t *self = (struct st_server_timing_filter_t *)_self;

    /* indicate the protocol handler to emit server timing header (basic and proxy properties) */
    req->send_server_timing = H2O_SEND_SERVER_TIMING_BASIC | H2O_SEND_SERVER_TIMING_PROXY;

    /* force chunked encoding for HTTP/1.1 if enforce flag is set */
    if (0x101 <= req->version && req->version < 0x200 && self->enforce)
        req->res.content_length = SIZE_MAX;

    h2o_setup_next_ostream(req, slot);
}

void h2o_server_timing_register(h2o_pathconf_t *pathconf, int enforce)
{
    struct st_server_timing_filter_t *self = (struct st_server_timing_filter_t *)h2o_create_filter(pathconf, sizeof(*self));
    self->super.on_setup_ostream = on_setup_ostream;
    self->enforce = enforce;
}
