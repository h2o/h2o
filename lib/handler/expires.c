/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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

struct st_expires_t {
    h2o_filter_t super;
    int mode;
    h2o_iovec_t value;
};

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_expires_t *self = (void *)_self;

    switch (req->res.status) {
    case 200:
    case 201:
    case 204:
    case 206:
    case 301:
    case 302:
    case 303:
    case 304:
    case 307:
        switch (self->mode) {
        case H2O_EXPIRES_MODE_ABSOLUTE:
            h2o_set_header(&req->pool, &req->res.headers, H2O_TOKEN_EXPIRES, self->value.base, self->value.len, 0);
            break;
        case H2O_EXPIRES_MODE_MAX_AGE:
            h2o_set_header_token(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, self->value.base, self->value.len);
            break;
        default:
            assert(0);
            break;
        }
        break;
    default:
        break;
    }

    h2o_setup_next_ostream(req, slot);
}

void h2o_expires_register(h2o_pathconf_t *pathconf, h2o_expires_args_t *args)
{
    struct st_expires_t *self = (void *)h2o_create_filter(pathconf, sizeof(*self));
    self->super.on_setup_ostream = on_setup_ostream;
    self->mode = args->mode;
    switch (args->mode) {
    case H2O_EXPIRES_MODE_ABSOLUTE:
        self->value = h2o_strdup(NULL, args->data.absolute, SIZE_MAX);
        break;
    case H2O_EXPIRES_MODE_MAX_AGE:
        self->value.base = h2o_mem_alloc(128);
        self->value.len = sprintf(self->value.base, "max-age=%" PRIu64, args->data.max_age);
        break;
    default:
        assert(0);
        break;
    }
}
