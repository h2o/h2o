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

static int has_te_trailer(const h2o_headers_t *headers)
{
    ssize_t te_index;
    h2o_iovec_t iter;
    const char *token;
    size_t token_len;

    if ((te_index = h2o_find_header(headers, H2O_TOKEN_TE, -1)) == -1)
        return 0;

    for (iter = headers->entries[te_index].value; (token = h2o_next_token(&iter, ',', &token_len, NULL)) != NULL;) {
#define TRAILERS "trailers"
        if (token_len >= sizeof(TRAILERS) - 1 && h2o_lcstris(token, sizeof(TRAILERS) - 1, H2O_STRLIT(TRAILERS))) {
            /* skip trailing space and check that the next char is `;` (or if the end of the token) */
            size_t i = sizeof(TRAILERS) - 1;
            for (; i < token_len && (token[i] == ' ' || token[i] == '\t'); ++i)
                ;
            if (i >= token_len || token[i] == ';')
                return 1;
        }
#undef TRAILERS
    }

    return 0;
}

static void on_setup_ostream(h2o_filter_t *_self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_server_timing_filter_t *self = (struct st_server_timing_filter_t *)_self;

    if (req->version == 0x200) {
        /* ok */
    } else if (0x101 <= req->version && req->version < 0x200) {
        if (self->enforce) {
            req->res.content_length = SIZE_MAX;
        } else {
            if (req->res.content_length != SIZE_MAX)
                goto Next;
            if (!has_te_trailer(&req->headers))
                goto Next;
        }
    } else {
        goto Next;
    }

    /* indicate the protocol handler to emit server timing */
    req->send_server_timing = 1;

Next:
    h2o_setup_next_ostream(req, slot);
}

void h2o_server_timing_register(h2o_pathconf_t *pathconf, int enforce)
{
    struct st_server_timing_filter_t *self = (struct st_server_timing_filter_t *)h2o_create_filter(pathconf, sizeof(*self));
    self->super.on_setup_ostream = on_setup_ostream;
    self->enforce = enforce;
}
