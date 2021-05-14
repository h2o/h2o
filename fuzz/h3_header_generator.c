/*
 * Copyright (c) 2021 Fastly, Inc.
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

#include <stdio.h>

#include "h2o.h"
#include "h2o/qpack.h"

int main(int argc, char *argv[])
{
    FILE *fp;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [output-file]\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    h2o_qpack_encoder_t *enc = h2o_qpack_create_encoder(4096, 10);
    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);
    h2o_iovec_t headers_frame =
        h2o_qpack_flatten_request(enc, &pool, 0, NULL, h2o_iovec_init(H2O_STRLIT("GET")), &H2O_URL_SCHEME_HTTPS,
                                  h2o_iovec_init(H2O_STRLIT("www.example.com")), h2o_iovec_init(H2O_STRLIT("/")), NULL, 0);
    fwrite(headers_frame.base, headers_frame.len, 1, fp);
    h2o_mem_clear_pool(&pool);
    h2o_qpack_destroy_encoder(enc);

    fclose(fp);

    return 0;
}