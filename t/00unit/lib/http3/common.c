/*
 * Copyright (c) 2026 Fastly, Inc.
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
#include "../../test.h"
#include "../../../../lib/http3/common.c"

static void test_partial_unistream_type(void)
{
    /* stream types whose varint encodings are 2 and 8 bytes long, delivered one or more bytes short */
    static const uint8_t two[] = {0x40, 0x21}, eight[] = {0xc0, 0, 0, 0, 0, 0, 0, 0x21};
    const struct {
        const uint8_t *bytes;
        size_t avail;
    } cases[] = {{two, 1}, {eight, 1}, {eight, 3}, {eight, 7}};

    for (size_t i = 0; i != PTLS_ELEMENTSOF(cases); ++i) {
        struct st_h2o_http3_ingress_unistream_t stream = {.handle_input = unknown_type_handle_input};
        const uint8_t *src = cases[i].bytes;
        /* the incomplete path returns before touching the connection */
        unknown_type_handle_input(NULL, &stream, &src, cases[i].bytes + cases[i].avail, 0);
        ok(src == cases[i].bytes);
        ok(stream.handle_input == unknown_type_handle_input);
    }
}

void test_lib__http3_common(void)
{
    subtest("partial unidirectional stream type", test_partial_unistream_type);
}
