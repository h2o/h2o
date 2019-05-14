/*
 * Copyright (c) 2019 Fastly, Kazuho Oku
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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/http3/frame.c"

static void test_priority(void)
{
    h2o_mem_pool_t pool;
    h2o_http3_priority_frame_t frame;
    const char *err_desc;
    uint8_t encoded[H2O_HTTP3_PRIORITY_FRAME_CAPACITY];
    size_t encoded_len;
    int ret;

    h2o_mem_init_pool(&pool);

    /* encode */
    frame.prioritized.type = H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT;
    frame.prioritized.id_ = 12345; /* should be ignored */
    frame.dependency.type = H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT;
    frame.dependency.id_ = 67890; /* ignored */
    frame.weight_m1 = 123;
    encoded_len = h2o_http3_encode_priority_frame(encoded, &frame) - encoded;

    /* decode */
    ok(encoded_len == 1 + 1 + 1 + 1);
    ok(encoded[0] == encoded_len - 2);
    ok(encoded[1] == H2O_HTTP3_FRAME_TYPE_PRIORITY);
    memset(&frame, 0, sizeof(frame));
    ret = h2o_http3_decode_priority_frame(&frame, (const uint8_t *)encoded + 2, encoded_len - 2, &err_desc);
    ok(ret == 0);
    ok(frame.prioritized.type == H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT);
    ok(frame.prioritized.id_ == 0);
    ok(frame.dependency.type == H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT);
    ok(frame.dependency.id_ == 0);
    ok(frame.weight_m1 == 123);

    /* encode one that specifies prioritized element id */
    frame.prioritized.type = H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PLACEHOLDER;
    frame.prioritized.id_ = 12345; /* should be ignored */
    encoded_len = h2o_http3_encode_priority_frame(encoded, &frame) - encoded;

    /* decode */
    ok(encoded_len == 1 + 1 + 1 + 2 + 1);
    ok(encoded[0] == encoded_len - 2);
    ok(encoded[1] == H2O_HTTP3_FRAME_TYPE_PRIORITY);
    memset(&frame, 0, sizeof(frame));
    ret = h2o_http3_decode_priority_frame(&frame, (const uint8_t *)encoded + 2, encoded_len - 2, &err_desc);
    ok(ret == 0);
    ok(frame.prioritized.type == H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PLACEHOLDER);
    ok(frame.prioritized.id_ == 12345);
    ok(frame.dependency.type == H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT);
    ok(frame.dependency.id_ == 0);
    ok(frame.weight_m1 == 123);

    /* encode one that specifies both the element ids */
    frame.dependency.type = H2O_HTTP3_PRIORITY_ELEMENT_TYPE_REQUEST_STREAM;
    frame.dependency.id_ = 67890; /* should be ignored */
    encoded_len = h2o_http3_encode_priority_frame(encoded, &frame) - encoded;

    /* decode */
    ok(encoded_len == 1 + 1 + 1 + 2 + 4 + 1);
    ok(encoded[0] == encoded_len - 2);
    ok(encoded[1] == H2O_HTTP3_FRAME_TYPE_PRIORITY);
    memset(&frame, 0, sizeof(frame));
    ret = h2o_http3_decode_priority_frame(&frame, (const uint8_t *)encoded + 2, encoded_len - 2, &err_desc);
    ok(ret == 0);
    ok(frame.prioritized.type == H2O_HTTP3_PRIORITY_ELEMENT_TYPE_PLACEHOLDER);
    ok(frame.prioritized.id_ == 12345);
    ok(frame.dependency.type == H2O_HTTP3_PRIORITY_ELEMENT_TYPE_REQUEST_STREAM);
    ok(frame.dependency.id_ == 67890);
    ok(frame.weight_m1 == 123);

    /* check decode errors */
    ret = h2o_http3_decode_priority_frame(&frame, (const uint8_t *)encoded + 2, 1, &err_desc);
    ok(ret != 0);
    ret = h2o_http3_decode_priority_frame(&frame, (const uint8_t *)encoded + 2, encoded_len - 1, &err_desc);
    ok(ret != 0);

    h2o_mem_clear_pool(&pool);
}

void test_lib__http3_frames(void)
{
    subtest("priority", test_priority);
}
