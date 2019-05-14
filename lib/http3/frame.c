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
#include "h2o/http3_common.h"

uint8_t *h2o_http3_encode_priority_frame(uint8_t *dst, const h2o_http3_priority_frame_t *frame)
{
    uint8_t *base = dst;

    ++dst; /* skip length; determined laterwards */
    *dst++ = H2O_HTTP3_FRAME_TYPE_PRIORITY;
    *dst++ = ((uint8_t)frame->prioritized.type << 6) | ((uint8_t)frame->dependency.type << 4);
    if (frame->prioritized.type != H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT)
        dst = quicly_encodev(dst, frame->prioritized.id_);
    if (frame->dependency.type != H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT)
        dst = quicly_encodev(dst, frame->dependency.id_);
    *dst++ = frame->weight_m1;
    *base = dst - (base + 2);

    assert(dst - base < H2O_HTTP3_PRIORITY_FRAME_CAPACITY);
    return dst;
}

int h2o_http3_decode_priority_frame(h2o_http3_priority_frame_t *frame, const uint8_t *payload, size_t len, const char **err_desc)
{
    const uint8_t *src = payload, *end = src + len;

    if (end - src < 2)
        goto Fail;

    if ((*src & 0xf) != 0)
        goto Fail;
    frame->prioritized.type = (*src >> 6) & 0x3;
    frame->dependency.type = (*src >> 4) & 0x3;
    ++src;
    if (frame->prioritized.type != H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT) {
        if ((frame->prioritized.id_ = quicly_decodev(&src, end)) == UINT64_MAX)
            goto Fail;
    } else {
        frame->prioritized.id_ = 0;
    }
    if (frame->dependency.type != H2O_HTTP3_PRIORITY_ELEMENT_TYPE_ABSENT) {
        if ((frame->dependency.id_ = quicly_decodev(&src, end)) == UINT64_MAX)
            goto Fail;
    } else {
        frame->dependency.id_ = 0;
    }
    if (end - src != 1)
        goto Fail;
    frame->weight_m1 = *src++;

    return 0;
Fail:
    *err_desc = "invalid PRIORITY frame";
    return H2O_HTTP3_ERROR_MALFORMED_FRAME(H2O_HTTP3_FRAME_TYPE_PRIORITY);
}
