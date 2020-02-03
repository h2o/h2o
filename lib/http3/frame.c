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
#include "h2o/absprio.h"
#include "h2o/http3_common.h"

uint8_t *h2o_http3_encode_priority_update_frame(uint8_t *dst, const h2o_http3_priority_update_frame_t *frame)
{
    *dst++ = H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE;
    *dst++ = frame->element_is_push ? 0x80 : 0;
    dst = quicly_encodev(dst, frame->element);
    *dst++ = 'u';
    *dst++ = '=';
    *dst++ = '0' + frame->priority.urgency;
    if (!frame->priority.incremental) {
        static const h2o_iovec_t s = {H2O_STRLIT(",i=1")};
        memcpy(dst, s.base, s.len);
        dst += s.len;
    }
    return dst;
}

int h2o_http3_decode_priority_update_frame(h2o_http3_priority_update_frame_t *frame, const uint8_t *payload, size_t len,
                                           const char **err_desc)
{
    const uint8_t *src = payload, *end = src + len;

    if (src == end)
        return H2O_HTTP3_ERROR_FRAME;
    frame->element_is_push = (*src++ & 0x80) != 0;
    if ((frame->element = quicly_decodev(&src, end)) == UINT64_MAX) {
        *err_desc = "invalid PRIORITY frame";
        return H2O_HTTP3_ERROR_FRAME;
    }
    if (!frame->element_is_push) {
        if (!(quicly_stream_is_client_initiated(frame->element) && !quicly_stream_is_unidirectional(frame->element)))
            return H2O_HTTP3_ERROR_FRAME;
    }
    frame->priority = h2o_absprio_default;
    h2o_absprio_parse_priority((const char *)src, end - src, &frame->priority);

    return 0;
}
