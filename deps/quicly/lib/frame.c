/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <string.h>
#include "quicly/frame.h"

uint8_t *quicly_encode_path_challenge_frame(uint8_t *dst, int is_response, const uint8_t *data)
{
    *dst++ = is_response ? QUICLY_FRAME_TYPE_PATH_RESPONSE : QUICLY_FRAME_TYPE_PATH_CHALLENGE;
    memcpy(dst, data, QUICLY_PATH_CHALLENGE_DATA_LEN);
    dst += QUICLY_PATH_CHALLENGE_DATA_LEN;
    return dst;
}

uint8_t *quicly_encode_ack_frame(uint8_t *dst, uint8_t *dst_end, quicly_ranges_t *ranges, uint64_t ack_delay)
{
#define WRITE_BLOCK(start, end)                                                                                                    \
    do {                                                                                                                           \
        uint64_t _start = (start), _end = (end);                                                                                   \
        assert(_start < _end);                                                                                                     \
        if (dst_end - dst < 8)                                                                                                     \
            return NULL;                                                                                                           \
        dst = quicly_encodev(dst, _end - _start - 1);                                                                              \
    } while (0)

    size_t range_index = ranges->num_ranges - 1;

    assert(ranges->num_ranges != 0);

    /* number of bytes being emitted without space check are 1 + 8 + 8 + 1 bytes (as defined in QUICLY_ACK_FRAME_CAPACITY) */
    *dst++ = QUICLY_FRAME_TYPE_ACK;
    dst = quicly_encodev(dst, ranges->ranges[range_index].end - 1); /* largest acknowledged */
    dst = quicly_encodev(dst, ack_delay);                           /* ack delay */
    QUICLY_BUILD_ASSERT(QUICLY_MAX_RANGES - 1 <= 63);
    *dst++ = (uint8_t)(ranges->num_ranges - 1); /* ack blocks */

    while (1) {
        WRITE_BLOCK(ranges->ranges[range_index].start, ranges->ranges[range_index].end); /* ACK block count */
        if (range_index-- == 0)
            break;
        WRITE_BLOCK(ranges->ranges[range_index].end, ranges->ranges[range_index + 1].start);
    }

    return dst;

#undef WRITE_BLOCK
}

int quicly_decode_ack_frame(const uint8_t **src, const uint8_t *end, quicly_ack_frame_t *frame, int is_ack_ecn)
{
    uint64_t i, num_gaps, gap, ack_range;

    if ((frame->largest_acknowledged = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((frame->ack_delay = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((num_gaps = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;

    if ((ack_range = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if (frame->largest_acknowledged < ack_range)
        goto Error;
    frame->smallest_acknowledged = frame->largest_acknowledged - ack_range;
    frame->ack_block_lengths[0] = ack_range + 1;
    frame->num_gaps = 0;

    for (i = 0; i != num_gaps; ++i) {
        if ((gap = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        if ((ack_range = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        if (i < QUICLY_ACK_MAX_GAPS) {
            if (frame->smallest_acknowledged < gap + ack_range + 2)
                goto Error;
            frame->gaps[i] = gap + 1;
            frame->ack_block_lengths[i + 1] = ack_range + 1;
            frame->smallest_acknowledged -= gap + ack_range + 2;
            ++frame->num_gaps;
        }
    }

    if (is_ack_ecn) {
        /* just skip ECT(0), ECT(1), ECT-CE counters for the time being */
        for (i = 0; i != 3; ++i)
            if (quicly_decodev(src, end) == UINT64_MAX)
                goto Error;
    }
    return 0;
Error:
    return QUICLY_TRANSPORT_ERROR_FRAME_ENCODING;
}

int quicly_tls_push_varint(ptls_buffer_t *buf, uint64_t v)
{
    size_t capacity = quicly_encodev_capacity(v);
    int ret;

    if ((ret = ptls_buffer_reserve(buf, capacity)) != 0)
        return ret;
    buf->off = quicly_encodev(buf->base + buf->off, v) - buf->base;

    return 0;
}

int quicly_tls_decode_varint(uint64_t *value, const uint8_t **src, const uint8_t *end)
{
    if ((*value = quicly_decodev(src, end)) == UINT64_MAX)
        return QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER;
    return 0;
}
