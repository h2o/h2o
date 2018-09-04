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

uint8_t *quicly_encode_ack_frame(uint8_t *dst, uint8_t *dst_end, uint64_t largest_pn, uint64_t ack_delay, quicly_ranges_t *ranges,
                                 size_t *range_index)
{
    uint8_t num_blocks = 0, *num_blocks_at;

    *dst++ = QUICLY_FRAME_TYPE_ACK;
    dst = quicly_encodev(dst, largest_pn);                    /* largest acknowledged */
    dst = quicly_encodev(dst, ack_delay);                     /* ack delay */
    num_blocks_at = dst++;                                    /* slot for num_blocks */
    if (largest_pn == ranges->ranges[*range_index].end - 1) { /* first ack block */
        dst = quicly_encodev(dst, ranges->ranges[*range_index].end - ranges->ranges[*range_index].start - 1);
        --*range_index;
    } else {
        dst = quicly_encodev(dst, 0);
    }

    while (*range_index != SIZE_MAX && dst_end - dst >= 16 && num_blocks < 63) {
        dst = quicly_encodev(dst, ranges->ranges[*range_index + 1].start - ranges->ranges[*range_index].end - 1); /* gap */
        dst = quicly_encodev(dst, ranges->ranges[*range_index].end - ranges->ranges[*range_index].start - 1);     /* ack block */
        --*range_index;
        ++num_blocks;
    }

    *num_blocks_at = num_blocks;
    return dst;
}

int quicly_decode_ack_frame(const uint8_t **src, const uint8_t *end, quicly_ack_frame_t *frame)
{
    uint64_t i, tmp;

    if ((frame->largest_acknowledged = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((frame->ack_delay = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if ((frame->num_gaps = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;

    if ((tmp = quicly_decodev(src, end)) == UINT64_MAX)
        goto Error;
    if (frame->largest_acknowledged < tmp)
        goto Error;
    frame->smallest_acknowledged = frame->largest_acknowledged - tmp;
    frame->ack_block_lengths[0] = tmp + 1;

    for (i = 0; i != frame->num_gaps; ++i) {
        if ((tmp = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        frame->gaps[i] = tmp + 1;
        if (frame->smallest_acknowledged < frame->gaps[i])
            goto Error;
        frame->smallest_acknowledged -= frame->gaps[i];
        if ((tmp = quicly_decodev(src, end)) == UINT64_MAX)
            goto Error;
        tmp += 1;
        if (frame->smallest_acknowledged < tmp)
            goto Error;
        frame->ack_block_lengths[i + 1] = tmp;
        frame->smallest_acknowledged -= tmp;
    }

    return 0;
Error:
    return QUICLY_ERROR_FRAME_ERROR(QUICLY_FRAME_TYPE_ACK);
}
