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
#include "quicly/maxsender.h"

quicly_stream_id_t quicly_maxsender_should_update_stream_id(quicly_maxsender_t *m, quicly_stream_id_t next_stream_id,
                                                            uint32_t num_open_streams, uint32_t max_concurrent_streams,
                                                            uint32_t update_ratio)
{
    uint32_t num_avail_actual = max_concurrent_streams - num_open_streams,
             num_avail_sent = m->max_sent > next_stream_id ? (uint32_t)((m->max_sent - next_stream_id) / 4) : 0;
    quicly_stream_id_t send_value;

    /* ratio check */
    if ((uint64_t)num_avail_actual * update_ratio < (uint64_t)num_avail_sent * 1024)
        return -1;

    /* calculate the actual value to send as well as making adjustments */
    send_value = next_stream_id + num_avail_actual * 4 - 4;
    if (send_value >= (int64_t)1 << 62)
        send_value = (((int64_t)1 << 62) - 4) | (next_stream_id & 3);

    /* do not send one value more than once */
    if (send_value == m->max_sent)
        return -1;

    return send_value;
}
