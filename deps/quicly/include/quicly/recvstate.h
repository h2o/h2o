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
#ifndef quicly_recvstate_h
#define quicly_recvstate_h

#include <assert.h>
#include <stddef.h>
#include "picotls.h"
#include "quicly/ranges.h"

typedef struct st_quicly_recvstate_t {
    /**
     * ranges that have been received (starts and remains non-empty until transfer completes)
     */
    quicly_ranges_t received;
    /**
     * starting offset of data
     */
    uint64_t data_off;
    /**
     * end_of_stream offset (or UINT64_MAX)
     */
    uint64_t eos;
} quicly_recvstate_t;

void quicly_recvstate_init(quicly_recvstate_t *state);
void quicly_recvstate_init_closed(quicly_recvstate_t *state);
void quicly_recvstate_dispose(quicly_recvstate_t *state);
static int quicly_recvstate_transfer_complete(quicly_recvstate_t *state);
static size_t quicly_recvstate_bytes_available(quicly_recvstate_t *state);
int quicly_recvstate_update(quicly_recvstate_t *state, uint64_t off, size_t *len, int is_fin);
int quicly_recvstate_reset(quicly_recvstate_t *state, uint64_t eos_at, uint64_t *bytes_missing);

/* inline definitions */

inline int quicly_recvstate_transfer_complete(quicly_recvstate_t *state)
{
    return state->received.num_ranges == 0;
}

inline size_t quicly_recvstate_bytes_available(quicly_recvstate_t *state)
{
    assert(state->data_off <= state->received.ranges[0].end);
    return state->received.ranges[0].end - state->data_off;
}

#endif
