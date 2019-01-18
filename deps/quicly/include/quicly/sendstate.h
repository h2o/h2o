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
#ifndef quicly_sendstate_h
#define quicly_sendstate_h

#include "quicly/ranges.h"

typedef struct st_quicly_sendstate_t {
    /**
     * ranges that have been acked (guaranteed to be non-empty; i.e., acked.ranges[0].end == contiguous_acked_offset)
     */
    quicly_ranges_t acked;
    /**
     * ranges that needs to be sent
     */
    quicly_ranges_t pending;
    /**
     * number's of bytes being committed; i.e. max(end) that's been inserted into pending
     */
    uint64_t size_committed : 63;
    /**
     *
     */
    uint64_t is_open : 1;
} quicly_sendstate_t;

typedef struct st_quicly_sendstate_sent_t {
    uint64_t start;
    uint64_t end;
} quicly_sendstate_sent_t;

void quicly_sendstate_init(quicly_sendstate_t *state);
void quicly_sendstate_init_closed(quicly_sendstate_t *state);
void quicly_sendstate_dispose(quicly_sendstate_t *state);
static int quicly_sendstate_transfer_complete(quicly_sendstate_t *state);
int quicly_sendstate_activate(quicly_sendstate_t *state);
int quicly_sendstate_shutdown(quicly_sendstate_t *state, uint64_t end_off);
int quicly_sendstate_acked(quicly_sendstate_t *state, quicly_sendstate_sent_t *args, int is_active, size_t *bytes_to_shift);
int quicly_sendstate_lost(quicly_sendstate_t *state, quicly_sendstate_sent_t *args);

/* inline definitions */

inline int quicly_sendstate_transfer_complete(quicly_sendstate_t *state)
{
    return !state->is_open && state->acked.ranges[0].end == state->size_committed;
}

#endif
