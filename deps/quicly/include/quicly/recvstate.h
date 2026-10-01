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

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include "picotls.h"
#include "quicly/ranges.h"

typedef struct st_quicly_recvstate_t {
    /**
     * Ranges that have been received; always non-empty. When a reset is received, the end of the ranges could be past `eos`.
     */
    quicly_ranges_t received;
    /**
     * starting offset of data
     */
    uint64_t data_off;
    /**
     * Offset at which the stream ends, or UINT64_MAX while that is unknown. Iff a reset is received before the transfer is
     * complete, it becomes max(received[0].end, min(current_eos, reset_stream.reliable_size)); i.e., bytes already available to
     * the application are never taken back, but reset is surfaced once the needed bytes are delivered.
     */
    uint64_t eos;
    /**
     * application protocol error code of the reset that has been received, or UINT64_MAX if the stream has not been reset.
     */
    uint64_t app_error_code;
} quicly_recvstate_t;

void quicly_recvstate_init(quicly_recvstate_t *state);
void quicly_recvstate_init_closed(quicly_recvstate_t *state);
void quicly_recvstate_dispose(quicly_recvstate_t *state);
static int quicly_recvstate_transfer_complete(quicly_recvstate_t *state);
static size_t quicly_recvstate_bytes_available(quicly_recvstate_t *state);
/**
 * Returns the offset up to which memory has been allocated for the stream. Used for flow credit management.
 */
static uint64_t quicly_recvstate_bytes_allocated(quicly_recvstate_t *state);
/**
 * Records that the range identified by (*off, *len) has been received. When 0 (success) is returned, the pair is narrowed to the
 * bytes that need to be written to the receive buffer.
 */
quicly_error_t quicly_recvstate_update(quicly_recvstate_t *state, uint64_t *off, size_t *len, int is_fin, size_t max_ranges);
quicly_error_t quicly_recvstate_reset(quicly_recvstate_t *state, uint64_t final_size, uint64_t reliable_size,
                                      uint64_t app_error_code, uint64_t *bytes_missing);

/* inline definitions */

inline int quicly_recvstate_transfer_complete(quicly_recvstate_t *state)
{
    return state->received.ranges[0].start == 0 && state->received.ranges[0].end >= state->eos;
}

inline size_t quicly_recvstate_bytes_available(quicly_recvstate_t *state)
{
    uint64_t total = quicly_recvstate_transfer_complete(state) ? state->eos : state->received.ranges[0].end;
    assert(state->data_off <= total);
    return total - state->data_off;
}

inline uint64_t quicly_recvstate_bytes_allocated(quicly_recvstate_t *state)
{
    uint64_t end = state->received.ranges[state->received.num_ranges - 1].end;
    return state->eos != UINT64_MAX && state->eos > end ? state->eos : end;
}

#ifdef __cplusplus
}
#endif

#endif
