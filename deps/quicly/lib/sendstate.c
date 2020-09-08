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
#include <stdlib.h>
#include <string.h>
#include "picotls.h"
#include "quicly/constants.h"
#include "quicly/sendstate.h"

void quicly_sendstate_init(quicly_sendstate_t *state)
{
    quicly_ranges_init_with_range(&state->acked, 0, 0);
    quicly_ranges_init(&state->pending);
    state->size_inflight = 0;
    state->final_size = UINT64_MAX;
}

void quicly_sendstate_init_closed(quicly_sendstate_t *state)
{
    quicly_sendstate_init(state);
    state->acked.ranges[0].end = 1;
    state->final_size = 0;
}

void quicly_sendstate_dispose(quicly_sendstate_t *state)
{
    quicly_ranges_clear(&state->acked);
    quicly_ranges_clear(&state->pending);
    state->final_size = 0;
    state->size_inflight = 0;
}

int quicly_sendstate_activate(quicly_sendstate_t *state)
{
    uint64_t end_off = state->final_size;

    /* take EOS position into account */
    if (end_off != UINT64_MAX)
        ++end_off;

    /* do nothing if already active */
    if (state->pending.num_ranges != 0 && state->pending.ranges[state->pending.num_ranges - 1].end == end_off)
        return 0;

    return quicly_ranges_add(&state->pending, state->size_inflight, end_off);
}

int quicly_sendstate_shutdown(quicly_sendstate_t *state, uint64_t final_size)
{
    int ret;

    assert(quicly_sendstate_is_open(state));
    assert(state->size_inflight <= final_size);

    if (state->pending.num_ranges != 0 && state->pending.ranges[state->pending.num_ranges - 1].end == UINT64_MAX) {
        state->pending.ranges[state->pending.num_ranges - 1].end = final_size + 1;
    } else {
        if ((ret = quicly_ranges_add(&state->pending, state->size_inflight, final_size + 1)) != 0)
            return ret;
    }

    state->final_size = final_size;
    return 0;
}

void quicly_sendstate_reset(quicly_sendstate_t *state)
{
    int ret;

    if (state->final_size == UINT64_MAX)
        state->final_size = state->size_inflight;

    ret = quicly_ranges_add(&state->acked, 0, state->final_size + 1);
    assert(ret == 0 && "guaranteed to succeed, because the numebr of ranges never increases");
    quicly_ranges_clear(&state->pending);
}

static int check_amount_of_state(quicly_sendstate_t *state)
{
    size_t num_ranges = state->acked.num_ranges + state->pending.num_ranges;

    /* bail out if number of gaps are small */
    if (PTLS_LIKELY(num_ranges < 32))
        return 0;

    /* When there are large number of gaps, make sure that the amount of state retained in quicly is relatively smaller than the
     * amount of state retained by application (in form of the stream-level send buffer). 512 is used as the threshold, based on the
     * assumption that the STREAM frames that have been sent are on average at least 512 bytes long, when seeing excess number of
     * gaps. */
    int64_t bytes_buffered = (int64_t)state->size_inflight - (int64_t)state->acked.ranges[0].end;
    if ((int64_t)num_ranges * 512 > bytes_buffered)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    return 0;
}

int quicly_sendstate_acked(quicly_sendstate_t *state, quicly_sendstate_sent_t *args, int is_active, size_t *bytes_to_shift)
{
    uint64_t prev_sent_upto = state->acked.ranges[0].end;
    int ret;

    /* adjust acked and pending ranges */
    if ((ret = quicly_ranges_add(&state->acked, args->start, args->end)) != 0)
        return ret;
    if (!is_active) {
        if ((ret = quicly_ranges_subtract(&state->pending, args->start, args->end)) != 0)
            return ret;
    }
    assert(state->pending.num_ranges == 0 || state->acked.ranges[0].end <= state->pending.ranges[0].start);

    /* calculate number of bytes that can be retired from the send buffer */
    if (prev_sent_upto != state->acked.ranges[0].end) {
        uint64_t sent_upto = state->acked.ranges[0].end;
        if (sent_upto > state->final_size) {
            /* adjust EOS position */
            assert(sent_upto == state->final_size + 1);
            --sent_upto;
        }
        *bytes_to_shift = sent_upto - prev_sent_upto;
    } else {
        *bytes_to_shift = 0;
    }

    return check_amount_of_state(state);
}

int quicly_sendstate_lost(quicly_sendstate_t *state, quicly_sendstate_sent_t *args)
{
    uint64_t start = args->start, end = args->end;
    size_t acked_slot = 0;
    int ret;

    while (start < end) {
        if (start < state->acked.ranges[acked_slot].end)
            start = state->acked.ranges[acked_slot].end;
        ++acked_slot;
        if (acked_slot == state->acked.num_ranges || end <= state->acked.ranges[acked_slot].start) {
            if (start < end) {
                if ((ret = quicly_ranges_add(&state->pending, start, end)) != 0)
                    return ret;
            }
            goto Exit;
        }
        if (start < state->acked.ranges[acked_slot].start) {
            if ((ret = quicly_ranges_add(&state->pending, start, state->acked.ranges[acked_slot].start)) != 0)
                return ret;
        }
    }

Exit:
    assert(state->pending.num_ranges == 0 || state->acked.ranges[0].end <= state->pending.ranges[0].start);
    return check_amount_of_state(state);
}
