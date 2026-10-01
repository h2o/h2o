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
    state->app_error_code = UINT64_MAX;
    state->reliable_size = 0;
    state->eos_state = QUICLY_SENDSTATE_EOS_STATE_UNSENT;
}

void quicly_sendstate_init_closed(quicly_sendstate_t *state)
{
    quicly_sendstate_init(state);
    state->final_size = 0;
    state->eos_state = QUICLY_SENDSTATE_EOS_STATE_DELIVERED;
}

void quicly_sendstate_dispose(quicly_sendstate_t *state)
{
    quicly_ranges_clear(&state->acked);
    quicly_ranges_clear(&state->pending);
    state->final_size = 0;
    state->size_inflight = 0;
}

int quicly_sendstate_transfer_complete(quicly_sendstate_t *state)
{
    if (state->acked.ranges[0].end == state->final_size) {
        if (state->eos_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED)
            return 1;
        if (state->app_error_code != UINT64_MAX && state->reliable_size == 0)
            return 1;
    }
    return 0;
}

int quicly_sendstate_is_fully_inflight(quicly_sendstate_t *state)
{
    return state->eos_state != QUICLY_SENDSTATE_EOS_STATE_UNSENT && state->size_inflight == state->final_size;
}

int quicly_sendstate_activate(quicly_sendstate_t *state)
{
    /* do nothing if already active */
    if (state->pending.num_ranges != 0 && state->pending.ranges[state->pending.num_ranges - 1].end == state->final_size)
        return 0;

    /* when the stream has been closed and everything below the final size has been sent, the range is empty and nothing is added;
     * what remains in that case is the marker that the stream ends with, which is not tracked as a range */
    return quicly_ranges_add(&state->pending, state->size_inflight, state->final_size);
}

int quicly_sendstate_shutdown(quicly_sendstate_t *state, uint64_t final_size)
{
    int ret;

    assert(state->size_inflight <= final_size);
    assert(state->eos_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT &&
           "where the stream ends cannot change once a frame saying so has gone out (RFC 9000 section 4.5)");

    /* the bytes below the final size that have yet to be sent are to be sent, those above it are not; the latter can be found in
     * `pending` when the stream is active, or when a shutdown that never went out is being withdrawn by a reset */
    if (state->size_inflight < final_size) {
        if ((ret = quicly_ranges_add(&state->pending, state->size_inflight, final_size)) != 0)
            return ret;
    }
    if ((ret = quicly_ranges_subtract(&state->pending, final_size, UINT64_MAX)) != 0)
        return ret;

    state->final_size = final_size;
    return 0;
}

int quicly_sendstate_reset(quicly_sendstate_t *state, uint64_t app_error_code, uint64_t reliable_size)
{
    int ret;

    /* reset is a no-op if the transfer is already complete */
    if (quicly_sendstate_transfer_complete(state))
        return 0;

    /* 2nd reset: it must not be a reliable reset and the error code must remain the same */
    if (state->app_error_code != UINT64_MAX)
        assert(reliable_size == 0 && state->app_error_code == app_error_code);

    if (state->size_inflight < state->final_size)
        state->final_size = reliable_size < state->size_inflight ? state->size_inflight : reliable_size;
    assert(reliable_size <= state->final_size);

    state->app_error_code = app_error_code;
    state->reliable_size = reliable_size;

    /* RESET_AT supersedes FIN; RESET supersedes RESET_AT */
    state->eos_state = QUICLY_SENDSTATE_EOS_STATE_UNSENT;

    /* retire the bytes at or above the reliable size; the peer is not to receive them, hence those below the final size are
     * accounted for as acked and nothing at all is left to be sent */
    if ((ret = quicly_ranges_add(&state->acked, reliable_size, state->final_size)) != 0)
        return ret;
    if ((ret = quicly_ranges_subtract(&state->pending, reliable_size, UINT64_MAX)) != 0)
        return ret;

    return 0;
}

static int check_amount_of_state(quicly_sendstate_t *state)
{
    size_t num_ranges = state->acked.num_ranges + state->pending.num_ranges;

    /* Bail out if number of gaps are small.
     * In case of HTTP/3, the worst case is when each HTTP request is received as a separate QUIC packet, and sending a small STREAM
     * frame carrying a HPACK encoder / decoder in response. If half of those STREAM frames are lost (note: loss of every other
     * packet can happen during slow start), `num_ranges` can become as large as `request_concurrency * 2`, as each gaps will be
     * recognized in `acked.num_ranges` and `pending.num_ranges`. */
    if (PTLS_LIKELY(num_ranges < 256))
        return 0;

    /* When there are large number of gaps, make sure that the amount of state retained in quicly is relatively smaller than the
     * amount of state retained by application (in form of the stream-level send buffer). 512 is used as the threshold, based on the
     * assumption that the STREAM frames that have been sent are on average at least 512 bytes long, when seeing excess number of
     * gaps. */
    int64_t bytes_buffered = (int64_t)state->size_inflight - (int64_t)state->acked.ranges[0].end;
    if ((int64_t)num_ranges * 128 > bytes_buffered)
        return QUICLY_ERROR_STATE_EXHAUSTION;

    return 0;
}

int quicly_sendstate_acked(quicly_sendstate_t *state, quicly_sendstate_sent_t *args, size_t *bytes_to_shift)
{
    uint64_t prev_sent_upto = state->acked.ranges[0].end;
    int ret;

    /* adjust acked and pending ranges; the range is empty when the frame carries nothing but the marker */
    if (args->start != args->end) {
        if ((ret = quicly_ranges_add(&state->acked, args->start, args->end)) != 0)
            return ret;
        if ((ret = quicly_ranges_subtract(&state->pending, args->start, args->end)) != 0)
            return ret;
        assert(state->pending.num_ranges == 0 || state->acked.ranges[0].end <= state->pending.ranges[0].start);
    }

    /* a frame that carries the marker the stream ends with tells the peer where it ends; one that carries a superseded marker
     * tells it nothing that still holds, and is ignored */
    if (args->eos_type != QUICLY_SENDSTATE_EOS_TYPE_NONE && args->eos_type == quicly_sendstate_eos_type(state))
        state->eos_state = QUICLY_SENDSTATE_EOS_STATE_DELIVERED;

    /* calculate number of bytes that can be retired from the send buffer */
    *bytes_to_shift = state->acked.ranges[0].end - prev_sent_upto;

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

    /* the marker is to be sent again, unless the frame that was lost carried one that has since been superseded, or unless the
     * marker has been delivered by some other frame in the meantime */
    if (args->eos_type != QUICLY_SENDSTATE_EOS_TYPE_NONE && args->eos_type == quicly_sendstate_eos_type(state) &&
        state->eos_state == QUICLY_SENDSTATE_EOS_STATE_INFLIGHT)
        state->eos_state = QUICLY_SENDSTATE_EOS_STATE_UNSENT;

    return check_amount_of_state(state);
}
