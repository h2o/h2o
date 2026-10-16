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
#include "quicly/constants.h"
#include "quicly/recvstate.h"

void quicly_recvstate_init(quicly_recvstate_t *state)
{
    quicly_ranges_init_with_range(&state->received, 0, 0);
    state->data_off = 0;
    state->eos = UINT64_MAX;
    state->app_error_code = UINT64_MAX;
}

void quicly_recvstate_init_closed(quicly_recvstate_t *state)
{
    quicly_ranges_init_with_range(&state->received, 0, 0);
    state->data_off = 0;
    state->eos = 0;
    state->app_error_code = UINT64_MAX;
}

void quicly_recvstate_dispose(quicly_recvstate_t *state)
{
    quicly_ranges_clear(&state->received);
}

quicly_error_t quicly_recvstate_update(quicly_recvstate_t *state, uint64_t *off, size_t *len, int is_fin, size_t max_ranges)
{
    assert(!quicly_recvstate_transfer_complete(state));

    /* end-of-stream consistency check: the check is possible only until a reliable reset is received, since it might reduce `eos`
     * to the reliable size */
    if (state->eos == UINT64_MAX) {
        if (is_fin) {
            state->eos = *off + *len;
            if (state->eos < state->received.ranges[state->received.num_ranges - 1].end)
                return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
        }
    } else if (*off + *len > state->eos) {
        if (state->app_error_code == UINT64_MAX)
            return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
        /* The peer might have had frames inflight when it reset, but it is no longer committed to anything at or above `eos`. Bytes
         * above must be dropped to retain consistency of the connection-level flow credit; only bytes up to `eos` are managed. */
        *len = *off < state->eos ? (size_t)(state->eos - *off) : 0;
    }

    /* no state change; entire data has already been received */
    if (*off + *len <= state->data_off) {
        *len = 0;
        return 0;
    }

    /* adjust if partially received */
    if (*off < state->data_off) {
        size_t delta = state->data_off - *off;
        *off += delta;
        *len -= delta;
    }

    /* update received range */
    if (*len != 0) {
        int ret;
        if ((ret = quicly_ranges_add(&state->received, *off, *off + *len)) != 0)
            return ret;
        if (state->received.num_ranges > max_ranges)
            return QUICLY_ERROR_STATE_EXHAUSTION;
    }
    return 0;
}

quicly_error_t quicly_recvstate_reset(quicly_recvstate_t *state, uint64_t final_size, uint64_t reliable_size,
                                      uint64_t app_error_code, uint64_t *bytes_missing)
{
    assert(!quicly_recvstate_transfer_complete(state));
    assert(reliable_size <= final_size);

    *bytes_missing = 0;

    if (final_size < state->received.ranges[state->received.num_ranges - 1].end)
        return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;

    if (state->app_error_code == UINT64_MAX) {
        /* this is the first reset being received; the final size cannot change once it is known (RFC 9000 section 4.5) */
        if (state->eos != UINT64_MAX && state->eos != final_size)
            return QUICLY_TRANSPORT_ERROR_FINAL_SIZE;
        /* The sender has consumed flow control credit up to the final size; report the part of it that will never be received,
         * the rest having been accounted for as it arrived. This is done once, no byte of the stream being charged thereafter. */
        *bytes_missing = final_size - state->received.ranges[state->received.num_ranges - 1].end;
    } else {
        /* the application error code cannot change between the resets received for one stream (section 5.2 of
         * draft-ietf-quic-reliable-stream-reset) */
        if (state->app_error_code != app_error_code)
            return QUICLY_TRANSPORT_ERROR_STREAM_STATE;
        /* as the sender is only allowed to reduce the reliable size, a value that does not reduce it is the result of reordering,
         * and is to be ignored rather than being an error (section 5.2) */
        if (reliable_size >= state->eos)
            return 0;
    }

    /* Raise the reliable size to the bytes that have already been received contiguously, if that is greater; they cannot become
     * undelivered. Ranges above it are retained; see quicly_recvstate_bytes_allocated. */
    if (state->received.ranges[0].start == 0 && reliable_size < state->received.ranges[0].end)
        reliable_size = state->received.ranges[0].end;

    /* from here on `eos` is the offset the peer remains committed to delivering, rather than the final size; the transfer is
     * complete once the contiguous prefix reaches it, which the ranges stranded above by the reset do not hold back */
    state->eos = reliable_size;
    state->app_error_code = app_error_code;

    return 0;
}
