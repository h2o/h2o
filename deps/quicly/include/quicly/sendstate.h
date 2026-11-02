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

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly/ranges.h"

/**
 * The marker that the stream ends with. The values are ordered by the amount that they tell the peer, so that a marker that has
 * been delivered satisfies the stream iff its value is no less than the one the stream ends with; a FIN does not stand in for a
 * reliable reset, whereas a RESET_STREAM stands in for a RESET_STREAM_AT that has been downgraded upon receiving STOP_SENDING.
 * Being ordered, the values also cannot express a reliable reset that reduces the Reliable Size of one that has been delivered;
 * that is not supported.
 */
#define QUICLY_SENDSTATE_EOS_TYPE_NONE 0
#define QUICLY_SENDSTATE_EOS_TYPE_FIN 1
#define QUICLY_SENDSTATE_EOS_TYPE_RESET_AT 2
#define QUICLY_SENDSTATE_EOS_TYPE_RESET 3

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
     * number of bytes that have been inflight (regardless of acked or not). Used for capping max_data.
     */
    uint64_t size_inflight;
    /**
     * UINT64_MAX until closed
     */
    uint64_t final_size;
    /**
     * application error code of the reset that the stream is to be closed with, or UINT64_MAX if it is not being reset
     */
    uint64_t app_error_code;
    /**
     * RESET_STREAM_AT.reliable_size; zero means that RESET_STREAM is to be sent. Valid when `app_error_code` is other than
     * UINT64_MAX.
     */
    uint64_t reliable_size;
    /**
     * How far the marker that the stream ends with has got. A frame carrying a marker that has since been superseded leaves the
     * state untouched, hence changing the marker returns it to UNSENT and a new frame is emitted in place of the old.
     */
    enum {
        QUICLY_SENDSTATE_EOS_STATE_UNSENT,
        QUICLY_SENDSTATE_EOS_STATE_INFLIGHT,
        QUICLY_SENDSTATE_EOS_STATE_DELIVERED,
    } eos_state;
} quicly_sendstate_t;

typedef struct st_quicly_sendstate_sent_t {
    uint64_t start;
    /**
     * Bounded by the largest offset that QUIC permits (2^62-1), hence 62 bits. The remaining two carry `eos_type`, so that
     * `quicly_sent_t` stays within four words.
     */
    uint64_t end : 62;
    /**
     * the marker that the frame carries (QUICLY_SENDSTATE_EOS_TYPE_*)
     */
    uint64_t eos_type : 2;
} quicly_sendstate_sent_t;

void quicly_sendstate_init(quicly_sendstate_t *state);
void quicly_sendstate_init_closed(quicly_sendstate_t *state);
void quicly_sendstate_dispose(quicly_sendstate_t *state);
/**
 * Returns if the transfer has completed; i.e., all data including FIN or RESET_STREAM_AT(reliable_size!=0) have been acked.
 * Ordinary RESET_STREAM might still be inflight.
 */
int quicly_sendstate_transfer_complete(quicly_sendstate_t *state);
/**
 * Returns the marker that the stream ends with (QUICLY_SENDSTATE_EOS_TYPE_*), NONE being returned while the stream is open.
 */
static uint8_t quicly_sendstate_eos_type(quicly_sendstate_t *state);
static int quicly_sendstate_is_open(quicly_sendstate_t *state);
int quicly_sendstate_is_fully_inflight(quicly_sendstate_t *state);
int quicly_sendstate_activate(quicly_sendstate_t *state);
int quicly_sendstate_shutdown(quicly_sendstate_t *state, uint64_t final_size);
int quicly_sendstate_reset(quicly_sendstate_t *state, uint64_t app_error_code, uint64_t reliable_size);
int quicly_sendstate_acked(quicly_sendstate_t *state, quicly_sendstate_sent_t *args, size_t *bytes_to_shift);
int quicly_sendstate_lost(quicly_sendstate_t *state, quicly_sendstate_sent_t *args);

/* inline definitions */

inline uint8_t quicly_sendstate_eos_type(quicly_sendstate_t *state)
{
    if (state->final_size == UINT64_MAX)
        return QUICLY_SENDSTATE_EOS_TYPE_NONE;
    if (state->app_error_code == UINT64_MAX)
        return QUICLY_SENDSTATE_EOS_TYPE_FIN;
    return state->reliable_size != 0 ? QUICLY_SENDSTATE_EOS_TYPE_RESET_AT : QUICLY_SENDSTATE_EOS_TYPE_RESET;
}

inline int quicly_sendstate_is_open(quicly_sendstate_t *state)
{
    return state->final_size == UINT64_MAX;
}

#ifdef __cplusplus
}
#endif

#endif
