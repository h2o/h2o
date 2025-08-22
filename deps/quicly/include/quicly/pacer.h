/*
 * Copyright (c) 2021 Fastly, Kazuho Oku
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
#ifndef quicly_pacer_h
#define quicly_pacer_h

#include <assert.h>
#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Simple pacer. The design guarantees that the formula below is met for any given pacer-restricted period:
 *
 *   flow_rate * duration + 8 * mtu <= bytes_sent < flow_rate * duration + 10 * mtu
 */
typedef struct st_quicly_pacer_t {
    /**
     * clock
     */
    int64_t at;
    /**
     * amount of credit being spent at `at`
     */
    size_t bytes_sent;
} quicly_pacer_t;

#define QUICLY_PACER_BURST_LOW 8   /* lower bound in packets */
#define QUICLY_PACER_BURST_HIGH 10 /* high bound in packets */

/**
 * resets the pacer
 */
static void quicly_pacer_reset(quicly_pacer_t *pacer);
/**
 * returns when the next chunk of data can be sent
 */
static int64_t quicly_pacer_can_send_at(quicly_pacer_t *pacer, uint32_t bytes_per_msec, uint16_t mtu);
/**
 * returns the number of bytes that can be sent at this moment
 */
static uint64_t quicly_pacer_get_window(quicly_pacer_t *pacer, int64_t now, uint32_t bytes_per_msec, uint16_t mtu);
/**
 * updates the window size available at current time
 */
static void quicly_pacer_consume_window(quicly_pacer_t *pacer, size_t delta);
/**
 * Calculates the flow rate as `bytes_per_msec`. The returned value is no less than 1.
 */
static uint32_t quicly_pacer_calc_send_rate(uint32_t multiplier, uint32_t cwnd, uint32_t rtt);

/* inline definitions */

inline void quicly_pacer_reset(quicly_pacer_t *pacer)
{
    pacer->at = INT64_MIN;
    pacer->bytes_sent = 0;
}

inline int64_t quicly_pacer_can_send_at(quicly_pacer_t *pacer, uint32_t bytes_per_msec, uint16_t mtu)
{
    /* return "now" if we have room in current msec */
    size_t burst_size = QUICLY_PACER_BURST_LOW * mtu + 1;
    size_t burst_credit = burst_size > bytes_per_msec ? burst_size - bytes_per_msec : 0;
    if (pacer->bytes_sent < bytes_per_msec + burst_credit)
        return 0;

    /* calculate delay; the value is rounded down, as it is better for a pacer to be a bit aggressive than not */
    int64_t delay = (pacer->bytes_sent - burst_credit) / bytes_per_msec;
    assert(delay > 0);
    return pacer->at + delay;
}

inline uint64_t quicly_pacer_get_window(quicly_pacer_t *pacer, int64_t now, uint32_t bytes_per_msec, uint16_t mtu)
{
    assert(pacer->at <= now);

    /* Determine when it is possible to sent one packet. Return if that is a moment in future. */
    int64_t can_send_at = quicly_pacer_can_send_at(pacer, bytes_per_msec, mtu);
    if (now < can_send_at)
        return 0;

    /* Calculate the upper bound of burst window (the size is later rounded up) */
    size_t burst_window = (QUICLY_PACER_BURST_HIGH - 1) * mtu + 1;
    if (burst_window < bytes_per_msec)
        burst_window = bytes_per_msec;

    /* Additional amount of data that we can send in `now - restricted_at` milliseconds is that difference multiplied by
     * `bytes_per_msec`. Adjust `bytes_sent` by that amount before setting `restricted_at` to `now`. `uint64_t` is used to store
     * window and delta so that the multiplication would not overflow assuming that the quiescence period is shorter than 2**32
     * milliseconds. */
    uint64_t window, delta = (now - pacer->at) * bytes_per_msec;
    if (pacer->bytes_sent > delta) {
        pacer->bytes_sent -= delta;
        if (burst_window > pacer->bytes_sent) {
            window = (burst_window - pacer->bytes_sent + mtu - 1) / mtu;
            if (window < 2)
                window = 2;
        } else {
            window = 2;
        }
    } else {
        pacer->bytes_sent = 0;
        window = (burst_window + mtu - 1) / mtu;
    }
    window *= mtu;

    pacer->at = now;

    return window;
}

inline void quicly_pacer_consume_window(quicly_pacer_t *pacer, size_t delta)
{
    pacer->bytes_sent += delta;
}

inline uint32_t quicly_pacer_calc_send_rate(uint32_t multiplier, uint32_t cwnd, uint32_t rtt)
{
    return (cwnd * multiplier + rtt - 1) / rtt;
}

#ifdef __cplusplus
}
#endif

#endif
