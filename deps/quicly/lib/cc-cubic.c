/*
 * Copyright (c) 2019 Fastly, Janardhan Iyengar
 * Copyright (c) 2020 RWTH Aachen University, COMSYS Network Architectures Group, Leo Blöcher
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

#include <math.h>
#include "quicly/cc.h"

#define QUICLY_MIN_CWND 2

typedef double cubic_float_t;
#define QUICLY_CUBIC_C ((cubic_float_t)0.4)
#define QUICLY_CUBIC_BETA ((cubic_float_t)0.7)

/* Calculates the time elapsed since the last congestion event (parameter t) */
static cubic_float_t calc_cubic_t(const quicly_cc_t *cc, int64_t now)
{
    cubic_float_t clock_delta = now - cc->state.cubic.avoidance_start;
    return clock_delta / 1000; /* ms -> s */
}

/* RFC 8312, Equation 1; using bytes as unit instead of MSS */
static uint32_t calc_w_cubic(const quicly_cc_t *cc, cubic_float_t t_sec, uint32_t max_udp_payload_size)
{
    cubic_float_t tk = t_sec - cc->state.cubic.k;
    return (QUICLY_CUBIC_C * (tk * tk * tk) * max_udp_payload_size) + cc->state.cubic.w_max;
}

/* RFC 8312, Equation 2 */
/* K depends solely on W_max, so we update both together on congestion events */
static void update_cubic_k(quicly_cc_t *cc, uint32_t max_udp_payload_size)
{
    cubic_float_t w_max_mss = cc->state.cubic.w_max / (cubic_float_t)max_udp_payload_size;
    cc->state.cubic.k = cbrt(w_max_mss * ((1 - QUICLY_CUBIC_BETA) / QUICLY_CUBIC_C));
}

/* RFC 8312, Equation 4; using bytes as unit instead of MSS */
static uint32_t calc_w_est(const quicly_cc_t *cc, cubic_float_t t_sec, cubic_float_t rtt_sec, uint32_t max_udp_payload_size)
{
    return (cc->state.cubic.w_max * QUICLY_CUBIC_BETA) +
           ((3 * (1 - QUICLY_CUBIC_BETA) / (1 + QUICLY_CUBIC_BETA)) * (t_sec / rtt_sec) * max_udp_payload_size);
}

/* TODO: Avoid increase if sender was application limited. */
static void cubic_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                           int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);
    /* Do not increase congestion window while in recovery. */
    if (largest_acked < cc->recovery_end)
        return;

    /* Slow start. */
    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd += bytes;
        if (cc->cwnd_maximum < cc->cwnd)
            cc->cwnd_maximum = cc->cwnd;
        return;
    }

    /* Congestion avoidance. */
    cubic_float_t t_sec = calc_cubic_t(cc, now);
    cubic_float_t rtt_sec = loss->rtt.smoothed / (cubic_float_t)1000; /* ms -> s */

    uint32_t w_cubic = calc_w_cubic(cc, t_sec, max_udp_payload_size);
    uint32_t w_est = calc_w_est(cc, t_sec, rtt_sec, max_udp_payload_size);

    if (w_cubic < w_est) {
        /* RFC 8312, Section 4.2; TCP-Friendly Region */
        /* Prevent cwnd from shrinking if W_est is reduced due to RTT increase */
        if (w_est > cc->cwnd)
            cc->cwnd = w_est;
    } else {
        /* RFC 8312, Section 4.3/4.4; CUBIC Region */
        cubic_float_t w_cubic_target = calc_w_cubic(cc, t_sec + rtt_sec, max_udp_payload_size);
        /* After fast convergence W_max < W_last_max holds, and hence W_cubic(0) = beta * W_max < beta * W_last_max = cwnd.
         * cwnd could thus shrink without this check (but only after fast convergence). */
        if (w_cubic_target > cc->cwnd)
            /* (W_cubic(t+RTT) - cwnd)/cwnd * MSS = (W_cubic(t+RTT)/cwnd - 1) * MSS */
            cc->cwnd += ((w_cubic_target / cc->cwnd) - 1) * max_udp_payload_size;
    }

    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static void cubic_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                          int64_t now, uint32_t max_udp_payload_size)
{
    /* Nothing to do if loss is in recovery window. */
    if (lost_pn < cc->recovery_end)
        return;
    cc->recovery_end = next_pn;

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0)
        cc->cwnd_exiting_slow_start = cc->cwnd;

    cc->state.cubic.avoidance_start = now;
    cc->state.cubic.w_max = cc->cwnd;

    /* RFC 8312, Section 4.6; Fast Convergence */
    /* w_last_max is initialized to zero; therefore this condition is false when exiting slow start */
    if (cc->state.cubic.w_max < cc->state.cubic.w_last_max) {
        cc->state.cubic.w_last_max = cc->state.cubic.w_max;
        cc->state.cubic.w_max *= (1.0 + QUICLY_CUBIC_BETA) / 2.0;
    } else {
        cc->state.cubic.w_last_max = cc->state.cubic.w_max;
    }
    update_cubic_k(cc, max_udp_payload_size);

    /* RFC 8312, Section 4.5; Multiplicative Decrease */
    cc->cwnd *= QUICLY_CUBIC_BETA;
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

static void cubic_on_persistent_congestion(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now)
{
    /* TODO */
}

static const struct st_quicly_cc_impl_t cubic_impl = {CC_CUBIC, cubic_on_acked, cubic_on_lost, cubic_on_persistent_congestion};

void quicly_cc_cubic_init(quicly_cc_t *cc, uint32_t initcwnd)
{
    memset(cc, 0, sizeof(quicly_cc_t));
    cc->impl = &cubic_impl;
    cc->cwnd = cc->cwnd_initial = cc->cwnd_maximum = initcwnd;
    cc->ssthresh = cc->cwnd_minimum = UINT32_MAX;
}
