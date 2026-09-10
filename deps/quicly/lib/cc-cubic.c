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
#include "quicly.h"
#include "quicly/pacer.h"

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

/* RFC 9438, Figure 1; using bytes as unit instead of MSS */
static cubic_float_t calc_w_cubic(const quicly_cc_t *cc, cubic_float_t t_sec, uint32_t max_udp_payload_size)
{
    cubic_float_t tk = t_sec - cc->state.cubic.k;
    return (QUICLY_CUBIC_C * (tk * tk * tk) * max_udp_payload_size) + cc->state.cubic.w_max;
}

/* RFC 9438, Figure 2 */
static void update_cubic_k(quicly_cc_t *cc, uint32_t cwnd_epoch, uint32_t max_udp_payload_size)
{
    if (cc->state.cubic.w_max > cwnd_epoch) {
        cubic_float_t window_delta_mss = (cc->state.cubic.w_max - cwnd_epoch) / (cubic_float_t)max_udp_payload_size;
        cc->state.cubic.k = cbrt(window_delta_mss / QUICLY_CUBIC_C);
    } else {
        cc->state.cubic.k = 0;
    }
}

/* RFC 9438, Figure 4; using bytes as unit instead of MSS */
static uint32_t update_w_est(quicly_cc_t *cc, uint32_t bytes, uint32_t max_udp_payload_size)
{
    cubic_float_t alpha =
        cc->state.cubic.w_est >= cc->state.cubic.cwnd_prior ? 1 : 3 * (1 - QUICLY_CUBIC_BETA) / (1 + QUICLY_CUBIC_BETA);
    cc->state.cubic.w_est += alpha * bytes / cc->cwnd * max_udp_payload_size;
    return cc->state.cubic.w_est < UINT32_MAX ? cc->state.cubic.w_est : UINT32_MAX;
}

/* TODO: Avoid increase if sender was application limited. */
static void cubic_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                           int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);
    /* Do not increase congestion window while in recovery (but jumpstart may do something different). */
    if (largest_acked < cc->recovery_end) {
        quicly_cc_jumpstart_on_acked(cc, 1, bytes, largest_acked, inflight, next_pn);
        return;
    }

    quicly_cc_jumpstart_on_acked(cc, 0, bytes, largest_acked, inflight, next_pn);

    /* TODO: respect cc_limited */

    /* Slow start. */
    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd = quicly_u32_add_saturating(cc->cwnd, bytes);
        if (cc->cwnd_maximum < cc->cwnd)
            cc->cwnd_maximum = cc->cwnd;
        return;
    }

    /* Congestion avoidance. */
    cubic_float_t t_sec = calc_cubic_t(cc, now);
    cubic_float_t rtt_sec = loss->rtt.smoothed / (cubic_float_t)1000; /* ms -> s */

    cubic_float_t w_cubic = calc_w_cubic(cc, t_sec, max_udp_payload_size);
    uint32_t w_est = update_w_est(cc, bytes, max_udp_payload_size);

    if (w_cubic < w_est) {
        /* RFC 9438, Section 4.3; Reno-Friendly Region */
        cc->cwnd = w_est;
    } else {
        /* RFC 9438, Sections 4.4 and 4.5; Concave and Convex Regions */
        cubic_float_t w_cubic_target = calc_w_cubic(cc, t_sec + rtt_sec, max_udp_payload_size);
        /* RFC 9438, Section 4.2 bounds target to make the increase non-decreasing and slower than slow start. */
        if (w_cubic_target < cc->cwnd)
            w_cubic_target = cc->cwnd;
        if (w_cubic_target > 1.5 * cc->cwnd)
            w_cubic_target = 1.5 * cc->cwnd;
        /* (W_cubic(t+RTT) - cwnd)/cwnd * MSS = (W_cubic(t+RTT)/cwnd - 1) * MSS */
        cc->cwnd = quicly_u32_add_saturating(cc->cwnd, ((w_cubic_target / cc->cwnd) - 1) * max_udp_payload_size);
    }

    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static void cubic_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                          int64_t now, uint32_t max_udp_payload_size)
{
    quicly_cc__update_ecn_episodes(cc, bytes, lost_pn);

    /* Nothing to do if loss is in recovery window. */
    if (lost_pn < cc->recovery_end)
        return;
    cc->recovery_end = next_pn;

    /* if detected loss before receiving all acks for jumpstart, restore original CWND */
    if (cc->ssthresh == UINT32_MAX)
        quicly_cc_jumpstart_on_first_loss(cc, lost_pn, 0);

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0) {
        cc->cwnd_exiting_slow_start = cc->cwnd;
        cc->exit_slow_start_at = now;
    }

    cc->state.cubic.avoidance_start = now;
    cc->state.cubic.cwnd_prior = cc->cwnd;

    /* RFC 9438, Section 4.7; compare cwnd with the effective W_max retained from the previous congestion event. */
    if (cc->cwnd < cc->state.cubic.w_max)
        cc->state.cubic.w_max = cc->cwnd * ((1.0 + QUICLY_CUBIC_BETA) / 2.0);
    else
        cc->state.cubic.w_max = cc->cwnd;

    /* RFC 9438, Section 4.6; Multiplicative Decrease */
    cc->cwnd *= cc->ssthresh == UINT32_MAX ? 0.5 : QUICLY_CUBIC_BETA; /* without HyStart++, we overshoot by 2x in slowstart */
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;
    cc->state.cubic.w_est = cc->cwnd;
    update_cubic_k(cc, cc->cwnd, max_udp_payload_size);

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

static void cubic_on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now)
{
    /* Prevent extreme cwnd growth following an idle period caused by application limit.
     * This fixes the W_cubic/W_est calculations by effectively subtracting the idle period
     * The sender is coming out of quiescence if the current packet is the only one in flight.
     * (see https://github.com/torvalds/linux/commit/30927520dbae297182990bb21d08762bcc35ce1d). */
    if (loss->sentmap.bytes_in_flight <= bytes && cc->state.cubic.avoidance_start != 0 && cc->state.cubic.last_sent_time != 0) {
        int64_t delta = now - cc->state.cubic.last_sent_time;
        if (delta > 0)
            cc->state.cubic.avoidance_start += delta;
    }

    cc->state.cubic.last_sent_time = now;
}

static void cubic_reset(quicly_cc_t *cc, uint32_t initcwnd, int normalize_mtu)
{
    memset(cc, 0, sizeof(quicly_cc_t));
    cc->type = &quicly_cc_type_cubic_legacy;
    cc->normalize_mtu = normalize_mtu;
    cc->cwnd = cc->cwnd_initial = cc->cwnd_maximum = initcwnd;
    cc->ssthresh = cc->cwnd_minimum = UINT32_MAX;
    cc->exit_slow_start_at = INT64_MAX;

    quicly_cc_jumpstart_reset(cc);
}

static int cubic_on_switch(quicly_cc_t *cc)
{
    if (cc->type == &quicly_cc_type_cubic_legacy)
        return 1;

    if (cc->type == &quicly_cc_type_reno || cc->type == &quicly_cc_type_cubic || cc->type == &quicly_cc_type_pico ||
        cc->type == &quicly_cc_type_cuback) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = &quicly_cc_type_cubic_legacy;
        } else {
            cubic_reset(cc, cc->cwnd_initial, cc->normalize_mtu);
        }
        return 1;
    }

    return 0;
}

static void cubic_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int normalize_mtu, int64_t now)
{
    cubic_reset(cc, initcwnd, normalize_mtu);
}

quicly_cc_type_t quicly_cc_type_cubic_legacy = {
    "cubic-legacy", &quicly_cc_cubic_legacy_init, cubic_on_acked, cubic_on_lost, cubic_on_sent, cubic_on_switch,
    NULL,           quicly_cc_jumpstart_enter};
quicly_init_cc_t quicly_cc_cubic_legacy_init = {cubic_init};
