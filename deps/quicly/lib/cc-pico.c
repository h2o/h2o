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
#include <math.h>
#include "quicly/pacer.h"
#include "quicly/cc.h"
#include "quicly.h"

/**
 * Calculates the increase ratio to be used in congestion avoidance phase.
 */
static uint32_t calc_bytes_per_mtu_increase(uint32_t cwnd, uint32_t rtt, uint32_t mtu)
{
    /* Reno: CWND size after reduction */
    uint32_t reno = cwnd * QUICLY_RENO_BETA;

    /* Cubic: Cubic reaches original CWND (i.e., Wmax) in K seconds, therefore:
     *   amount_to_increase = 0.3 * Wmax
     *   amount_to_be_acked = K * Wmax / RTT_at_Wmax
     * where
     *   K = (0.3 / 0.4 * Wmax / MTU)^(1/3)
     *
     * Hence:
     *   bytes_per_mtu_increase = amount_to_be_acked / amount_to_increase * MTU
     *     = (K * Wmax / RTT_at_Wmax) / (0.3 * Wmax) * MTU
     *     = K * MTU / (0.3 * RTT_at_Wmax)
     *
     * In addition, we have to adjust the value to take fast convergence into account. On a path with stable capacity, 50% of
     * congestion events adjust Wmax to 0.85x of before calculating K. If that happens, the modified K (K') is:
     *
     *   K' = (0.3 / 0.4 * 0.85 * Wmax / MTU)^(1/3) = 0.85^(1/3) * K
     *
     * where K' represents the time to reach 0.85 * Wmax. As the cubic curve is point symmetric at the point where this curve
     * reaches 0.85 * Wmax, it would take 2 * K' seconds to reach Wmax.
     *
     * Therefore, by amortizing the two modes, the congestion period of Cubic with fast convergence is calculated as:
     *
     *   bytes_per_mtu_increase = ((1 + 0.85^(1/3) * 2) / 2) * K * MTU / (0.3 * RTT_at_Wmax)
     */
    uint32_t cubic = 1.447 / 0.3 * 1000 * cbrt(0.3 / 0.4 * cwnd / mtu) / rtt * mtu;

    return reno < cubic ? reno : cubic;
}

/* TODO: Avoid increase if sender was application limited. */
static void pico_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    /* In recovery period: CWND remains the same (but either jumpstart or rapid start may handle it differently). */
    if (largest_acked < cc->recovery_end) {
        quicly_cc_jumpstart_on_acked(cc, 1, bytes, largest_acked, inflight, next_pn);
        return;
    }

    quicly_cc_jumpstart_on_acked(cc, 0, bytes, largest_acked, inflight, next_pn);

    if (!cc_limited)
        return;

    cc->state.pico.stash += bytes;

    /* Calculate the amount of bytes required to be acked for incrementing CWND by one MTU. */
    uint32_t bytes_per_mtu_increase;
    if (cc->cwnd < cc->ssthresh) {
        quicly_cc_rapid_start_update_rtt(&cc->rapid_start, &loss->rtt, now);
        bytes_per_mtu_increase =
            quicly_cc_rapid_start_use_3x(&cc->rapid_start, &loss->rtt) ? max_udp_payload_size / 2 : max_udp_payload_size;
    } else {
        bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
    }

    /* Bail out if we do not yet have enough bytes being acked. */
    if (cc->state.pico.stash < bytes_per_mtu_increase)
        return;

    /* Update CWND, reducing stash relative to the amount we've adjusted the CWND */
    uint32_t count = cc->state.pico.stash / bytes_per_mtu_increase;
    cc->cwnd = quicly_u32_add_saturating(cc->cwnd, count * max_udp_payload_size);
    cc->state.pico.stash -= count * bytes_per_mtu_increase;

    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static void pico_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                         int64_t now, uint32_t max_udp_payload_size)
{
    quicly_cc__update_ecn_episodes(cc, bytes, lost_pn);

    /* Nothing to do if loss is in recovery window (modulo when exiting rapid start, in which case CWND is further reduced relative
     * to the number of bytes lost. */
    if (lost_pn < cc->recovery_end) {
        if (cc->num_loss_episodes == 1 && !quicly_cc_is_jumpstart_ack(cc, lost_pn)) {
            quicly_cc_rapid_start_on_lost(&cc->rapid_start, bytes, &cc->cwnd, cc->cwnd_exiting_slow_start);
            goto ClampMinAndUpdateMetrics;
        }
        return;
    }

    cc->recovery_end = next_pn;

    /* if detected loss before receiving all acks for jumpstart, restore original CWND */
    if (cc->ssthresh == UINT32_MAX)
        quicly_cc_jumpstart_on_first_loss(cc, lost_pn);

    ++cc->num_loss_episodes;
    if (cc->cwnd_exiting_slow_start == 0) {
        cc->cwnd_exiting_slow_start = cc->cwnd;
        cc->exit_slow_start_at = now;
    }

    /* Calculate increase rate. */
    cc->state.pico.bytes_per_mtu_increase = calc_bytes_per_mtu_increase(cc->cwnd, loss->rtt.smoothed, max_udp_payload_size);

    /* Reduce congestion window. At the end of Slow Start, 0.5x is used, because the 1 RTT delay in ACK causes the sender to
     * overshoot by 2x (note: after 0.5x reduction, CWND is still as large as BDP+QUEUE, so further reduction is preferable).
     *
     * In rapid start, upon the first loss we set CWND to 0.7x (QUICLY_RENO_BETA), then reduce proportionally to the bytes deemed
     * lost during recovery, with a lower bound of 1/3 * beta.
     * Rationale: at a small loss, reducing by beta mirrors CA's single signal behavior. With up to ~67% loss (typical for 3x
     * growth under tail-drop), CWND upon loss detection is 3 * (BDP + Q); therefore clamping to 1/3 * beta reproduces the CA
     * target. For loss >67% (i.e., beyond queue overflow), we keep the lower bound to avoid over-shrinking. */
    if (cc->ssthresh == UINT32_MAX) {
        cc->cwnd *= quicly_cc_rapid_start_is_enabled(&cc->rapid_start) != 0 ? QUICLY_RENO_BETA : 0.5;
    } else {
        cc->cwnd *= QUICLY_RENO_BETA;
    }

ClampMinAndUpdateMetrics:
    /* After CWND has been reduced, adjust if it is below permitted minimum and update metrics. */
    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
    cc->ssthresh = cc->cwnd;

    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

static void pico_on_persistent_congestion(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now)
{
    /* TODO */
}

static void pico_on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now)
{
    /* Unused */
}

static void pico_init_pico_state(quicly_cc_t *cc, uint32_t stash)
{
    cc->state.pico.stash = stash;
    cc->state.pico.bytes_per_mtu_increase = cc->cwnd * QUICLY_RENO_BETA; /* use Reno, for simplicity */
}

static void pico_reset(quicly_cc_t *cc, uint32_t initcwnd)
{
    *cc = (quicly_cc_t){
        .type = &quicly_cc_type_pico,
        .cwnd = initcwnd,
        .cwnd_initial = initcwnd,
        .cwnd_maximum = initcwnd,
        .cwnd_minimum = UINT32_MAX,
        .exit_slow_start_at = INT64_MAX,
        .ssthresh = UINT32_MAX,
    };
    pico_init_pico_state(cc, 0);

    quicly_cc_jumpstart_reset(cc);
}

static int pico_on_switch(quicly_cc_t *cc)
{
    if (cc->type == &quicly_cc_type_pico) {
        return 1; /* nothing to do */
    } else if (cc->type == &quicly_cc_type_reno) {
        cc->type = &quicly_cc_type_pico;
        pico_init_pico_state(cc, cc->state.reno.stash);
        return 1;
    } else if (cc->type == &quicly_cc_type_cubic) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = &quicly_cc_type_pico;
            pico_init_pico_state(cc, 0);
        } else {
            pico_reset(cc, cc->cwnd_initial);
        }
        return 1;
    }

    return 0;
}

static void pico_enable_rapid_start(quicly_cc_t *cc, int64_t now)
{
    quicly_cc_init_rapid_start(&cc->rapid_start, now);
}

static void pico_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    pico_reset(cc, initcwnd);
}

quicly_cc_type_t quicly_cc_type_pico = {"pico",         &quicly_cc_pico_init,          pico_on_acked,
                                        pico_on_lost,   pico_on_persistent_congestion, pico_on_sent,
                                        pico_on_switch, quicly_cc_jumpstart_enter,     pico_enable_rapid_start};
quicly_init_cc_t quicly_cc_pico_init = {pico_init};
