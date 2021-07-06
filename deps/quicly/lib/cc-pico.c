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
#include "quicly/cc.h"
#include "quicly.h"

/**
 * Speed at which the multiplicative increase grows from BETA to 1. Unit is Hz.
 */
#define QUICLY_PICO_MULT_HZ 1.0

static uint32_t calc_bytes_per_mtu_increase(uint32_t cwnd, uint32_t ssthresh, uint32_t rtt, uint32_t mtu)
{
    /* Increase per byte acked is the sum of 1mtu/cwnd (additive part) and ... */
    double increase_per_byte = (double)mtu / cwnd;
    /* ... multiplicative part being 1 during slow start, and the RTT-compensated rate for recovery within ~1/QUICLY_PICO_MULT_HZ
     * seconds congestion avoidance. */
    if (cwnd < ssthresh) {
        increase_per_byte += 1;
    } else {
        increase_per_byte += (1 / QUICLY_RENO_BETA - 1) * QUICLY_PICO_MULT_HZ / 1000 * rtt;
    }

    return (uint32_t)(mtu / increase_per_byte);
}

/* TODO: Avoid increase if sender was application limited. */
static void pico_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    /* Do not increase congestion window while in recovery. */
    if (largest_acked < cc->recovery_end)
        return;

    cc->state.reno.stash += bytes;

    /* Calculate the amount of bytes required to be acked for incrementing CWND by one MTU. */
    uint32_t bytes_per_mtu_increase = calc_bytes_per_mtu_increase(cc->cwnd, cc->ssthresh, loss->rtt.smoothed, max_udp_payload_size);

    /* Bail out if we do not yet have enough bytes being acked. */
    if (cc->state.reno.stash < bytes_per_mtu_increase)
        return;

    /* Update CWND, reducing stash relative to the amount we've adjusted the CWND */
    uint32_t count = cc->state.reno.stash / bytes_per_mtu_increase;
    cc->cwnd += count * max_udp_payload_size;
    cc->state.reno.stash -= count * bytes_per_mtu_increase;

    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
}

static int pico_on_switch(quicly_cc_t *cc)
{
    /* switch to reno then rewrite the type */
    if (!quicly_cc_type_reno.cc_switch(cc))
        return 0;
    cc->type = &quicly_cc_type_pico;
    return 1;
}

static void pico_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int64_t now)
{
    quicly_cc_type_reno.cc_init->cb(quicly_cc_type_reno.cc_init, cc, initcwnd, now);
    cc->type = &quicly_cc_type_pico;
}

quicly_cc_type_t quicly_cc_type_pico = {"pico",
                                        &quicly_cc_pico_init,
                                        pico_on_acked,
                                        quicly_cc_reno_on_lost,
                                        quicly_cc_reno_on_persistent_congestion,
                                        quicly_cc_reno_on_sent,
                                        pico_on_switch};
quicly_init_cc_t quicly_cc_pico_init = {pico_init};
