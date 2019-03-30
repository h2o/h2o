/*
 * Copyright (c) 2019 Fastly, Janardhan Iyengar
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

#define QUICLY_INITIAL_WINDOW 10
#define QUICLY_MIN_CWND 2
#define QUICLY_RENO_BETA 0.7

void quicly_cc_init(quicly_cc_t *cc)
{
    memset(cc, 0, sizeof(quicly_cc_t));
    cc->cwnd = QUICLY_INITIAL_WINDOW * QUICLY_MAX_PACKET_SIZE;
    cc->ssthresh = UINT32_MAX;
}

// TODO: Avoid increase if sender was application limited
void quicly_cc_on_acked(quicly_cc_t *cc, uint32_t bytes, uint64_t largest_acked, uint32_t inflight)
{
    assert(inflight >= bytes);
    // no increases while in recovery
    if (largest_acked < cc->recovery_end)
        return;

    // slow start
    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd += bytes;
        return;
    }
    // congestion avoidance
    cc->stash += bytes;
    if (cc->stash < cc->cwnd)
        return;
    // increase cwnd by 1 MSS per cwnd acked
    uint32_t count = cc->stash / cc->cwnd;
    cc->stash -= count * cc->cwnd;
    cc->cwnd += count * QUICLY_MAX_PACKET_SIZE;
}

void quicly_cc_on_lost(quicly_cc_t *cc, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn)
{
    // nothing to do if loss is in recovery window
    if (lost_pn < cc->recovery_end)
        return;
    // set end of recovery window
    cc->recovery_end = next_pn;
    cc->cwnd *= QUICLY_RENO_BETA;
    if (cc->cwnd < QUICLY_MIN_CWND * QUICLY_MAX_PACKET_SIZE)
        cc->cwnd = QUICLY_MIN_CWND * QUICLY_MAX_PACKET_SIZE;
    cc->ssthresh = cc->cwnd;
}

void quicly_cc_on_persistent_congestion(quicly_cc_t *cc)
{
    // TODO
}
