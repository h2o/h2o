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

/* Interface definition for quicly's congestion controller.
 */

#ifndef quicly_cc_h
#define quicly_cc_h

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "quicly/constants.h"

typedef struct st_quicly_cc_t {
    uint32_t cwnd;
    uint32_t ssthresh;
    uint32_t stash;
    uint64_t recovery_end;
} quicly_cc_t;

void quicly_cc_init(quicly_cc_t *cc);

/**
 * Called to query the controller whether data can be sent. Returns 1 if yes, 0 otherwise.
 */
int quicly_cc_can_send(quicly_cc_t *cc, uint32_t inflight);

/**
 * Called when a packet is newly acknowledged.
 */
void quicly_cc_on_acked(quicly_cc_t *cc, uint32_t bytes, uint64_t largest_acked, uint32_t inflight);

/**
 * Called when a packet is detected as lost. |next_pn| is the next unsent packet number,
 * used for setting the recovery window.
 */
void quicly_cc_on_lost(quicly_cc_t *cc, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn);

/**
 * Called when persistent congestion is observed.
 */
void quicly_cc_on_persistent_congestion(quicly_cc_t *cc);

#endif
