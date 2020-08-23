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

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "quicly/constants.h"
#include "quicly/loss.h"

typedef enum {
    /**
     * Reno, with 0.7 beta reduction
     */
    CC_RENO_MODIFIED,
    /**
     * CUBIC (RFC 8312)
     */
    CC_CUBIC
} quicly_cc_type_t;

/**
 * Holds pointers to concrete congestion control implementation functions.
 */
struct st_quicly_cc_impl_t;

typedef struct st_quicly_cc_t {
    /**
     * Congestion controller implementation.
     */
    const struct st_quicly_cc_impl_t *impl;
    /**
     * Current congestion window.
     */
    uint32_t cwnd;
    /**
     * Current slow start threshold.
     */
    uint32_t ssthresh;
    /**
     * Packet number indicating end of recovery period, if in recovery.
     */
    uint64_t recovery_end;
    /**
     * State information specific to the congestion controller implementation.
     */
    union {
        /**
         * State information for Reno congestion control.
         */
        struct {
            /**
             * Stash of acknowledged bytes, used during congestion avoidance.
             */
            uint32_t stash;
        } reno;
        /**
         * State information for CUBIC congestion control.
         */
        struct {
            /**
             * Time offset from the latest congestion event until cwnd reaches W_max again.
             */
            double k;
            /**
             * Last cwnd value before the latest congestion event.
             */
            uint32_t w_max;
            /**
             * W_max value from the previous congestion event.
             */
            uint32_t w_last_max;
            /**
             * Timestamp of the latest congestion event.
             */
            int64_t avoidance_start;
            /**
             * Timestamp of the most recent send operation.
             */
            int64_t last_sent_time;
        } cubic;
    } state;
    /**
     * Initial congestion window.
     */
    uint32_t cwnd_initial;
    /**
     * Congestion window at the end of slow start.
     */
    uint32_t cwnd_exiting_slow_start;
    /**
     * Minimum congestion window during the connection.
     */
    uint32_t cwnd_minimum;
    /**
     * Maximum congestion window during the connection.
     */
    uint32_t cwnd_maximum;
    /**
     * Total number of number of loss episodes (congestion window reductions).
     */
    uint32_t num_loss_episodes;
} quicly_cc_t;

struct st_quicly_cc_impl_t {
    /**
     * Congestion controller type.
     */
    quicly_cc_type_t type;
    /**
     * Called when a packet is newly acknowledged.
     */
    void (*cc_on_acked)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                        int64_t now, uint32_t max_udp_payload_size);
    /**
     * Called when a packet is detected as lost. |next_pn| is the next unsent packet number,
     * used for setting the recovery window.
     */
    void (*cc_on_lost)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn, int64_t now,
                       uint32_t max_udp_payload_size);
    /**
     * Called when persistent congestion is observed.
     */
    void (*cc_on_persistent_congestion)(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now);
    /**
     * Called after a packet is sent.
     */
    void (*cc_on_sent)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now);
};

/**
 * The factory method for the modified Reno congestion controller.
 */
extern struct st_quicly_init_cc_t quicly_cc_reno_init;
/**
 * The factory method for the modified Reno congestion controller.
 */
extern struct st_quicly_init_cc_t quicly_cc_cubic_init;

/**
 * Calculates the initial congestion window size given the maximum UDP payload size.
 */
uint32_t quicly_cc_calc_initial_cwnd(uint16_t max_udp_payload_size);

#ifdef __cplusplus
}
#endif

#endif
