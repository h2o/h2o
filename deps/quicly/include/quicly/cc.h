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
#include "quicly/pacer.h"
#include "quicly/loss.h"

#define QUICLY_MIN_CWND 2
#define QUICLY_RENO_BETA 0.7

/**
 * Holds pointers to concrete congestion control implementation functions.
 */
typedef const struct st_quicly_cc_type_t quicly_cc_type_t;

typedef struct st_quicly_cc_t {
    /**
     * Congestion controller type.
     */
    quicly_cc_type_t *type;
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
     * If the most recent loss episode was signalled by ECN only (i.e., no packet loss).
     */
    unsigned episode_by_ecn : 1;
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
         * State information for Pico.
         */
        struct {
            /**
             * Stash of acknowledged bytes, used during congestion avoidance.
             */
            uint32_t stash;
            /**
             * Number of bytes required to be acked in order to increase CWND by 1 MTU.
             */
            uint32_t bytes_per_mtu_increase;
        } pico;
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
     * jumpstart state
     */
    struct {
        /**
         * first packet number in jumpstart
         */
        uint64_t enter_pn;
        /**
         * packet number following the last packet in jumpstart
         */
        uint64_t exit_pn;
        /**
         * amount of bytes acked for packets sent in jumpstart
         */
        uint32_t bytes_acked;
    } jumpstart;
    /**
     * Initial congestion window.
     */
    uint32_t cwnd_initial;
    /**
     * Congestion window at the end of slow start.
     */
    uint32_t cwnd_exiting_slow_start;
    /**
     * the time at which we exitted slow start (or INT64_MAX)
     */
    int64_t exit_slow_start_at;
    /**
     * Congestion window at the end of the unvalidated phase of jumpstart.
     */
    uint32_t cwnd_exiting_jumpstart;
    /**
     * Minimum congestion window during the connection.
     */
    uint32_t cwnd_minimum;
    /**
     * Maximum congestion window during the connection.
     */
    uint32_t cwnd_maximum;
    /**
     * Total number of loss episodes (congestion window reductions).
     */
    uint32_t num_loss_episodes;
    /**
     * Total number of loss episodes that was reported only by ECN (hence no packet loss).
     */
    uint32_t num_ecn_loss_episodes;
} quicly_cc_t;

struct st_quicly_cc_type_t {
    /**
     * name (e.g., "reno")
     */
    const char *name;
    /**
     * Corresponding default init_cc.
     */
    struct st_quicly_init_cc_t *cc_init;
    /**
     * Called when a packet is newly acknowledged.
     */
    void (*cc_on_acked)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                        int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size);
    /**
     * Called when a packet is detected as lost.
     * @param bytes    bytes declared lost, or zero iff ECN_CE is observed
     * @param next_pn  the next unsent packet number, used for setting the recovery window
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
    /**
     * Switches the underlying algorithm of `cc` to that of `cc_switch`, returning a boolean if the operation was successful.
     */
    int (*cc_switch)(quicly_cc_t *cc);
    /**
     *
     */
    void (*cc_jumpstart)(quicly_cc_t *cc, uint32_t cwnd, uint64_t next_pn);
};

/**
 * The type objects for each CC. These can be used for testing the type of each `quicly_cc_t`.
 */
extern quicly_cc_type_t quicly_cc_type_reno, quicly_cc_type_cubic, quicly_cc_type_pico;
/**
 * The factory methods for each CC.
 */
extern struct st_quicly_init_cc_t quicly_cc_reno_init, quicly_cc_cubic_init, quicly_cc_pico_init;

/**
 * A null-terminated list of all CC types.
 */
extern quicly_cc_type_t *quicly_cc_all_types[];

/**
 * Calculates the initial congestion window size given the maximum UDP payload size.
 */
uint32_t quicly_cc_calc_initial_cwnd(uint32_t max_packets, uint16_t max_udp_payload_size);

void quicly_cc_reno_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                            int64_t now, uint32_t max_udp_payload_size);
void quicly_cc_reno_on_persistent_congestion(quicly_cc_t *cc, const quicly_loss_t *loss, int64_t now);
void quicly_cc_reno_on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now);
/**
 * Updates ECN counter when loss is observed.
 */
static void quicly_cc__update_ecn_episodes(quicly_cc_t *cc, uint32_t lost_bytes, uint64_t lost_pn);

static void quicly_cc_jumpstart_reset(quicly_cc_t *cc);
static int quicly_cc_in_jumpstart(quicly_cc_t *cc);
static void quicly_cc_jumpstart_enter(quicly_cc_t *cc, uint32_t jump_cwnd, uint64_t next_pn);
static void quicly_cc_jumpstart_on_acked(quicly_cc_t *cc, int in_recovery, uint32_t bytes, uint64_t largest_acked,
                                         uint32_t inflight, uint64_t next_pn);
static void quicly_cc_jumpstart_on_first_loss(quicly_cc_t *cc, uint64_t lost_pn);

/* inline definitions */

inline void quicly_cc__update_ecn_episodes(quicly_cc_t *cc, uint32_t lost_bytes, uint64_t lost_pn)
{
    /* when it is a new loss episode, initially assume that all losses are due to ECN signalling ... */
    if (lost_pn >= cc->recovery_end) {
        ++cc->num_ecn_loss_episodes;
        cc->episode_by_ecn = 1;
    }

    /* ... but if a loss is observed, decrement the ECN loss episode counter */
    if (lost_bytes != 0 && cc->episode_by_ecn) {
        --cc->num_ecn_loss_episodes;
        cc->episode_by_ecn = 0;
    }
}

inline void quicly_cc_jumpstart_reset(quicly_cc_t *cc)
{
    cc->jumpstart.enter_pn = UINT64_MAX;
    cc->jumpstart.exit_pn = UINT64_MAX;
    cc->jumpstart.bytes_acked = 0;
}

inline int quicly_cc_in_jumpstart(quicly_cc_t *cc)
{
    return cc->jumpstart.enter_pn < UINT64_MAX && cc->jumpstart.exit_pn == UINT64_MAX;
}

inline void quicly_cc_jumpstart_enter(quicly_cc_t *cc, uint32_t jump_cwnd, uint64_t next_pn)
{
    assert(cc->cwnd < jump_cwnd);

    /* retain state to be restored upon loss */
    cc->jumpstart.enter_pn = next_pn;

    /* adjust */
    cc->cwnd = jump_cwnd;
}

inline void quicly_cc_jumpstart_on_acked(quicly_cc_t *cc, int in_recovery, uint32_t bytes, uint64_t largest_acked,
                                         uint32_t inflight, uint64_t next_pn)
{
    int is_jumpstart_ack = cc->jumpstart.enter_pn <= largest_acked && largest_acked < cc->jumpstart.exit_pn;

    /* remember the amount of bytes acked for the packets sent in jumpstart */
    if (is_jumpstart_ack)
        cc->jumpstart.bytes_acked += bytes;

    if (in_recovery) {
        /* Propotional Rate Reduction: if a loss is observed due to jumpstart, CWND is adjusted so that it would become bytes that
         * passed through to the client during the jumpstart phase of exactly 1 RTT, when the last ACK for the jumpstart phase is
         * received */
        if (is_jumpstart_ack && cc->cwnd < cc->jumpstart.bytes_acked)
            cc->cwnd = cc->jumpstart.bytes_acked;
        return;
    }

    /* when receiving the first ack for jumpstart, stop jumpstart and go back to slow start, adopting current inflight as cwnd */
    if (cc->jumpstart.exit_pn == UINT64_MAX && cc->jumpstart.enter_pn <= largest_acked) {
        assert(cc->cwnd < cc->ssthresh);
        cc->cwnd = inflight;
        cc->cwnd_exiting_jumpstart = cc->cwnd;
        cc->jumpstart.exit_pn = next_pn;
    }
}

inline void quicly_cc_jumpstart_on_first_loss(quicly_cc_t *cc, uint64_t lost_pn)
{
    if (cc->jumpstart.enter_pn != UINT64_MAX && lost_pn < cc->jumpstart.exit_pn) {
        assert(cc->cwnd < cc->ssthresh);
        /* CWND is set to the amount of bytes ACKed during the jump start phase plus the value before jump start */
        cc->cwnd = cc->jumpstart.bytes_acked;
        if (cc->cwnd < cc->cwnd_initial)
            cc->cwnd = cc->cwnd_initial;
        if (cc->jumpstart.exit_pn == UINT64_MAX)
            cc->jumpstart.exit_pn = lost_pn;
    }
}

#ifdef __cplusplus
}
#endif

#endif
