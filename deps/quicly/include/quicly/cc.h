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
/**
 * Reference maximum UDP payload size used for packet-size-neutral congestion control. This is the midpoint of the maximum UDP
 * payload sizes of IPv4 and IPv6 packets carried at an IP MTU of 1500 bytes.
 */
#define QUICLY_CC_REFERENCE_MTU 1462
/**
 * Default beta used when a packet is lost; 0.7 is used to achieve fairness with Cubic.
 */
#define QUICLY_BETA_LOSS 0.7
/**
 * Beta used by Reno.
 */
#define QUICLY_BETA_RENO 0.5
/**
 * Beta used when congestion is signalled by ECN-CE alone; 0.85 is the value recommended by ABE (RFC 8511) for congestion
 * controllers using 0.7 as the loss-based factor. To disable, ABE set the `QUICLY_USE_ABE` macro to 0.
 */
#define QUICLY_BETA_ECN 0.85

#ifndef QUICLY_USE_ABE
#define QUICLY_USE_ABE 1
#endif

/* factors defined by Rapid Start (see the I-D) */
#define QUICLY_RAPID_START_K (2. / 3)
#define QUICLY_RAPID_START_ACK_FACTOR(beta) (QUICLY_RAPID_START_K * (1 - (beta)))
#define QUICLY_RAPID_START_LOSS_FACTOR(beta) ((beta) + QUICLY_RAPID_START_ACK_FACTOR(beta))

/**
 * Holds pointers to concrete congestion control implementation functions.
 */
typedef const struct st_quicly_cc_type_t quicly_cc_type_t;

/**
 * Congestion control configuration. Congestion controllers retain a pointer to the configuration they have been initialized with.
 */
typedef struct st_quicly_cc_conf_t {
    /**
     * initializes a congestion controller for given connection
     */
    struct st_quicly_init_cc_t *init_cc;
    /**
     * initial CWND in terms of packet numbers
     */
    uint32_t initcwnd_packets;
    /**
     * if rapid start should be used
     */
    uint8_t rapid_start : 1;
    /**
     * if ABBA accelerated bottleneck bandwidth adaptation should be used when using CUBIC or Cuback
     */
    uint8_t abba : 1;
    /**
     * if CC growth should be normalized to the reference packet size rather than the path's maximum UDP payload size
     */
    uint8_t normalize_mtu : 1;
} quicly_cc_conf_t;

enum en_quicly_cc_rapid_start_state_t {
    /**
     * Rapid Start does not affect congestion control.
     */
    QUICLY_CC_RAPID_START_STATE_INACTIVE,
    /**
     * Rapid Start is probing during startup, selecting either 2x or 3x growth based on the RTT floor.
     */
    QUICLY_CC_RAPID_START_STATE_PROBING,
    /**
     * Rapid Start is handling the first recovery period.
     */
    QUICLY_CC_RAPID_START_STATE_RECOVERY
};

/**
 * state used by rapid start
 */
struct st_quicly_cc_rapid_start_t {
    /**
     * Current lifecycle phase.
     */
    enum en_quicly_cc_rapid_start_state_t state;
    /**
     * Whether the first recovery was entered due to ECN rather than packet loss. Valid only in `RECOVERY`.
     */
    uint8_t by_ecn : 1;
    /**
     * Lower bound for CWND adjustments made during `RECOVERY`.
     */
    uint32_t cwnd_floor;
};

/**
 * State used exclusively by Cuback; see `quicly_cc_type_cuback`.
 */
struct st_quicly_cc_cuback_t {
    /**
     * Delivery rate in bytes per second observed at the last congestion event. As the bottleneck remains saturated, this is what
     * converts the bytes being acked into the passage of time, which is the ack-driven substitute for the clock that Cubic reads.
     * Set to 0 if bandwidth is unknown due to switching from another CC.
     */
    double bandwidth;
    /**
     * Cubic's cwnd_prior, in bytes.
     */
    uint32_t cwnd_prior;
    /**
     * Whether fast convergence is applied to the current epoch. When set, W_max is the midpoint between the cwnd_prior and
     * cwnd_epoch.
     */
    unsigned fast_convergence : 1;
    /**
     * Whether the reduction that began the current epoch used QUICLY_BETA_ECN (i.e., ABE).
     */
    unsigned by_ecn : 1;
};

/**
 * ABBA augments CUBIC and Cuback to respond quickly to increases in available bandwidth, while retaining their ordinary window
 * growth and congestion response.
 *
 * It models the relationship between CWND and RTT using the congestion watermark and the lowest RTT observed afterward. An RTT
 * below the model's prediction signals room for faster window growth. Fitting requires enough RTT variation to estimate a useful
 * slope, which is reduced to two thirds while keeping the low point fixed. Far beyond the congestion window, the model instead
 * assumes RTT is proportional to CWND. Until CWND reaches the policy's cwnd_prior / beta, the model's growth multiplier is capped
 * at beta^(-2/3) to yield under persistent congestion. On each ACK, it selects the larger of ordinary growth and model-based
 * acceleration.
 */
struct st_quicly_cc_abba_t {
    /**
     * Retains the watermarks of one congestion-avoidance period. `high` pairs the pre-reduction window with the RTT upon
     * congestion; if it was a packet loss, the minimum RTT observed through recovery is adopted, because senders continue pushing
     * until loss feedback arrives after 1 RTT, keeping the queue full. If it was an ECN-CE event, minimum RTT observed within 1
     * RTT before CE is adopted, since CE is an indication of *persistent* congestion (Section 5.1 of RFC 3168). `low` starts at
     * recovery exit and tracks the point at the lowest RTT observed during congestion avoidance.
     */
    struct {
        uint32_t cwnd;
        float rtt;
    } high, low;
    /**
     * RTT = a * CWND + b. An unfitted model has a == 0 and b set to NaN: zero slope disables inversion, while NaN indicates no
     * prediction to preserve when establishing a proportional model. A horizontal fit has a == 0, b > 0; a proportional fit
     * has a > 0, b == 0.
     */
    float a, b;
    /**
     * Fractional bytes retained when accelerated growth determines the window.
     */
    float increase_remainder;
};

/**
 * State used by the Cubic policy implemented by cc-pico.c; see `quicly_cc_type_cubic`.
 */
struct st_quicly_cc_cubic_t {
    /**
     * Reno-friendly congestion window estimate. Zero indicates that congestion avoidance has not yet been initialized from the
     * post-recovery congestion window; until then, the remaining fields do not define a usable increase function.
     */
    double w_est;
    /**
     * Timestamp at which the current epoch began. Zero while the CUBIC clock is stopped. When resuming, `epoch_start` is set to the
     * current time and `k` is recalculated.
     */
    int64_t epoch_start;
    /**
     * Time offset from the beginning of the epoch until cwnd reaches W_max. NaN indicates that (re)calculation is needed, either
     * because its initialization is deferred or because the clock has been stopped (see above). Once calculated, K is negative when
     * the epoch begins above W_max.
     */
    double k;
    /**
     * Congestion window before the reduction at the latest congestion event.
     */
    uint32_t cwnd_prior;
    /**
     * Whether fast convergence applies to the current epoch. When set, W_max is the midpoint of `cwnd_prior` and the post-reduction
     * CWND retained in `quicly_cc_t::ssthresh`; otherwise W_max equals `cwnd_prior`.
     */
    unsigned fast_convergence : 1;
    /**
     * Whether the epoch adopted QUICLY_BETA_ECN (i.e., ABE).
     */
    unsigned by_ecn : 1;
    /**
     * Whether the sender is currently CC-limited.
     */
    unsigned cc_limited : 1;
};

typedef struct st_quicly_cc_t {
    /**
     * Congestion controller type.
     */
    quicly_cc_type_t *type;
    /**
     * Configuration.
     */
    const quicly_cc_conf_t *conf;
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
         * State information shared by Reno, Pico, Cubic, and Cuback.
         */
        struct {
            /**
             * Number of additional bytes that need to be acknowledged before increasing CWND by one MTU; zero means that the
             * value needs to be initialized.
             */
            uint32_t bytes_to_mtu_increase;
            /**
             * State used exclusively by each congestion controller.
             */
            union {
                /**
                 * [pico] size of the ACK interval after which CWND is increased by one MTU
                 */
                uint32_t bytes_per_mtu_increase;
                struct st_quicly_cc_cuback_t cuback;
                struct st_quicly_cc_cubic_t cubic;
            };
            /**
             * Bandwidth adaptation state shared by CUBIC and Cuback.
             */
            struct st_quicly_cc_abba_t abba;
            /**
             * State to undo a recovery episode when all packets deemed lost are later acknowledged. The packet number range being
             * tracked for undo is: start_pn <= pn < recovery_end. `num_packets_lost` counts packets in that range that were
             * declared lost and have not yet been late-ACKed. Other fields retain the values to be restored when
             * `num_packets_lost` becomes zero.
             */
            struct {
                uint64_t start_pn;
                uint32_t num_packets_lost;
                uint32_t cwnd;
                uint32_t ssthresh;
                uint32_t bytes_to_mtu_increase;
                struct st_quicly_cc_abba_t abba;
                union {
                    uint32_t bytes_per_mtu_increase;
                    struct st_quicly_cc_cuback_t cuback;
                    struct st_quicly_cc_cubic_t cubic;
                };
                uint64_t cwnd_increase_ca;
                uint64_t cwnd_increase_accel;
            } undo;
        } pico;
        /**
         * State information for the legacy CUBIC congestion controller.
         */
        struct {
            /**
             * Time offset from the latest congestion event until cwnd reaches W_max again.
             */
            double k;
            /**
             * Effective W_max retained from the latest congestion event.
             */
            uint32_t w_max;
            /**
             * Congestion window before the reduction at the latest congestion event.
             */
            uint32_t cwnd_prior;
            /**
             * Reno-friendly congestion window estimate.
             */
            double w_est;
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
     * rapid start
     */
    struct st_quicly_cc_rapid_start_t rapid_start;
    /**
     * Initial congestion window.
     */
    uint32_t cwnd_initial;
    /**
     * Congestion window at the end of slow start. (Equals 0 if still in slow start.)
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
     * Total number of loss episodes undone.
     */
    uint32_t num_loss_episodes_undone;
    /**
     * Total number of loss episodes undone that occurred during startup.
     */
    uint32_t num_loss_episodes_undone_in_startup;
    /**
     * Total number of loss episodes that was reported only by ECN (hence no packet loss).
     */
    uint32_t num_ecn_loss_episodes;
    /**
     * Total number of congestion-avoidance episodes for which ABBA's model became fit (i.e., obtained a usable, non-horizontal
     * RTT/CWND slope), making acceleration possible. This does not imply that acceleration actually increased CWND.
     */
    uint32_t num_accel_eligible_episodes;
    /**
     * Total bytes added to CWND while in congestion avoidance.
     */
    uint64_t cwnd_increase_ca;
    /**
     * Total bytes added to CWND by ABBA's growth model; a subset of `cwnd_increase_ca`.
     */
    uint64_t cwnd_increase_accel;
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
     * Called after a packet is sent.
     */
    void (*cc_on_sent)(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now);
    /**
     * Switches the underlying algorithm of `cc` to that of `cc_switch`, returning a boolean whether the operation was successful.
     */
    int (*cc_switch)(quicly_cc_t *cc);
    /**
     * [optional] Called when a packet previously detected as lost is later acknowledged.
     */
    void (*cc_on_late_ack)(quicly_cc_t *cc, uint64_t pn, int64_t now);
    /**
     * [optional] called by quicly to enter jumpstart.
     */
    void (*cc_jumpstart)(quicly_cc_t *cc, uint32_t cwnd, uint64_t next_pn);
    /**
     * [optional] updates whether the sender is CC-limited
     */
    void (*cc_update_cc_limited)(quicly_cc_t *cc, int cc_limited, int64_t now);
};

/**
 * The type objects for each CC. These can be used for testing the type of each `quicly_cc_t`.
 */
extern quicly_cc_type_t quicly_cc_type_reno, quicly_cc_type_cubic, quicly_cc_type_cubic_legacy, quicly_cc_type_pico,
    quicly_cc_type_cuback;
/**
 * The factory methods for each CC.
 */
extern struct st_quicly_init_cc_t quicly_cc_reno_init, quicly_cc_cubic_init, quicly_cc_cubic_legacy_init, quicly_cc_pico_init,
    quicly_cc_cuback_init;

/**
 * A null-terminated list of all CC types.
 */
extern quicly_cc_type_t *quicly_cc_all_types[];

/**
 * Calculates the initial congestion window size given the maximum UDP payload size.
 */
uint32_t quicly_cc_calc_initial_cwnd(uint32_t max_packets, uint16_t max_udp_payload_size);

/**
 * Updates ECN counter when loss is observed.
 */
static void quicly_cc__update_ecn_episodes(quicly_cc_t *cc, uint32_t lost_bytes, uint64_t lost_pn);

static void quicly_cc_jumpstart_reset(quicly_cc_t *cc);
static int quicly_cc_in_jumpstart(quicly_cc_t *cc);
static int quicly_cc_is_jumpstart_ack(quicly_cc_t *cc, uint64_t pn);
static void quicly_cc_jumpstart_enter(quicly_cc_t *cc, uint32_t jump_cwnd, uint64_t next_pn);
static void quicly_cc_jumpstart_on_acked(quicly_cc_t *cc, int in_recovery, uint32_t bytes, uint64_t largest_acked,
                                         uint32_t inflight, uint64_t next_pn);
static void quicly_cc_jumpstart_on_first_loss(quicly_cc_t *cc, uint64_t lost_pn, int skip_cwnd_adjust);

/**
 * Initializes the heuristics needed to determine if slow start needs to be acclerated (i.e., 3x).
 */
static void quicly_cc_init_rapid_start(struct st_quicly_cc_rapid_start_t *rs, int64_t now);
/**
 * If Rapid Start is currently affecting congestion control.
 */
static int quicly_cc_rapid_start_is_active(struct st_quicly_cc_rapid_start_t *rs);
/**
 * If Rapid Start is handling the first recovery period.
 */
static int quicly_cc_rapid_start_is_in_first_recovery(struct st_quicly_cc_rapid_start_t *rs);
/**
 * Reads RTT variables and returns if Slow Start should be accelerated.
 */
static int quicly_cc_rapid_start_use_3x(struct st_quicly_cc_rapid_start_t *rs, const quicly_rtt_t *rtt);
/**
 * Ends rapid start and enters the first recovery period.
 */
static void quicly_cc_rapid_start_on_first_lost(struct st_quicly_cc_rapid_start_t *rs, uint32_t *cwnd, int by_ecn,
                                                uint32_t cwnd_floor);
/**
 * During the first recovery period, updates CWND. Must only be called during the first recovery period.
 */
static void quicly_cc_rapid_start_on_recovery(struct st_quicly_cc_rapid_start_t *rs, uint32_t *cwnd, uint32_t bytes_acked,
                                              uint32_t bytes_lost);
/**
 * Called upon exitting recovery, to disable rapid start.
 */
static void quicly_cc_rapid_start_exit_recovery(struct st_quicly_cc_rapid_start_t *rs);

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

inline int quicly_cc_is_jumpstart_ack(quicly_cc_t *cc, uint64_t pn)
{
    return cc->jumpstart.enter_pn <= pn && pn < cc->jumpstart.exit_pn;
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
    int is_jumpstart_ack = quicly_cc_is_jumpstart_ack(cc, largest_acked);

    /* remember the amount of bytes acked for the packets sent in jumpstart */
    if (is_jumpstart_ack)
        cc->jumpstart.bytes_acked += bytes;

    if (in_recovery) {
        /* Propotional Rate Reduction: if a loss is observed due to jumpstart, CWND is adjusted so that it would become bytes that
         * passed through to the client during the jumpstart phase of exactly 1 RTT, when the last ACK for the jumpstart phase is
         * received (TODO use QUICLY_BETA_ECN?) */
        if (is_jumpstart_ack && cc->cwnd < cc->jumpstart.bytes_acked * QUICLY_BETA_LOSS)
            cc->cwnd = cc->jumpstart.bytes_acked * QUICLY_BETA_LOSS;
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

inline void quicly_cc_jumpstart_on_first_loss(quicly_cc_t *cc, uint64_t lost_pn, int skip_cwnd_adjust)
{
    if (cc->jumpstart.enter_pn != UINT64_MAX && lost_pn < cc->jumpstart.exit_pn) {
        assert(cc->cwnd < cc->ssthresh);
        /* CWND is set to the amount of bytes ACKed during the jump start phase plus the value before jump start */
        if (!skip_cwnd_adjust) {
            cc->cwnd = cc->jumpstart.bytes_acked;
            if (cc->cwnd < cc->cwnd_initial)
                cc->cwnd = cc->cwnd_initial;
        }
        if (cc->jumpstart.exit_pn == UINT64_MAX)
            cc->jumpstart.exit_pn = lost_pn;
    }
}

inline void quicly_cc_init_rapid_start(struct st_quicly_cc_rapid_start_t *rs, int64_t now)
{
    (void)now;
    rs->state = QUICLY_CC_RAPID_START_STATE_PROBING;
}

inline int quicly_cc_rapid_start_is_active(struct st_quicly_cc_rapid_start_t *rs)
{
    return rs->state != QUICLY_CC_RAPID_START_STATE_INACTIVE;
}

inline int quicly_cc_rapid_start_is_in_first_recovery(struct st_quicly_cc_rapid_start_t *rs)
{
    return rs->state == QUICLY_CC_RAPID_START_STATE_RECOVERY;
}

inline int quicly_cc_rapid_start_use_3x(struct st_quicly_cc_rapid_start_t *rs, const quicly_rtt_t *rtt)
{
    if (rs->state != QUICLY_CC_RAPID_START_STATE_PROBING || rtt->latest == 0)
        return 0;

    /* Disable Rapid Start below four milliseconds, where it provides little benefit and the one-millisecond clock cannot divide
     * the minimum RTT into four floor-tracking slots. */
    if (rtt->minimum < PTLS_ELEMENTSOF(rtt->floor.samples)) {
        rs->state = QUICLY_CC_RAPID_START_STATE_INACTIVE;
        return 0;
    }

    /* If the latest RTT is below max(min_rtt + 4ms, min_rtt * 1.1), adopt a higher increase rate (i.e., 3x per RTT) than the
     * ordinary Slow Start (2x per RTT). The thresholds are chosen so that they do not overlap with HyStart++, which reduces the
     * increase rate to 1.25x. */
    float threshold = rtt->minimum + 4;
    if (threshold < rtt->minimum * 35 / 32)
        threshold = rtt->minimum * 35 / 32;

    return quicly_rtt_get_floor(rtt) <= threshold;
}

inline void quicly_cc_rapid_start_on_first_lost(struct st_quicly_cc_rapid_start_t *rs, uint32_t *cwnd, int by_ecn,
                                                uint32_t cwnd_floor)
{
    if (rs->state == QUICLY_CC_RAPID_START_STATE_INACTIVE)
        return;

    assert(rs->state == QUICLY_CC_RAPID_START_STATE_PROBING);
    rs->state = QUICLY_CC_RAPID_START_STATE_RECOVERY;
    rs->by_ecn = by_ecn != 0;

    double beta = QUICLY_USE_ABE && rs->by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS;

    rs->cwnd_floor = *cwnd * (1. / 3) * beta;
    if (rs->cwnd_floor < cwnd_floor)
        rs->cwnd_floor = cwnd_floor;

    /* the silence factor is identical to the loss factor */
    *cwnd *= QUICLY_RAPID_START_LOSS_FACTOR(beta);
    if (*cwnd < rs->cwnd_floor)
        *cwnd = rs->cwnd_floor;
}

inline void quicly_cc_rapid_start_on_recovery(struct st_quicly_cc_rapid_start_t *rs, uint32_t *cwnd, uint32_t bytes_acked,
                                              uint32_t bytes_lost)
{
    if (rs->state == QUICLY_CC_RAPID_START_STATE_INACTIVE)
        return;

    assert(rs->state == QUICLY_CC_RAPID_START_STATE_RECOVERY);

    static const struct {
        double ack, loss;
    } factors[] = {
#define ENTRY(beta) {QUICLY_RAPID_START_ACK_FACTOR(beta), QUICLY_RAPID_START_LOSS_FACTOR(beta)}
        ENTRY(QUICLY_BETA_LOSS),
        ENTRY(QUICLY_BETA_ECN),
#undef ENTRY
    };

    int use_ecn_factor = QUICLY_USE_ABE && rs->by_ecn;
    uint32_t reduction = factors[use_ecn_factor].ack * bytes_acked + factors[use_ecn_factor].loss * bytes_lost;
    assert(reduction <= *cwnd && "CWND never underflows");
    *cwnd -= reduction;
    if (*cwnd < rs->cwnd_floor)
        *cwnd = rs->cwnd_floor;
}

inline void quicly_cc_rapid_start_exit_recovery(struct st_quicly_cc_rapid_start_t *rs)
{
    assert(rs->state == QUICLY_CC_RAPID_START_STATE_RECOVERY);
    rs->state = QUICLY_CC_RAPID_START_STATE_INACTIVE;
}

#ifdef __cplusplus
}
#endif

#endif
