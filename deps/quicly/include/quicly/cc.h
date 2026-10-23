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
 * Beta used when congestion is signalled by ECN-CE alone; 0.85 is the value recommended by RFC 8511 for congestion controllers
 * using 0.7 as the loss-based factor.
 */
#define QUICLY_BETA_ECN 0.85

/* factors defined by Rapid Start (see the I-D) */
#define QUICLY_RAPID_START_K (2. / 3)
#define QUICLY_RAPID_START_ACK_FACTOR(beta) (QUICLY_RAPID_START_K * (1 - (beta)))
#define QUICLY_RAPID_START_LOSS_FACTOR(beta) ((beta) + QUICLY_RAPID_START_ACK_FACTOR(beta))

/**
 * Holds pointers to concrete congestion control implementation functions.
 */
typedef const struct st_quicly_cc_type_t quicly_cc_type_t;

/**
 * state used by rapid start
 */
struct st_quicly_cc_rapid_start_t {
    /**
     * Until when the newest sample (i.e., `rtt_samples[0]`) is to be updated. Once congestion is observed, this field is set to -1
     * and `recovery` is used; upon exiting that recovery period, it is set to 0, indicating that rapid start is disabled.
     */
    int64_t newest_rtt_sample_until;
    union {
        /**
         * Records the RTT floor for most recent periods of 4, where the duration the period is defined as `floor(rtt.minimum / 4)`.
         * [0] holds the newest entry, [3] holds the oldest one.
         */
        uint32_t rtt_samples[4];
        /**
         * Values retained for the duration of the first recovery period.
         */
        struct {
            /**
             * The cause of the recovery entry. Different factors are used based on the cause.
             */
            unsigned by_ecn : 1;
            /**
             * Retains the lower limit CWND can be reduced.
             */
            uint32_t cwnd_floor;
        } recovery;
    };
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
     * Whether growth is normalized to QUICLY_CC_REFERENCE_MTU.
     */
    unsigned normalize_mtu : 1;
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
                union {
                    uint32_t bytes_per_mtu_increase;
                    struct st_quicly_cc_cuback_t cuback;
                    struct st_quicly_cc_cubic_t cubic;
                };
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
     * [optional] turns on rapid start
     */
    void (*enable_rapid_start)(quicly_cc_t *cc, int64_t now);
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
 * If rapid start is used on the connection.
 */
static int quicly_cc_rapid_start_is_enabled(struct st_quicly_cc_rapid_start_t *rs);
/**
 * If rapid start is in recovery
 */
static int quicly_cc_rapid_start_is_in_recovery(struct st_quicly_cc_rapid_start_t *rs);
/**
 * Updates heuristics needed to determine if slow start needs to be acclerated (i.e., 3x). Must not be called once the connection
 * enters the recovery period.
 */
static void quicly_cc_rapid_start_update_rtt(struct st_quicly_cc_rapid_start_t *rs, const quicly_rtt_t *rtt, int64_t now);
/**
 * Reads RTT variables from `loss`, updates the heuristics (iff now != 0), and returns if the Slow Start should be accelerated.
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
    for (size_t i = 0; i < PTLS_ELEMENTSOF(rs->rtt_samples); ++i)
        rs->rtt_samples[i] = UINT32_MAX;
    rs->newest_rtt_sample_until = now + 1; /* 1 is added to guarantee that `newest_slot_until` will be zero (i.e., disabled) */
}

inline int quicly_cc_rapid_start_is_enabled(struct st_quicly_cc_rapid_start_t *rs)
{
    return rs->newest_rtt_sample_until != 0;
}

inline int quicly_cc_rapid_start_is_in_recovery(struct st_quicly_cc_rapid_start_t *rs)
{
    return rs->newest_rtt_sample_until == -1;
}

inline void quicly_cc_rapid_start_update_rtt(struct st_quicly_cc_rapid_start_t *rs, const quicly_rtt_t *rtt, int64_t now)
{
    /* bail out unless enabled */
    if (rs->newest_rtt_sample_until <= 0)
        return;

    /* when the delay is tiny (minrtt < 4ms) benefits are small, so disable rapid start to guard `sample_duration` becoming zero */
    if (rtt->minimum < PTLS_ELEMENTSOF(rs->rtt_samples)) {
        rs->newest_rtt_sample_until = 0;
        return;
    }

    /* fast path: if the newest slot covers `now`, update the slot and return */
    if (now < rs->newest_rtt_sample_until) {
        if (rs->rtt_samples[0] > rtt->latest)
            rs->rtt_samples[0] = rtt->latest;
        return;
    }

    /* slow path: determine the distance to move in the unit of slots */
    int64_t sample_duration = rtt->minimum / PTLS_ELEMENTSOF(rs->rtt_samples);
    size_t distance = (now - rs->newest_rtt_sample_until) / sample_duration + 1;

    /* move */
    for (size_t dst = PTLS_ELEMENTSOF(rs->rtt_samples) - 1; dst != 0; --dst)
        rs->rtt_samples[dst] = dst >= distance ? rs->rtt_samples[dst - distance] : UINT32_MAX;

    /* fill the newest slot */
    rs->rtt_samples[0] = rtt->latest;
    rs->newest_rtt_sample_until += sample_duration * distance;
    assert(rs->newest_rtt_sample_until - sample_duration <= now && now < rs->newest_rtt_sample_until);
}

inline int quicly_cc_rapid_start_use_3x(struct st_quicly_cc_rapid_start_t *rs, const quicly_rtt_t *rtt)
{
    if (rs->newest_rtt_sample_until <= 0)
        return 0;

    /* If the latest RTT is below max(min_rtt + 4ms, min_rtt * 1.1), adopt a higher increase rate (i.e., 3x per RTT) than the
     * ordinary Slow Start (2x per RTT). The thresholds are chosen so that they do not overlap with HyStart++, which reduces the
     * increase rate to 1.25x. */
    uint32_t threshold = rtt->minimum + 4;
    if (threshold < rtt->minimum * 35 / 32)
        threshold = rtt->minimum * 35 / 32;

    uint32_t floor = UINT32_MAX;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(rs->rtt_samples); ++i)
        if (floor > rs->rtt_samples[i])
            floor = rs->rtt_samples[i];

    return floor <= threshold;
}

inline void quicly_cc_rapid_start_on_first_lost(struct st_quicly_cc_rapid_start_t *rs, uint32_t *cwnd, int by_ecn,
                                                uint32_t cwnd_floor)
{
    if (rs->newest_rtt_sample_until == 0)
        return;

    assert(rs->newest_rtt_sample_until > 0);
    rs->newest_rtt_sample_until = -1;
    rs->recovery.by_ecn = by_ecn != 0;

    double beta = rs->recovery.by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS;

    rs->recovery.cwnd_floor = *cwnd * (1. / 3) * beta;
    if (rs->recovery.cwnd_floor < cwnd_floor)
        rs->recovery.cwnd_floor = cwnd_floor;

    /* the silence factor is identical to the loss factor */
    *cwnd *= QUICLY_RAPID_START_LOSS_FACTOR(beta);
    if (*cwnd < rs->recovery.cwnd_floor)
        *cwnd = rs->recovery.cwnd_floor;
}

inline void quicly_cc_rapid_start_on_recovery(struct st_quicly_cc_rapid_start_t *rs, uint32_t *cwnd, uint32_t bytes_acked,
                                              uint32_t bytes_lost)
{
    if (rs->newest_rtt_sample_until == 0)
        return;

    assert(rs->newest_rtt_sample_until == -1);

    static const struct {
        double ack, loss;
    } factors[] = {
#define ENTRY(beta) {QUICLY_RAPID_START_ACK_FACTOR(beta), QUICLY_RAPID_START_LOSS_FACTOR(beta)}
        ENTRY(QUICLY_BETA_LOSS),
        ENTRY(QUICLY_BETA_ECN),
#undef ENTRY
    };

    uint32_t reduction = factors[rs->recovery.by_ecn].ack * bytes_acked + factors[rs->recovery.by_ecn].loss * bytes_lost;
    assert(reduction <= *cwnd && "CWND never underflows");
    *cwnd -= reduction;
    if (*cwnd < rs->recovery.cwnd_floor)
        *cwnd = rs->recovery.cwnd_floor;
}

inline void quicly_cc_rapid_start_exit_recovery(struct st_quicly_cc_rapid_start_t *rs)
{
    assert(rs->newest_rtt_sample_until == -1);
    rs->newest_rtt_sample_until = 0;
}

#ifdef __cplusplus
}
#endif

#endif
