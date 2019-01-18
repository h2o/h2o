/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#ifndef quicly_loss_h
#define quicly_loss_h

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"

typedef struct quicly_loss_conf_t {
    /**
     * Maximum number of tail loss probes before an RTO fires.
     */
    unsigned max_tlps;
    /**
     * Maximum reordering in time space before time based loss detection considers a packet lost. In percentile (1/1024) of an RTT.
     */
    unsigned time_reordering_percentile;
    /**
     * Minimum time in the future a tail loss probe alarm may be set for.
     */
    uint32_t min_tlp_timeout;
    /**
     * Minimum time in the future an RTO alarm may be set for.
     */
    uint32_t min_rto_timeout;
    /**
     * The default RTT used before an RTT sample is taken.
     */
    uint32_t default_initial_rtt;
} quicly_loss_conf_t;

#define QUICLY_LOSS_DEFAULT_MAX_TLPS 2
#define QUICLY_LOSS_DEFAULT_TIME_REORDERING_PERCENTILE (1024 / 8)
#define QUICLY_LOSS_DEFAULT_MIN_TLP_TIMEOUT 10
#define QUICLY_LOSS_DEFAULT_MIN_RTO_TIMEOUT 200
#define QUICLY_LOSS_DEFAULT_INITIAL_RTT 100
#define QUICLY_LOSS_MAX_RTO_COUNT 16 /* 65 seconds under 1ms granurality */

extern quicly_loss_conf_t quicly_loss_default_conf;

typedef struct quicly_rtt_t {
    uint32_t minimum;
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
} quicly_rtt_t;

static void quicly_rtt_init(quicly_rtt_t *rtt, const quicly_loss_conf_t *conf, uint32_t initial_rtt);
static void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t latest_rtt, uint32_t ack_delay);

typedef struct quicly_loss_t {
    /**
     * configuration
     */
    const quicly_loss_conf_t *conf;
    /**
     * pointer to transport parameter containing max_ack_delay
     */
    uint8_t *max_ack_delay;
    /**
     * The number of times a tail loss probe has been sent without receiving an ack.
     */
    uint8_t tlp_count;
    /**
     * The number of times an rto has been sent without receiving an ack.
     */
    uint8_t rto_count;
    /**
     * The last packet number sent prior to the first retransmission timeout.
     */
    uint64_t largest_sent_before_rto;
    /**
     * The time the most recent packet was sent.
     */
    int64_t time_of_last_packet_sent;
    /**
     * The largest packet number acknowledged in an ack frame.
     */
    uint64_t largest_acked_packet;
    /**
     * The time at which the next packet will be considered lost based on exceeding the reordering window in time.
     */
    int64_t loss_time;
    /**
     *
     */

    /**
     * The time at when lostdetect_on_alarm should be called.
     */
    int64_t alarm_at;
    /**
     * rtt
     */
    quicly_rtt_t rtt;
} quicly_loss_t;

typedef int (*quicly_loss_do_detect_cb)(quicly_loss_t *r, uint64_t largest_acked, uint32_t delay_until_lost, int64_t *loss_time);

static void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt, uint8_t *max_ack_delay);
static void quicly_loss_update_alarm(quicly_loss_t *r, int64_t now, int64_t last_retransmittable_sent_at, int has_outstanding);

/* called every time a is received for congestion control and loss recovery.
 * TODO (jri): Make this function be called on each packet newly acked, rather than every new ack received.
 */
static int quicly_loss_on_packet_acked(quicly_loss_t *r, uint64_t acked);

static void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_acked, uint32_t latest_rtt, uint32_t ack_delay,
                                        int is_ack_only);
static int quicly_loss_on_alarm(quicly_loss_t *r, uint64_t largest_sent, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect,
                                size_t *num_packets_to_send);
static int quicly_loss_detect_loss(quicly_loss_t *r, uint64_t largest_pn, quicly_loss_do_detect_cb do_detect);

/* inline definitions */

inline void quicly_rtt_init(quicly_rtt_t *rtt, const quicly_loss_conf_t *conf, uint32_t initial_rtt)
{
    rtt->minimum = UINT32_MAX;
    rtt->latest = initial_rtt;
    rtt->smoothed = 0;
    rtt->variance = 0;
}

inline void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t _latest_rtt, uint32_t ack_delay)
{
    rtt->latest = _latest_rtt != 0 ? _latest_rtt : 1; /* set minimum to 1 to avoid special cases */

    /* update minimum */
    if (rtt->latest < rtt->minimum)
        rtt->minimum = rtt->latest;

    /* rtt->latest = max(rtt->minimum, rtt->latest - ack_delay) */
    if (rtt->latest > ack_delay) {
        rtt->latest -= ack_delay;
    } else {
        rtt->latest = 0;
    }
    if (rtt->latest < rtt->minimum)
        rtt->latest = rtt->minimum;

    /* smoothed and variance */
    if (rtt->smoothed == 0) {
        rtt->smoothed = rtt->latest;
    } else {
        uint32_t absdiff = rtt->smoothed >= rtt->latest ? rtt->smoothed - rtt->latest : rtt->latest - rtt->smoothed;
        rtt->variance = (rtt->variance * 3 + absdiff) / 4;
        rtt->smoothed = (rtt->smoothed * 7 + rtt->latest) / 8;
    }
    assert(rtt->smoothed != 0);
}

inline void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt, uint8_t *max_ack_delay)
{
    *r = (quicly_loss_t){conf, max_ack_delay, 0, 0, 0, 0, 0, INT64_MAX, INT64_MAX};
    quicly_rtt_init(&r->rtt, conf, initial_rtt);
}

inline void quicly_loss_update_alarm(quicly_loss_t *r, int64_t now, int64_t last_retransmittable_sent_at, int has_outstanding)
{
    if (has_outstanding) {
        int64_t alarm_duration;
        if (r->loss_time != INT64_MAX) {
            /* Time loss detection */
            alarm_duration = r->loss_time - last_retransmittable_sent_at;
        } else if (r->rtt.smoothed == 0) {
            /* handshake timer */
            alarm_duration = 2 * r->rtt.latest /* should contain intial rtt */;
            if (alarm_duration < r->conf->min_tlp_timeout)
                alarm_duration = r->conf->min_tlp_timeout;
            alarm_duration <<= r->tlp_count;
        } else {
            /* RTO or TLP alarm (FIXME observe and use max_ack_delay) */
            alarm_duration = r->rtt.smoothed + 4 * r->rtt.variance + *r->max_ack_delay;
            if (alarm_duration < r->conf->min_rto_timeout)
                alarm_duration = r->conf->min_rto_timeout;
            alarm_duration <<= r->rto_count < QUICLY_LOSS_MAX_RTO_COUNT ? r->rto_count : QUICLY_LOSS_MAX_RTO_COUNT;
            if (r->tlp_count < r->conf->max_tlps) {
                /* Tail Loss Probe */
                int64_t tlp_alarm_duration = r->rtt.smoothed * 3 / 2 + *r->max_ack_delay;
                if (tlp_alarm_duration < r->conf->min_tlp_timeout)
                    tlp_alarm_duration = r->conf->min_tlp_timeout;
                if (tlp_alarm_duration < alarm_duration)
                    alarm_duration = tlp_alarm_duration;
            }
        }
        if (r->alarm_at > last_retransmittable_sent_at + alarm_duration) {
            r->alarm_at = last_retransmittable_sent_at + alarm_duration;
            if (r->alarm_at < now)
                r->alarm_at = now;
        }
    } else {
        r->alarm_at = INT64_MAX;
        r->loss_time = INT64_MAX;
    }
}

inline int quicly_loss_on_packet_acked(quicly_loss_t *r, uint64_t acked)
{
    int rto_verified = r->rto_count > 0 && acked > r->largest_sent_before_rto;
    r->tlp_count = 0;
    r->rto_count = 0;
    return rto_verified;
}

inline void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_acked, uint32_t latest_rtt, uint32_t ack_delay,
                                        int is_ack_only)
{
    if (r->largest_acked_packet < largest_acked)
        r->largest_acked_packet = largest_acked;
    if (latest_rtt != UINT32_MAX)
        quicly_rtt_update(&r->rtt, latest_rtt, ack_delay);
}

/* This function updates the early retransmit timer and indicates to the caller how many packets should be sent.
 * After calling this function, app should:
 *  * if num_packets_to_send is zero, send things normally
 *  * if num_packets_to_send is non-zero, send the specfied number of packets immmediately
 * and then call quicly_loss_update_alarm and update the alarm */
inline int quicly_loss_on_alarm(quicly_loss_t *r, uint64_t largest_sent, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect,
                                size_t *num_packets_to_send)
{
    r->alarm_at = INT64_MAX;
    if (r->loss_time != INT64_MAX) {
        /* Early retransmit or Time Loss Detection */
        *num_packets_to_send = 0;
        return quicly_loss_detect_loss(r, largest_acked, do_detect);
    }
    if (r->tlp_count < r->conf->max_tlps) {
        /* Tail Loss Probe. */
        r->tlp_count++;
        *num_packets_to_send = 1;
        return 0;
    }
    /* RTO */
    if (r->rto_count == 0)
        r->largest_sent_before_rto = largest_sent;
    ++r->rto_count;
    *num_packets_to_send = 2;
    return 0;
}

inline int quicly_loss_detect_loss(quicly_loss_t *r, uint64_t largest_pn, quicly_loss_do_detect_cb do_detect)
{
    uint32_t delay_until_lost = (r->rtt.latest > r->rtt.smoothed ? r->rtt.latest : r->rtt.smoothed) * 9 / 8;
    int64_t loss_time;
    int ret;

    r->loss_time = INT64_MAX;

    if ((ret = do_detect(r, largest_pn, delay_until_lost, &loss_time)) != 0)
        return ret;
    if (loss_time != INT64_MAX)
        r->loss_time = loss_time;

    return 0;
}

#endif
