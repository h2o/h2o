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

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"

typedef struct quicly_loss_conf_t {
    /**
     * Maximum reordering in time space before time based loss detection considers a packet lost. In percentile (1/1024) of an RTT.
     */
    unsigned time_reordering_percentile;
    /**
     * Minimum time in the future a PTO alarm may be set for.
     */
    uint32_t min_pto;
    /**
     * The default RTT used before an RTT sample is taken.
     */
    uint32_t default_initial_rtt;
} quicly_loss_conf_t;

#define QUICLY_LOSS_DEFAULT_TIME_REORDERING_PERCENTILE (1024 / 8)

extern quicly_loss_conf_t quicly_loss_default_conf;

typedef struct quicly_rtt_t {
    uint32_t minimum;
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
} quicly_rtt_t;

static void quicly_rtt_init(quicly_rtt_t *rtt, const quicly_loss_conf_t *conf, uint32_t initial_rtt);
static void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t latest_rtt, uint32_t ack_delay);
static uint32_t quicly_rtt_get_pto(quicly_rtt_t *rtt, uint32_t max_ack_delay);

typedef struct quicly_loss_t {
    /**
     * configuration
     */
    const quicly_loss_conf_t *conf;
    /**
     * pointer to transport parameter containing the peer's max_ack_delay
     */
    uint16_t *max_ack_delay;
    /**
     * pointer to transport parameter containing the peer's ack exponent
     */
    uint8_t *ack_delay_exponent;
    /**
     * The number of consecutive PTOs (PTOs that have fired without receiving an ack).
     */
    uint8_t pto_count;
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
     * The time at when lostdetect_on_alarm should be called.
     */
    int64_t alarm_at;
    /**
     * rtt
     */
    quicly_rtt_t rtt;
} quicly_loss_t;

typedef int (*quicly_loss_do_detect_cb)(quicly_loss_t *r, uint64_t largest_acked, uint32_t delay_until_lost, int64_t *loss_time);

static void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt, uint16_t *max_ack_delay,
                             uint8_t *ack_delay_exponent);

static void quicly_loss_update_alarm(quicly_loss_t *r, int64_t now, int64_t last_retransmittable_sent_at, int has_outstanding);

/* called when an ACK is received
 */
static void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_newly_acked, int64_t now, int64_t sent_at,
                                        uint64_t ack_delay_encoded, int ack_eliciting);

/* This function updates the early retransmit timer and indicates to the caller how many packets should be sent.
 * After calling this function, app should:
 *  * if num_packets_to_send is zero, send things normally
 *  * if num_packets_to_send is non-zero, send the specfied number of packets immmediately
 * and then call quicly_loss_update_alarm and update the alarm */
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

inline void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t latest_rtt, uint32_t ack_delay)
{
    assert(latest_rtt != UINT32_MAX);
    rtt->latest = latest_rtt != 0 ? latest_rtt : 1; /* Force minimum RTT sample to 1ms */

    /* update minimum */
    if (rtt->latest < rtt->minimum)
        rtt->minimum = rtt->latest;

    /* use ack_delay if it's a plausible value */
    if (rtt->latest > rtt->minimum + ack_delay)
        rtt->latest -= ack_delay;

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

inline uint32_t quicly_rtt_get_pto(quicly_rtt_t *rtt, uint32_t max_ack_delay)
{
    return rtt->smoothed + (rtt->variance != 0 ? rtt->variance * 4 : 1) + max_ack_delay;
}

inline void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt, uint16_t *max_ack_delay,
                             uint8_t *ack_delay_exponent)
{
    *r = (quicly_loss_t){conf, max_ack_delay, ack_delay_exponent, 0, 0, 0, INT64_MAX, INT64_MAX};
    quicly_rtt_init(&r->rtt, conf, initial_rtt);
}

inline void quicly_loss_update_alarm(quicly_loss_t *r, int64_t now, int64_t last_retransmittable_sent_at, int has_outstanding)
{
    if (has_outstanding) {
        assert(last_retransmittable_sent_at != INT64_MAX);
        int64_t alarm_duration;
        if (r->loss_time != INT64_MAX) {
            /* time-threshold loss detection */
            alarm_duration = r->loss_time - last_retransmittable_sent_at;
        } else if (r->rtt.smoothed == 0) {
            alarm_duration = 2 * r->rtt.latest; /* should contain initial rtt */
        } else {
            /* PTO alarm (FIXME observe and use max_ack_delay) */
            alarm_duration = r->rtt.smoothed + 4 * r->rtt.variance + *r->max_ack_delay;
            if (alarm_duration < r->conf->min_pto)
                alarm_duration = r->conf->min_pto;
            alarm_duration <<= r->pto_count < QUICLY_MAX_PTO_COUNT ? r->pto_count : QUICLY_MAX_PTO_COUNT;
        }
        r->alarm_at = last_retransmittable_sent_at + alarm_duration;
        if (r->alarm_at < now)
            r->alarm_at = now;
    } else {
        r->alarm_at = INT64_MAX;
        r->loss_time = INT64_MAX;
    }
}

inline void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_newly_acked, int64_t now, int64_t sent_at,
                                        uint64_t ack_delay_encoded, int ack_eliciting)
{
    if (largest_newly_acked != UINT64_MAX)
        r->pto_count = 0;

    /* Only use RTT samples for new largest acked */
    if (largest_newly_acked == UINT64_MAX || r->largest_acked_packet >= largest_newly_acked)
        return;
    r->largest_acked_packet = largest_newly_acked;

    uint64_t ack_delay_microsecs = ack_delay_encoded << *r->ack_delay_exponent;
    uint32_t ack_delay_millisecs = (uint32_t)((ack_delay_microsecs * 2 + 1000) / 2000);
    /* Use min(ack_delay, max_ack_delay) for an ACK that acknowledges one or more ack-eliciting packets.
     * This makes it so that persistent late ACKs from the peer increase the SRTT.
     * OTOH, when the ACK does not acknowledge any ack-eliciting packets, the ack_delay can be large. In such cases,
     * allow for the ack_delay to be arbitrarily large (effectively bounded by the lifetime of these packets in the sent_map). */
    if (ack_delay_millisecs > *r->max_ack_delay && ack_eliciting)
        ack_delay_millisecs = *r->max_ack_delay;
    quicly_rtt_update(&r->rtt, (uint32_t)(now - sent_at), ack_delay_millisecs);
}

inline int quicly_loss_on_alarm(quicly_loss_t *r, uint64_t largest_sent, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect,
                                size_t *num_packets_to_send)
{
    r->alarm_at = INT64_MAX;
    if (r->loss_time != INT64_MAX) {
        /* Early retransmit or Time Loss Detection */
        *num_packets_to_send = 0;
        return quicly_loss_detect_loss(r, largest_acked, do_detect);
    }
    /* PTO */
    if (r->pto_count == 0)
        ++r->pto_count;
    *num_packets_to_send = 2;
    return 0;
}

inline int quicly_loss_detect_loss(quicly_loss_t *r, uint64_t largest_pn, quicly_loss_do_detect_cb do_detect)
{
    uint32_t delay_until_lost = ((r->rtt.latest > r->rtt.smoothed ? r->rtt.latest : r->rtt.smoothed) * 9 + 7) / 8;
    int64_t loss_time;
    int ret;

    r->loss_time = INT64_MAX;

    if ((ret = do_detect(r, largest_pn, delay_until_lost, &loss_time)) != 0)
        return ret;
    if (loss_time != INT64_MAX)
        r->loss_time = loss_time;

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
