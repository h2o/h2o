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
     * Minimum time in the future a PTO alarm may be set for. Typically set to alarm granularity.
     */
    uint32_t min_pto;
    /**
     * The default RTT used before an RTT sample is taken.
     */
    uint32_t default_initial_rtt;
    /**
     * Number of speculative PTOs at the end of a window. This must not be set to more than 3.
     */
    uint8_t num_speculative_ptos;
} quicly_loss_conf_t;

#define QUICLY_LOSS_DEFAULT_TIME_REORDERING_PERCENTILE (1024 / 8)

extern quicly_loss_conf_t quicly_loss_spec_conf;
extern quicly_loss_conf_t quicly_loss_performant_conf;

typedef struct quicly_rtt_t {
    uint32_t minimum;
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
} quicly_rtt_t;

static void quicly_rtt_init(quicly_rtt_t *rtt, const quicly_loss_conf_t *conf, uint32_t initial_rtt);
static void quicly_rtt_update(quicly_rtt_t *rtt, uint32_t latest_rtt, uint32_t ack_delay);
static uint32_t quicly_rtt_get_pto(quicly_rtt_t *rtt, uint32_t max_ack_delay, uint32_t min_pto);

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
    int8_t pto_count;
    /**
     * The time the most recent packet was sent.
     */
    int64_t time_of_last_packet_sent;
    /**
     * The largest packet number acknowledged in an ack frame, added by one (so that zero can mean "below any PN").
     */
    uint64_t largest_acked_packet_plus1;
    /**
     * Total number of application data bytes sent when the last tail occurred, not including retransmissions.
     */
    uint64_t total_bytes_sent;
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

static void quicly_loss_update_alarm(quicly_loss_t *r, int64_t now, int64_t last_retransmittable_sent_at, int has_outstanding,
                                     int can_send_stream_data, uint64_t total_bytes_sent);

/* called when an ACK is received
 */
static void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_newly_acked, int64_t now, int64_t sent_at,
                                        uint64_t ack_delay_encoded, int ack_eliciting);

/* This function updates the loss detection timer and indicates to the caller how many packets should be sent.
 * After calling this function, app should:
 *  * send min_packets_to_send number of packets immmediately. min_packets_to_send should never be 0.
 *  * if restrict_sending is true, limit sending to min_packets_to_send, otherwise as limited by congestion/flow control
 * and then call quicly_loss_update_alarm and update the alarm
 */
static int quicly_loss_on_alarm(quicly_loss_t *r, uint64_t largest_sent, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect,
                                size_t *min_packets_to_send, int *restrict_sending);

static int quicly_loss_detect_loss(quicly_loss_t *r, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect);

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

    /* update min_rtt */
    if (rtt->latest < rtt->minimum)
        rtt->minimum = rtt->latest;

    /* use ack_delay if it's a plausible value */
    if (rtt->latest > rtt->minimum + ack_delay)
        rtt->latest -= ack_delay;

    /* update smoothed_rtt and rttvar */
    if (rtt->smoothed == 0) {
        /* first RTT sample */
        rtt->smoothed = rtt->latest;
    } else {
        uint32_t absdiff = rtt->smoothed >= rtt->latest ? rtt->smoothed - rtt->latest : rtt->latest - rtt->smoothed;
        rtt->variance = (rtt->variance * 3 + absdiff) / 4;
        rtt->smoothed = (rtt->smoothed * 7 + rtt->latest) / 8;
    }
    assert(rtt->smoothed != 0);
}

inline uint32_t quicly_rtt_get_pto(quicly_rtt_t *rtt, uint32_t max_ack_delay, uint32_t min_pto)
{
    return rtt->smoothed + (rtt->variance != 0 ? rtt->variance * 4 : min_pto) + max_ack_delay;
}

inline void quicly_loss_init(quicly_loss_t *r, const quicly_loss_conf_t *conf, uint32_t initial_rtt, uint16_t *max_ack_delay,
                             uint8_t *ack_delay_exponent)
{
    *r = (quicly_loss_t){.conf = conf,
                         .max_ack_delay = max_ack_delay,
                         .ack_delay_exponent = ack_delay_exponent,
                         .pto_count = 0,
                         .time_of_last_packet_sent = 0,
                         .largest_acked_packet_plus1 = 0,
                         .total_bytes_sent = 0,
                         .loss_time = INT64_MAX,
                         .alarm_at = INT64_MAX};
    quicly_rtt_init(&r->rtt, conf, initial_rtt);
}

#include <stdio.h>
#include <inttypes.h>

inline void quicly_loss_update_alarm(quicly_loss_t *r, int64_t now, int64_t last_retransmittable_sent_at, int has_outstanding,
                                     int can_send_stream_data, uint64_t total_bytes_sent)
{
fprintf(stderr, "%s:%d (now=%" PRId64 ", last_retransmittable_sent_at=%" PRId64 ", has_outstanding=%d, can_send_stream_data=%d\n", __FUNCTION__, __LINE__, now, last_retransmittable_sent_at, has_outstanding, can_send_stream_data);
    if (!has_outstanding) {
        /* Do not set alarm if there's no data oustanding */
        r->alarm_at = INT64_MAX;
        r->loss_time = INT64_MAX;
        return;
    }
    assert(last_retransmittable_sent_at != INT64_MAX);
    int64_t alarm_duration;
    if (r->loss_time != INT64_MAX) {
        /* time-threshold loss detection */
        alarm_duration = r->loss_time - last_retransmittable_sent_at;
fprintf(stderr, "%s:%d\n", __FUNCTION__, __LINE__);
    } else if (r->rtt.smoothed == 0) {
        alarm_duration = 2 * r->rtt.latest; /* should contain initial rtt */
fprintf(stderr, "%s:%d\n", __FUNCTION__, __LINE__);
    } else {
        /* PTO alarm */
        /* the bitshift below is fine; it would take more than a millenium to overflow either alarm_duration or pto_count, even when
         * the timer granularity is nanosecond */
        assert(r->pto_count < 63);
        /* Probes are sent with a modified backoff to minimize latency of recovery. For instance, with num_speculative_ptos set to
         * 2, the backoff pattern is as follows:
         *   * when there's a tail: 0.25, 0.5, 1, 2, 4, 8, ...
         *   * when mid-transfer: 1, 1, 1, 2, 4, 8, ...
         * The first 2 probes in this case (and num_speculative_ptos, more generally), or the probes sent when pto_count < 0, are
         * the speculative ones, which add potentially redundant retransmissions at a tail to reduce the cost of potential tail
         * losses.
         */
        if (!can_send_stream_data && r->total_bytes_sent < total_bytes_sent && r->conf->num_speculative_ptos > 0 &&
            r->pto_count <= 0) {
fprintf(stderr, "%s:%d\n", __FUNCTION__, __LINE__);
            /* New tail, defined as (i) sender is not in PTO recovery, (ii) there is no stream data to send, and
             * (iii) new application data was sent since the last tail. Move the pto_count back to kick off speculative probing. */
            if (r->pto_count == 0)
                /*  kick off speculative probing if not already in progress */
                r->pto_count = -r->conf->num_speculative_ptos;
            r->total_bytes_sent = total_bytes_sent;
        }
        alarm_duration = quicly_rtt_get_pto(&r->rtt, *r->max_ack_delay, r->conf->min_pto);
        if (r->pto_count < 0 && !can_send_stream_data) {
fprintf(stderr, "%s:%d: alarm_duration=%" PRId64 ", pto_count=%d\n", __FUNCTION__, __LINE__, alarm_duration, r->pto_count);
            /* Speculative probes sent under an RTT do not need to account for ack delay, since there is no expectation
             * of an ack being received before the probe is sent. */
            alarm_duration = quicly_rtt_get_pto(&r->rtt, 0, r->conf->min_pto);
            alarm_duration >>= -r->pto_count;
            if (alarm_duration < r->conf->min_pto)
                alarm_duration = r->conf->min_pto;
        } else if (r->pto_count >= 0)
            alarm_duration <<= r->pto_count;
    }
fprintf(stderr, "%s:%d:alarm_at=%" PRId64 ", alarm_duration=%" PRId64 "\n", __FUNCTION__, __LINE__, r->alarm_at, alarm_duration);
    r->alarm_at = last_retransmittable_sent_at + alarm_duration;
    if (r->alarm_at < now)
        r->alarm_at = now;
}

inline void quicly_loss_on_ack_received(quicly_loss_t *r, uint64_t largest_newly_acked, int64_t now, int64_t sent_at,
                                        uint64_t ack_delay_encoded, int ack_eliciting)
{
    /* Reset PTO count if anything is newly acked, and if sender is not speculatively probing at a tail */
    if (largest_newly_acked != UINT64_MAX && r->pto_count > 0)
        r->pto_count = 0;

    /* If largest newly acked is not larger than before, skip RTT sample */
    if (largest_newly_acked == UINT64_MAX || r->largest_acked_packet_plus1 > largest_newly_acked)
        return;
    r->largest_acked_packet_plus1 = largest_newly_acked + 1;

    /* If ack does not acknowledge any ack-eliciting packet, skip RTT sample */
    if (!ack_eliciting)
        return;

    /* Decode ack delay */
    uint64_t ack_delay_microsecs = ack_delay_encoded << *r->ack_delay_exponent;
    uint32_t ack_delay_millisecs = (uint32_t)((ack_delay_microsecs * 2 + 1000) / 2000);
    /* use min(ack_delay, max_ack_delay) as the ack delay */
    if (ack_delay_millisecs > *r->max_ack_delay)
        ack_delay_millisecs = *r->max_ack_delay;
    quicly_rtt_update(&r->rtt, (uint32_t)(now - sent_at), ack_delay_millisecs);
}

inline int quicly_loss_on_alarm(quicly_loss_t *r, uint64_t largest_sent, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect,
                                size_t *min_packets_to_send, int *restrict_sending)
{
    r->alarm_at = INT64_MAX;
    *min_packets_to_send = 1;
    if (r->loss_time != INT64_MAX) {
        /* Time threshold loss detection. Send at least 1 packet, but no restrictions on sending otherwise. */
        *restrict_sending = 0;
        return quicly_loss_detect_loss(r, largest_acked, do_detect);
    }
    /* PTO. Send at least and at most 1 packet during speculative probing and 2 packets otherwise. */
    ++r->pto_count;
    *restrict_sending = 1;
    if (r->pto_count > 0)
        *min_packets_to_send = 2;

    return 0;
}

inline int quicly_loss_detect_loss(quicly_loss_t *r, uint64_t largest_acked, quicly_loss_do_detect_cb do_detect)
{
    uint32_t delay_until_lost = ((r->rtt.latest > r->rtt.smoothed ? r->rtt.latest : r->rtt.smoothed) * 9 + 7) / 8;
    int64_t loss_time;
    int ret;

    r->loss_time = INT64_MAX;

    if ((ret = do_detect(r, largest_acked, delay_until_lost, &loss_time)) != 0)
        return ret;
    if (loss_time != INT64_MAX)
        r->loss_time = loss_time;

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
