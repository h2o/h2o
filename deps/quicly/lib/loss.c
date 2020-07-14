/*
 * Copyright (c) 2017-2020 Fastly, Kazuho Oku
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
#include "quicly/loss.h"

void quicly_loss_init_sentmap_iter(quicly_loss_t *loss, quicly_sentmap_iter_t *iter, int64_t now, uint32_t max_ack_delay,
                                   int is_closing)
{
    quicly_sentmap_init_iter(&loss->sentmap, iter);

    int64_t retire_before = now - quicly_loss_get_sentmap_expiration_time(loss, max_ack_delay);

    /* Retire entries older than the time specified, unless the connection is alive and the number of packets in the sentmap is
     * below 32 packets. This exception (the threshold of 32) exists to be capable of recognizing excessively late-ACKs when under
     * heavy loss; in such case, 32 is more than enough, yet small enough that the memory footprint does not matter. */
    const quicly_sent_packet_t *sent;
    while ((sent = quicly_sentmap_get(iter))->sent_at <= retire_before && sent->cc_bytes_in_flight == 0) {
        if (!is_closing && loss->sentmap.num_packets < 32)
            break;
        quicly_sentmap_update(&loss->sentmap, iter, QUICLY_SENTMAP_EVENT_EXPIRED);
    }
}

int quicly_loss_detect_loss(quicly_loss_t *loss, int64_t now, uint32_t max_ack_delay, int is_1rtt_only,
                            quicly_loss_on_detect_cb on_loss_detected)
{
    /* This function ensures that the value returned in loss_time is when the next application timer should be set for loss
     * detection. if no timer is required, loss_time is set to INT64_MAX. */

    const uint32_t delay_until_lost = ((loss->rtt.latest > loss->rtt.smoothed ? loss->rtt.latest : loss->rtt.smoothed) * 9 + 7) / 8;
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;
    int ret;

    loss->loss_time = INT64_MAX;

    quicly_loss_init_sentmap_iter(loss, &iter, now, max_ack_delay, 0);

    /* Mark packets as lost if they are smaller than the largest_acked and outside either time-threshold or packet-threshold
     * windows. Once marked as lost, cc_bytes_in_flight becomes zero. */
    while ((sent = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX) {
        int64_t largest_acked_signed = loss->largest_acked_packet_plus1[sent->ack_epoch] - 1;
        if ((int64_t)sent->packet_number < largest_acked_signed &&
            (sent->sent_at <= now - delay_until_lost ||                                      /* time threshold */
             (int64_t)sent->packet_number <= largest_acked_signed - QUICLY_LOSS_DEFAULT_PACKET_THRESHOLD)) { /* packet threshold */
            if (sent->cc_bytes_in_flight != 0) {
                on_loss_detected(loss, sent, (int64_t)sent->packet_number > largest_acked_signed - QUICLY_LOSS_DEFAULT_PACKET_THRESHOLD);
                if ((ret = quicly_sentmap_update(&loss->sentmap, &iter, QUICLY_SENTMAP_EVENT_LOST)) != 0)
                    return ret;
            } else {
                quicly_sentmap_skip(&iter);
            }
        } else {
            /* When only one PN space is active, it is possible to stop looking for packets that have to be considered lost and
             * continue on to calculating the loss time. Otherwise, iterate through the entire sentmap. */
            if (is_1rtt_only)
                break;
            quicly_sentmap_skip(&iter);
        }
    }

    if (!is_1rtt_only) {
        quicly_loss_init_sentmap_iter(loss, &iter, now, max_ack_delay, 0);
        sent = quicly_sentmap_get(&iter);
    }

    /* schedule time-threshold alarm if there is a packet outstanding that is smaller than largest_acked */
    while (sent->sent_at != INT64_MAX && sent->packet_number + 1 < loss->largest_acked_packet_plus1[sent->ack_epoch]) {
        if (sent->cc_bytes_in_flight != 0) {
            assert(now < sent->sent_at + delay_until_lost);
            loss->loss_time = sent->sent_at + delay_until_lost;
            break;
        }
        quicly_sentmap_skip(&iter);
        sent = quicly_sentmap_get(&iter);
    }

    return 0;
}
