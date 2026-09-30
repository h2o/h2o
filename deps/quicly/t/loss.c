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
#include <math.h>
#include "quicly/loss.h"
#include "quicly/defaults.h"
#include "test.h"

static int64_t now;
static uint64_t num_packets_lost = 0;

static void on_loss_detected(quicly_loss_t *loss, const quicly_sent_packet_t *lost_packet, int is_time_threshold)
{
    ++num_packets_lost;
}

static void acked(quicly_loss_t *loss, uint64_t pn, size_t epoch)
{
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;

    quicly_loss_init_sentmap_iter(loss, &iter, now, quicly_spec_context.transport_params.max_ack_delay, 0);
    while ((sent = quicly_sentmap_get(&iter))->packet_number != pn) {
        assert(sent->packet_number != UINT64_MAX);
        quicly_sentmap_skip(&iter);
    }
    double sent_at = sent->sent_at;
    ok(quicly_sentmap_update(&loss->sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);

    quicly_loss_on_ack_received(loss, pn, UINT64_MAX, pn + 1, epoch, now, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
}

static void test_time_detection(void)
{
    quicly_loss_t loss;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* commit 3 packets (pn=0..2); check that loss timer is not active */
    ok(quicly_sentmap_prepare(&loss.sentmap, 0, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 1, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 2, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    now += 10;

    /* receive ack for the 1st packet; check that loss timer is not active */
    acked(&loss, 0, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    now += 10;

    /* receive ack for the 3rd packet; check that loss timer is active */
    acked(&loss, 2, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 0);

    now = loss.loss_time;
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 1);

    quicly_loss_dispose(&loss);
}

static void test_pn_detection(void)
{
    quicly_loss_t loss;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* commit 4 packets (pn=0..3); check that loss timer is not active */
    ok(quicly_sentmap_prepare(&loss.sentmap, 0, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 1, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 2, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 3, now, QUICLY_EPOCH_INITIAL) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);

    /* receive ack for the 3rd packet; loss timer is activated but no packets are declared as lost */
    acked(&loss, 2, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 0);

    /* receive ack for the 4th packet; loss timer is active and pn=0 is declared lost */
    acked(&loss, 3, QUICLY_EPOCH_INITIAL);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time != INT64_MAX);
    ok(num_packets_lost == 1);

    quicly_loss_dispose(&loss);
}

static void test_slow_cert_verify(void)
{
    quicly_loss_t loss;
    double last_retransmittable_sent_at;
    size_t min_packets_to_send;
    int restrict_sending;

    now = 0;
    num_packets_lost = 0;

    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    ok(loss.loss_time == INT64_MAX);

    /* sent Handshake+1RTT packet */
    ok(quicly_sentmap_prepare(&loss.sentmap, 1, now, QUICLY_EPOCH_HANDSHAKE) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 2, now, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    last_retransmittable_sent_at = now;
    quicly_loss_update_alarm(&loss, now, last_retransmittable_sent_at, 1, 0, 1, 0, 1);

    now += 10;

    /* receive ack for the Handshake packet, but 1RTT packet remains unacknowledged */
    acked(&loss, 1, QUICLY_EPOCH_HANDSHAKE);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 0);

    /* PTO fires */
    now = loss.alarm_at;
    ok(quicly_loss_on_alarm(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, &min_packets_to_send,
                            &restrict_sending, on_loss_detected) == 0);
    ok(restrict_sending);
    ok(min_packets_to_send == 2);
    ok(num_packets_lost == 0);

    /* therefore send probes */
    ok(quicly_sentmap_prepare(&loss.sentmap, 3, now, QUICLY_EPOCH_HANDSHAKE) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    ok(quicly_sentmap_prepare(&loss.sentmap, 4, now, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);

    now += 10;

    /* again receives an ack for the Handshake packet, but 1RTT packet remains unacknowledged */
    acked(&loss, 3, QUICLY_EPOCH_HANDSHAKE);
    ok(quicly_loss_detect_loss(&loss, now, quicly_spec_context.transport_params.max_ack_delay, 0, on_loss_detected) == 0);
    ok(loss.loss_time == INT64_MAX);
    ok(num_packets_lost == 0);

    quicly_loss_dispose(&loss);
}

static void test_late_ack_threshold_adjustment(void)
{
    quicly_loss_t loss;

    now = 0;

    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);

    ok(loss.min_pn_to_relax_reorder_tolerance == 0);
    ok(loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 100, 100, 200, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 200);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 101, 101, 200, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 200);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 250, 199, 300, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 200);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 8);

    quicly_loss_on_ack_received(&loss, 200, 200, 300, QUICLY_EPOCH_1RTT, now, now - 20, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING_LATE_ACK);
    ok(loss.min_pn_to_relax_reorder_tolerance == 300);
    ok(!loss.thresholds.use_packet_based);
    ok(loss.thresholds.time_based_percentile == 1024 / 4);

    quicly_loss_dispose(&loss);
}

static void test_rtt_floor(void)
{
    quicly_rtt_t rtt;

    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, quicly_spec_context.egress[0].loss.default_initial_rtt);
    ok(quicly_rtt_get_floor(&rtt) == quicly_spec_context.egress[0].loss.default_initial_rtt);
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 40);
    ok(quicly_rtt_get_floor(&rtt) == 40);

    quicly_rtt_update(&rtt, 16, 0, 1);
    ok(quicly_rtt_get_floor(&rtt) == 16);
    quicly_rtt_update(&rtt, 16, 0, 5);
    ok(rtt.floor.samples[0] == 16);
    ok(rtt.floor.samples[1] == 16);

    /* A lower sample in the current slot replaces its floor. */
    quicly_rtt_update(&rtt, 15, 0, 6);
    ok(quicly_rtt_get_floor(&rtt) == 15);

    /* Once the low samples age out, the floor rises. */
    quicly_rtt_update(&rtt, 21, 0, 21);
    quicly_rtt_update(&rtt, 21, 0, 25);
    quicly_rtt_update(&rtt, 21, 0, 29);
    quicly_rtt_update(&rtt, 21, 0, 33);
    ok(quicly_rtt_get_floor(&rtt) == 21);

    /* A three-slot jump retains only the previous slot 0, clearing the unsampled slots in between. */
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 40);
    quicly_rtt_update(&rtt, 16, 0, 1);
    quicly_rtt_update(&rtt, 20, 0, 5);
    quicly_rtt_update(&rtt, 24, 0, 9);
    quicly_rtt_update(&rtt, 28, 0, 13);
    ok(quicly_rtt_get_floor(&rtt) == 16);
    quicly_rtt_update(&rtt, 32, 0, 25);
    ok(quicly_rtt_get_floor(&rtt) == 28);

    /* That retained minimum must expire on the next shift, not survive in a skipped slot. */
    quicly_rtt_update(&rtt, 36, 0, 29);
    ok(quicly_rtt_get_floor(&rtt) == 32);

    /* Reinitialization discards the old floor and uses the new initial estimate until the next sample. */
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 80);
    ok(quicly_rtt_get_floor(&rtt) == 80);
    quicly_rtt_update(&rtt, 100, 0, 34);
    ok(quicly_rtt_get_floor(&rtt) == 100);

    /* Floor samples use the same ACK-delay adjustment as latest RTT. */
    quicly_rtt_update(&rtt, 120, 10, 200);
    ok(quicly_rtt_get_floor(&rtt) == 110);

    /* Sub-four-millisecond RTTs use one-millisecond slots rather than dividing by zero. */
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 20);
    quicly_rtt_update(&rtt, 3, 0, 1);
    quicly_rtt_update(&rtt, 3, 0, 2);
    ok(quicly_rtt_get_floor(&rtt) == 3);

    /* Retain fractional floor values, including the fallback before the first sample. */
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 0.75f);
    ok(quicly_rtt_get_floor(&rtt) == 0.75f);
    quicly_rtt_update(&rtt, 0.25f, 0, 1);
    ok(quicly_rtt_get_floor(&rtt) == 0.25f);
    quicly_rtt_update(&rtt, 0.5f, 0, 5);
    ok(quicly_rtt_get_floor(&rtt) == 0.5f);

    /* Accepted RTT samples update the floor as part of loss-core ACK processing. */
    quicly_loss_t loss;
    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    quicly_loss_on_ack_received(&loss, 0, UINT64_MAX, 1, QUICLY_EPOCH_1RTT, 100, 84, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(quicly_rtt_get_floor(&loss.rtt) == 16);
    /* An ACK without an RTT sample must not age or resample the floor. */
    int64_t newest_sample_until = loss.rtt.floor.newest_sample_until;
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, 200, 100, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_NON_ACK_ELICITING);
    ok(loss.rtt.floor.newest_sample_until == newest_sample_until);
    ok(quicly_rtt_get_floor(&loss.rtt) == 16);
    quicly_loss_dispose(&loss);
}

static void test_fractional_rtt(void)
{
    quicly_loss_t loss;
    const double sent_at = 1800000000000.125;
    const uint16_t max_ack_delay = 1;
    const uint8_t ack_delay_exponent = 3;
    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &max_ack_delay, &ack_delay_exponent);

    /* Fractional measurements are retained even with epoch-scale timestamps. */
    quicly_loss_on_ack_received(&loss, 0, UINT64_MAX, 1, QUICLY_EPOCH_1RTT, sent_at + 1.125, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 1.125f && loss.rtt.minimum == 1.125f);
    ok(loss.rtt.smoothed == 1.125f && loss.rtt.variance == 0.5625f);
    ok(quicly_rtt_get_pto(&loss.rtt, 0, 1) == 3.375);

    /* Subtract an encoded 256us ACK delay without rounding it to milliseconds. */
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, sent_at + 1.625, sent_at, 32,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(fabsf(loss.rtt.latest - 1.369f) < 0.000001f);
    ok(loss.rtt.minimum == 1.125f);
    ok(fabsf(loss.rtt.smoothed - 1.1555f) < 0.000001f);
    ok(fabsf(loss.rtt.variance - 0.482875f) < 0.000001f);

    /* The peer's maximum ACK delay is still expressed in milliseconds and caps even a huge encoded delay. */
    quicly_loss_on_ack_received(&loss, 2, UINT64_MAX, 3, QUICLY_EPOCH_1RTT, sent_at + 2.625, sent_at, UINT64_C(0x3fffffffffffffff),
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 1.625f);

    /* Sub-millisecond samples are retained; sub-microsecond and zero-duration samples are clamped to 1us. */
    quicly_loss_on_ack_received(&loss, 3, UINT64_MAX, 4, QUICLY_EPOCH_1RTT, sent_at + 0.25, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 0.25f && loss.rtt.minimum == 0.25f);
    quicly_loss_on_ack_received(&loss, 4, UINT64_MAX, 5, QUICLY_EPOCH_1RTT, sent_at + 0.0005, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 0.001f && loss.rtt.minimum == 0.001f);
    quicly_loss_on_ack_received(&loss, 5, UINT64_MAX, 6, QUICLY_EPOCH_1RTT, sent_at, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 0.001f);
    quicly_loss_dispose(&loss);
}

static void test_rtt_sample_floor(void)
{
    quicly_rtt_t rtt;
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 20);
    quicly_rtt_update(&rtt, 0, 0, 1);
    ok(rtt.latest == 0.001f && rtt.minimum == 0.001f && rtt.smoothed == 0.001f);
    ok(rtt.variance == 0.0005f);

    /* The zero-duration sample is not mistaken for "no sample" on the next update. */
    quicly_rtt_update(&rtt, 0.25f, 0.125f, 2);
    ok(rtt.latest == 0.125f && rtt.minimum == 0.001f);
    ok(fabsf(rtt.smoothed - 0.0165f) < 0.000001f);

    /* Reject an ACK delay that would reduce the adjusted sample below the measured minimum. */
    quicly_rtt_update(&rtt, 0.125f, 0.1245f, 3);
    ok(rtt.latest == 0.125f && rtt.minimum == 0.001f);
    ok(rtt.smoothed >= 0.001f && rtt.variance >= 0);
    ok(quicly_rtt_get_pto(&rtt, 0, 1) == (double)rtt.smoothed + 1);
}

static void test_submillisecond_timers(void)
{
    quicly_loss_t loss;
    const int64_t millisec = INT64_C(1800000000000);
    const double sent_at = millisec + 0.75;
    const uint16_t max_ack_delay = 0;
    const uint8_t ack_delay_exponent = 3;
    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &max_ack_delay, &ack_delay_exponent);
    ok(quicly_sentmap_prepare(&loss.sentmap, 0, sent_at, QUICLY_EPOCH_1RTT) == 0);
    quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);

    /* ACK of a later packet supplies a 125us RTT, while packet 0 remains outstanding. */
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, sent_at + 0.125, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);
    ok(loss.rtt.latest == 0.125f);
    ok(quicly_rtt_get_pto(&loss.rtt, 0, 1) == 1.125);
    quicly_loss_update_alarm(&loss, millisec, sent_at, 1, 1, 0, 0, 1);
    ok(loss.alarm_at == millisec + 2);

    /* The loss delay is still at least 1ms, despite the smaller RTT. */
    num_packets_lost = 0;
    ok(quicly_loss_detect_loss(&loss, millisec + 1, 0, 1, on_loss_detected) == 0);
    ok(num_packets_lost == 0 && loss.loss_time == millisec + 2);
    ok(quicly_loss_detect_loss(&loss, millisec + 2, 0, 1, on_loss_detected) == 0);
    ok(num_packets_lost == 1 && loss.loss_time == INT64_MAX);
    quicly_loss_dispose(&loss);
}

static void test_fractional_pto(void)
{
    quicly_loss_t loss;
    quicly_loss_conf_t conf = quicly_spec_context.egress[0].loss;
    conf.min_pto = 1;
    const uint16_t max_ack_delay = 1;
    const uint8_t ack_delay_exponent = 3;
    const int64_t millisec = INT64_C(1800000000000);
    quicly_loss_init(&loss, &conf, 20, &max_ack_delay, &ack_delay_exponent);
    quicly_rtt_update(&loss.rtt, 1.125f, 0, millisec);

    /* PTO is 3.375ms before ACK delay. Back off without rounding; ceil only after adding the send timestamp. */
    static const struct {
        int pto_count, handshake;
        int64_t delay_at_125us, delay_at_750us;
    } tests[] = {
        {-2, 0, 2, 2},                                              /* speculative PTO is clamped to the 1ms minimum */
        {-1, 0, 2, 3},                                              /* speculative PTO excludes ACK delay */
        {0, 0, 5, 6},  {1, 0, 9, 10}, {2, 0, 18, 19}, {0, 1, 4, 5}, /* handshake PTO excludes ACK delay */
        {1, 1, 7, 8},
    };
    for (size_t i = 0; i != PTLS_ELEMENTSOF(tests); ++i) {
        loss.pto_count = tests[i].pto_count;
        quicly_loss_update_alarm(&loss, millisec, millisec + 0.125, 1, 1, tests[i].handshake, 0, 1);
        ok(loss.alarm_at == millisec + tests[i].delay_at_125us);
        quicly_loss_update_alarm(&loss, millisec, millisec + 0.75, 1, 1, tests[i].handshake, 0, 1);
        ok(loss.alarm_at == millisec + tests[i].delay_at_750us);
    }

    /* An overdue alarm is still clamped to now; no outstanding packets disables it. */
    quicly_loss_update_alarm(&loss, millisec + 100, millisec + 0.75, 1, 1, 0, 0, 0);
    ok(loss.alarm_at == millisec + 100);
    quicly_loss_update_alarm(&loss, millisec + 100, millisec + 0.75, 0, 1, 0, 0, 0);
    ok(loss.alarm_at == INT64_MAX);

    /* The variance floor does not round SRTT down. */
    for (size_t i = 0; i != 16; ++i)
        quicly_rtt_update(&loss.rtt, 1.125f, 0, millisec + 100 + i);
    ok(quicly_rtt_get_pto(&loss.rtt, 0, 1) == 2.125);
    quicly_loss_dispose(&loss);
}

static void test_fractional_loss_deadline(void)
{
    const int64_t millisec = INT64_C(1800000000000);
    const double sent_at = millisec + 0.973;
    const uint16_t max_ack_delay = 0;
    const uint8_t ack_delay_exponent = 3;

    for (int is_1rtt_only = 0; is_1rtt_only != 2; ++is_1rtt_only) {
        quicly_loss_t loss;
        quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &max_ack_delay, &ack_delay_exponent);
        ok(quicly_sentmap_prepare(&loss.sentmap, 0, sent_at, QUICLY_EPOCH_1RTT) == 0);
        quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
        quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, sent_at + 0.913, sent_at, 0,
                                    QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);

        /* At epoch-scale timestamps, sent_at + loss_delay rounds to the +2ms tick, but subtracting loss_delay from that
         * tick rounds below sent_at. Detection must agree with the scheduled deadline despite that rounding difference. */
        num_packets_lost = 0;
        ok(quicly_loss_detect_loss(&loss, millisec + 1, 0, is_1rtt_only, on_loss_detected) == 0);
        ok(num_packets_lost == 0 && loss.loss_time == millisec + 2);
        ok(quicly_loss_detect_loss(&loss, millisec + 2, 0, is_1rtt_only, on_loss_detected) == 0);
        ok(num_packets_lost == 1 && loss.loss_time == INT64_MAX);
        quicly_loss_dispose(&loss);
    }
}

static void test_fractional_sentmap_timers(void)
{
    quicly_loss_t loss;
    const int64_t millisec = INT64_C(1800000000000);
    const double sent_at = millisec + 0.125;
    quicly_loss_init(&loss, &quicly_spec_context.egress[0].loss, 20, &quicly_spec_context.transport_params.max_ack_delay,
                     &quicly_spec_context.transport_params.ack_delay_exponent);
    for (uint64_t pn = 0; pn != 2; ++pn) {
        ok(quicly_sentmap_prepare(&loss.sentmap, pn, sent_at, QUICLY_EPOCH_1RTT) == 0);
        quicly_sentmap_commit(&loss.sentmap, 10, 0, 0);
    }
    quicly_sentmap_iter_t iter;
    quicly_sentmap_init_iter(&loss.sentmap, &iter);
    quicly_sentmap_skip(&iter);
    ok(quicly_sentmap_update(&loss.sentmap, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
    quicly_loss_on_ack_received(&loss, 1, UINT64_MAX, 2, QUICLY_EPOCH_1RTT, sent_at + 1.125, sent_at, 0,
                                QUICLY_LOSS_ACK_RECEIVED_KIND_ACK_ELICITING);

    num_packets_lost = 0;
    /* A 1.125ms RTT gives a 1.265625ms loss delay. Round the +1.390625ms deadline, not the duration, to the +2ms tick. */
    ok(quicly_loss_detect_loss(&loss, millisec + 1, 0, 1, on_loss_detected) == 0);
    ok(num_packets_lost == 0 && loss.loss_time == millisec + 2);
    ok(quicly_loss_detect_loss(&loss, millisec + 2, 0, 1, on_loss_detected) == 0);
    ok(num_packets_lost == 1 && loss.loss_time == INT64_MAX);

    /* Four PTOs are 13.5ms; sent at +0.125ms, the packet expires on the +14ms tick. */
    ok(quicly_loss_get_sentmap_expiration_time(&loss, 0) == 13.5);
    int64_t expires_at = millisec + 14;
    ok(quicly_loss_init_sentmap_iter(&loss, &iter, expires_at - 1, 0, 1) == 0);
    ok(quicly_sentmap_get(&iter)->packet_number == 0);
    ok(quicly_loss_init_sentmap_iter(&loss, &iter, expires_at, 0, 1) == 0);
    ok(quicly_sentmap_get(&iter)->packet_number == UINT64_MAX);
    /* Even the largest finite timer value must not retire the end-of-iteration sentinel. */
    ok(quicly_loss_init_sentmap_iter(&loss, &iter, INT64_MAX, 0, 1) == 0);
    ok(quicly_sentmap_get(&iter)->packet_number == UINT64_MAX);
    quicly_loss_dispose(&loss);
}

void test_loss(void)
{
    subtest("fractional-rtt", test_fractional_rtt);
    subtest("rtt-sample-floor", test_rtt_sample_floor);
    subtest("submillisecond-timers", test_submillisecond_timers);
    subtest("fractional-pto", test_fractional_pto);
    subtest("fractional-loss-deadline", test_fractional_loss_deadline);
    subtest("fractional-sentmap-timers", test_fractional_sentmap_timers);
    subtest("time-detection", test_time_detection);
    subtest("pn-detection", test_pn_detection);
    subtest("slow-cert-verify", test_slow_cert_verify);
    subtest("late-ack-threshold-adjustment", test_late_ack_threshold_adjustment);
    subtest("rtt-floor", test_rtt_floor);
}
