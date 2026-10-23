/*
 * Copyright (c) 2017-2024 Fastly, Kazuho Oku
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
#include "quicly.h"
#include "../lib/cc-pico.c"
#include "test.h"

static void test_pico_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);
    uint32_t bytes_per_mtu_increase = cc.state.pico.bytes_per_mtu_increase;

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.recovery_end == 20);
    ok(cc.num_loss_episodes == 1);
    ok(cc.state.pico.undo.num_packets_lost == 1);
    ok(cc.cwnd < initcwnd);
    ok(cc.ssthresh == cc.cwnd);
    ok(cc.cwnd_exiting_slow_start == initcwnd);
    ok(cc.exit_slow_start_at == 1000);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.recovery_end == 0);
    ok(cc.num_loss_episodes == 0);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
    ok(cc.state.pico.undo.num_packets_lost == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.state.pico.bytes_per_mtu_increase == bytes_per_mtu_increase);
    ok(cc.cwnd_exiting_slow_start == 0);
    ok(cc.exit_slow_start_at == INT64_MAX);
}

static void test_pico_undo_multiple_losses(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    uint32_t reduced_cwnd = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 11, 20, 1001, mtu);
    ok(cc.state.pico.undo.num_packets_lost == 2);

    cc.type->cc_on_late_ack(&cc, 9, 1099);
    ok(cc.state.pico.undo.num_packets_lost == 2);
    ok(cc.recovery_end == 20);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.state.pico.undo.num_packets_lost == 1);
    ok(cc.recovery_end == 20);
    ok(cc.cwnd == reduced_cwnd);
    ok(cc.num_loss_episodes == 1);

    cc.type->cc_on_late_ack(&cc, 11, 1101);
    ok(cc.state.pico.undo.num_packets_lost == 0);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.num_loss_episodes == 0);
    ok(cc.num_loss_episodes_undone == 1);
    ok(cc.num_loss_episodes_undone_in_startup == 1);
}

static void test_pico_undo_rapid_start_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);
    cc.type->enable_rapid_start(&cc, 900);
    ok(quicly_cc_rapid_start_is_enabled(&cc.rapid_start));

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.rapid_start.newest_rtt_sample_until == -1);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.rapid_start.newest_rtt_sample_until == 0);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);

    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1200, mtu);
    ok(cc.cwnd == initcwnd / 2);
    ok(cc.ssthresh == cc.cwnd);
}

static void test_pico_undo_jumpstart_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu, jumpcwnd = 24 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);
    cc.type->cc_jumpstart(&cc, jumpcwnd, 10);
    ok(quicly_cc_in_jumpstart(&cc));
    ok(cc.cwnd == jumpcwnd);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.undo.cwnd == jumpcwnd / 2);
    ok(cc.cwnd < jumpcwnd);
    ok(!quicly_cc_in_jumpstart(&cc));

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.recovery_end == 0);
    ok(cc.cwnd == jumpcwnd / 2);
    ok(cc.ssthresh == UINT32_MAX);

    cc.type->cc_on_acked(&cc, &loss, mtu, 11, 18 * mtu, 1, 20, 1200, mtu);
    ok(cc.cwnd != 18 * mtu);
    ok(cc.cwnd_exiting_jumpstart == 0);
    ok(!quicly_cc_in_jumpstart(&cc));
}

/**
 * Compares CWND against a value calculated using floating point arithmetic, tolerating an off-by-one; the compiler is allowed to
 * evaluate the same expression differently between translation units (e.g., by contracting a multiply-add into an FMA).
 */
static int cwnd_is(uint32_t actual, double expected)
{
    uint32_t truncated = (uint32_t)expected;
    return actual == truncated || actual == truncated + 1 || actual + 1 == truncated;
}

static void test_fast_cbrt(void)
{
    static const struct {
        double input;
        double expected;
    } cases[] = {
        {0, 0}, {1, 1}, {1.5, 1.1447142425533319}, {-1, -1}, {1048576, 101.59366732596477}, {-1572864, -116.29571794125694},
    };

    for (size_t i = 0; i != PTLS_ELEMENTSOF(cases); ++i) {
        double actual = fast_cbrt(cases[i].input);
        if (cases[i].expected == 0)
            ok(actual == 0);
        else
            ok(fabs((actual - cases[i].expected) / cases[i].expected) < 4e-5);
    }
}

static void test_pico_ecn(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);

    /* exit slow start by observing a packet loss */
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.cwnd == initcwnd / 2);
    ok(cc.num_ecn_loss_episodes == 0);
    uint32_t cwnd_in_ca = cc.cwnd;

    /* a CE mark (i.e., zero-byte congestion report) reduces CWND by QUICLY_BETA_ECN rather than by QUICLY_BETA_LOSS */
    cc.type->cc_on_lost(&cc, &loss, 0, 20, 30, 1100, mtu);
    ok(cc.num_loss_episodes == 2);
    ok(cc.num_ecn_loss_episodes == 1);
    ok(cwnd_is(cc.cwnd, cwnd_in_ca * QUICLY_BETA_ECN));
    ok(cc.ssthresh == cc.cwnd);
    ok(cc.state.pico.undo.num_packets_lost == 0); /* CE marks cannot be undone by late ACKs */
    /* the increase rate follows the factor being used; here, Reno's 1 MTU per RTT, i.e. per post-reduction CWND bytes acked */
    ok(cc.state.pico.bytes_per_mtu_increase == cc.cwnd);

    /* a packet loss reduces CWND by QUICLY_BETA_LOSS */
    uint32_t cwnd_before_loss = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 1200, mtu);
    ok(cc.num_ecn_loss_episodes == 1);
    ok(cwnd_is(cc.cwnd, cwnd_before_loss * QUICLY_BETA_LOSS));
}

static void test_pico_ecn_rapid_start(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);
    cc.type->enable_rapid_start(&cc, 900);

    /* upon a CE mark, the silence factor derived from QUICLY_BETA_ECN (i.e., 0.95x) is applied */
    cc.type->cc_on_lost(&cc, &loss, 0, 10, 20, 1000, mtu);
    ok(cc.rapid_start.newest_rtt_sample_until == -1);
    ok(cc.rapid_start.recovery.by_ecn);
    ok(cwnd_is(cc.cwnd, initcwnd * QUICLY_RAPID_START_LOSS_FACTOR(QUICLY_BETA_ECN)));
    uint32_t cwnd_entering_recovery = cc.cwnd;

    /* during the recovery period, CWND is reduced by ack_factor (0.1x) per byte newly acked */
    cc.type->cc_on_acked(&cc, &loss, 4 * mtu, 15, 8 * mtu, 1, 20, 1100, mtu);
    ok(cwnd_is(cc.cwnd, cwnd_entering_recovery - QUICLY_RAPID_START_ACK_FACTOR(QUICLY_BETA_ECN) * (4 * mtu)));
    uint32_t cwnd_after_ack = cc.cwnd;

    /* a packet loss detected within the same recovery period is accounted using loss_factor (0.95x), the factor being retained
     * from when the recovery period was entered, even though the episode is no longer counted as an ECN-only one */
    cc.type->cc_on_lost(&cc, &loss, mtu, 16, 20, 1100, mtu);
    ok(cc.num_loss_episodes == 1);
    ok(cc.num_ecn_loss_episodes == 0);
    ok(cwnd_is(cc.cwnd, cwnd_after_ack - QUICLY_RAPID_START_LOSS_FACTOR(QUICLY_BETA_ECN) * mtu));
}

static void test_cubic_fast_convergence(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.cwnd_prior == 50 * mtu);
    ok(cc.state.pico.cubic.w_est == 0);

    cc.cwnd = 45 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1100, mtu);
    ok(cc.state.pico.cubic.fast_convergence);
    ok((cc.state.pico.cubic.cwnd_prior + cc.ssthresh) / 2 == 45 * mtu * 85 / 100);
    ok(cc.state.pico.cubic.w_est == 0);

    /* The effective W_max is 38.25 MTUs, so a 40-MTU congestion window does not trigger fast convergence again. */
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 1200, mtu);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.cwnd_prior == 40 * mtu);
    ok(cc.state.pico.cubic.w_est == 0);
}

static void test_cubic_target_bounds(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.epoch_start = 1;

    cc.type->cc_on_acked(&cc, &loss, 2 * mtu, 1, cc.cwnd, 1, 2, 1000000, mtu);
    ok(cc.cwnd == initcwnd + mtu);

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.ssthresh = cc.cwnd / 2;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd / 2;
    cc.state.pico.cubic.w_est = cc.state.pico.cubic.cwnd_prior - 1;
    cc.state.pico.cubic.epoch_start = 1;
    cc.state.pico.cubic.k = 0;
    cc.type->cc_on_acked(&cc, &loss, 1, 1, cc.cwnd, 0, 2, 1, mtu);
    ok(cc.cwnd == initcwnd);
}

static void test_cubic_w_est(void)
{
    uint32_t mtu = 1200;
    struct st_quicly_cc_cubic_t state = {.w_est = 10 * mtu, .cwnd_prior = 10 * mtu};

    /* At 10 MTUs, the exposed estimate stays unchanged until 10 MTUs have been acknowledged, then grows by exactly one MTU. */
    ok(cubic_update_w_est(&state, 10 * mtu, 10 * mtu, 10 * mtu - 1, mtu, mtu) == 10 * mtu);
    ok(10 * mtu < state.w_est && state.w_est < 11 * mtu);
    ok(cubic_update_w_est(&state, 10 * mtu, 10 * mtu, 1, mtu, mtu) == 11 * mtu);
    ok(state.w_est == 11 * mtu);

    /* The next increase requires the new 11-MTU window to be acknowledged. */
    ok(cubic_update_w_est(&state, 11 * mtu, 10 * mtu, 11 * mtu, mtu, mtu) == 12 * mtu);
    ok(state.w_est == 12 * mtu);

    /* With normalization, one window of ACKs advances the estimate by the reference MTU, while the exposed window remains
     * quantized in actual-MTU steps. */
    state = (struct st_quicly_cc_cubic_t){.w_est = 10 * mtu, .cwnd_prior = 10 * mtu};
    ok(cubic_update_w_est(&state, 10 * mtu, 10 * mtu, 10 * mtu, mtu, QUICLY_CC_REFERENCE_MTU) == 11 * mtu);
    ok(state.w_est == 10 * mtu + QUICLY_CC_REFERENCE_MTU);
}

static void test_cubic_mtu_normalization(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 0, .smoothed = 0, .minimum = 0, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    /* In the cubic region, normalization substitutes the reference MTU in W_cubic. */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 1, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.epoch_start = 1000;
    cc.state.pico.cubic.k = 0;
    cc.type->cc_on_acked(&cc, &loss, initcwnd, 1, initcwnd, 0, 2, 2000, mtu);
    ok(cwnd_is(cc.cwnd, initcwnd + QUICLY_CUBIC_C * QUICLY_CC_REFERENCE_MTU));

    /* In the Reno-friendly region, growth uses the reference MTU but CWND is still exposed in actual-MTU steps. Five windows of
     * ACKs therefore accumulate six 1200-byte steps (floor(5 * 1462 / 1200)). */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 1, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.epoch_start = 1000;
    cc.state.pico.cubic.k = 100;
    for (size_t i = 0; i != 5; ++i) {
        uint32_t cwnd = cc.cwnd;
        cc.type->cc_on_acked(&cc, &loss, cwnd, i + 1, cwnd, 1, i + 2, 1000, mtu);
    }
    ok(cc.cwnd == initcwnd + 6 * mtu);
}

static void test_cubic_cc_limited(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = 50 * mtu;
    cc.state.pico.cubic.epoch_start = 1000;
    cc.state.pico.cubic.k = -5;
    cc.state.pico.cubic.w_est = cc.cwnd;

    /* Entering the app-limited state stops the wall clock without resetting the ACK-clocked Reno estimate. An ACK from the
     * preceding CC-limited region advances W_est, but neither restarts the epoch nor grows CWND. */
    ok(!isnan(cc.state.pico.cubic.k));
    cc.type->cc_update_cc_limited(&cc, 0, 2000);
    ok(!cc.state.pico.cubic.cc_limited);
    ok(isnan(cc.state.pico.cubic.k));
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(cc.state.pico.cubic.w_est == initcwnd);
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 2100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(cc.state.pico.cubic.w_est > initcwnd);

    /* Resumption starts the wall clock. An ACK that is not locally CC-limited advances W_cubic but not W_est. */
    double w_est_before = cc.state.pico.cubic.w_est;
    cc.type->cc_update_cc_limited(&cc, 1, 3000);
    ok(cc.state.pico.cubic.cc_limited);
    cc.type->cc_on_acked(&cc, &loss, mtu, 2, mtu, 0, 3, 3100, mtu);
    ok(cc.cwnd > initcwnd);
    ok(cc.state.pico.cubic.epoch_start == 3000);
    ok(!isnan(cc.state.pico.cubic.k));
    ok(cc.state.pico.cubic.w_est == w_est_before);
    ok(cc.state.pico.cubic.k < 0);
    double tk = -cc.state.pico.cubic.k;
    ok(cwnd_is(0.4 * tk * tk * tk * mtu + cc.state.pico.cubic.cwnd_prior, initcwnd));

    /* The next locally CC-limited ACK advances both clocks. */
    uint32_t cwnd_before = cc.cwnd;
    w_est_before = cc.state.pico.cubic.w_est;
    cc.type->cc_on_acked(&cc, &loss, mtu, 3, mtu, 1, 4, 3100, mtu);
    ok(cc.cwnd > cwnd_before);
    ok(cc.state.pico.cubic.w_est > w_est_before);
}

static void test_cubic_recovery_epoch(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    /* RFC 9438 starts the epoch when congestion avoidance begins, not when congestion is detected. */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 0);
    cc.type->cc_on_acked(&cc, &loss, 0, 19, 0, 1, 20, 1100, mtu);
    ok(cc.state.pico.cubic.epoch_start == 0);
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1200, mtu);
    ok(cc.state.pico.cubic.w_est == cc.cwnd);
    ok(cc.state.pico.cubic.epoch_start == 1200);

    /* If recovery exits while app-limited, initialize W_est but defer the wall-clock epoch until sending resumes. */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    cc.type->cc_update_cc_limited(&cc, 0, 1050);
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 0, 21, 1200, mtu);
    ok(cc.state.pico.cubic.w_est == cc.cwnd);
    ok(cc.state.pico.cubic.epoch_start == 0);
    cc.type->cc_update_cc_limited(&cc, 1, 1300);
    ok(cc.state.pico.cubic.epoch_start == 1300);
}

static void test_cubic_rapid_start_epoch(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.type->enable_rapid_start(&cc, 900);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.cwnd_prior != 0);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(isnan(cc.state.pico.cubic.k));

    cc.type->cc_on_acked(&cc, &loss, 4 * mtu, 15, 8 * mtu, 1, 20, 1100, mtu);
    uint32_t cwnd_prior_during_recovery = cc.state.pico.cubic.cwnd_prior;
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(isnan(cc.state.pico.cubic.k));

    /* Further reduction during recovery does not initialize or restart the epoch. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 16, 20, 1150, mtu);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(isnan(cc.state.pico.cubic.k));
    uint32_t cwnd_epoch = cc.cwnd;

    /* The first ACK beyond recovery initializes the increase function and starts the epoch from Rapid Start's progressively
     * reduced CWND, using twice the BDP estimate as W_max. */
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1200, mtu);
    ok(cc.state.pico.cubic.cwnd_prior == (uint32_t)(2. * cwnd_epoch / QUICLY_BETA_LOSS));
    ok(cc.state.pico.cubic.cwnd_prior != cwnd_prior_during_recovery);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.w_est == cwnd_epoch);
    ok(cc.state.pico.cubic.epoch_start == 1200);
    ok(!isnan(cc.state.pico.cubic.k));
    ok(!quicly_cc_rapid_start_is_enabled(&cc.rapid_start));

    /* Losses from the completed recovery no longer revise CWND or the initialized Cubic epoch. */
    uint32_t cwnd_after_recovery = cc.cwnd, ssthresh_after_recovery = cc.ssthresh;
    struct st_quicly_cc_cubic_t cubic_after_recovery = cc.state.pico.cubic;
    cc.type->cc_on_lost(&cc, &loss, mtu, 19, 21, 1250, mtu);
    ok(cc.cwnd == cwnd_after_recovery);
    ok(cc.ssthresh == ssthresh_after_recovery);
    ok(memcmp(&cc.state.pico.cubic, &cubic_after_recovery, sizeof(cubic_after_recovery)) == 0);
}

static void test_cubic_abe(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);

    /* Establish a 50-MTU W_max when leaving ordinary slow start. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.cwnd_prior == 50 * mtu);

    /* An ECN event below W_max reduces by 0.85 and applies FC using (1 + 0.85) / 2, i.e. 0.925. */
    cc.cwnd = 45 * mtu;
    cc.type->cc_on_lost(&cc, &loss, 0, 20, 30, 1100, mtu);
    ok(cc.state.pico.cubic.by_ecn);
    ok(cc.cwnd == (uint32_t)(45 * mtu * QUICLY_BETA_ECN));
    ok(cc.state.pico.cubic.fast_convergence);
    ok((cc.state.pico.cubic.cwnd_prior + cc.ssthresh) / 2 == (uint32_t)(45 * mtu * (1 + QUICLY_BETA_ECN) / 2));
    ok(isnan(cc.state.pico.cubic.k));

    /* The ECN epoch uses alpha_ecn ~= 0.729. */
    uint32_t cwnd_epoch = cc.cwnd;
    double expected_w_est =
        cwnd_epoch + (1 + 0.8) * (1 - QUICLY_BETA_ECN) / ((1 - 0.8) * (1 + QUICLY_BETA_ECN)) * mtu / cwnd_epoch * mtu;
    cc.type->cc_on_acked(&cc, &loss, mtu, 30, mtu, 1, 31, 1200, mtu);
    ok(cc.state.pico.cubic.k > 0);
    ok((uint32_t)cc.state.pico.cubic.w_est == (uint32_t)expected_w_est);
}

static void test_cubic_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.cwnd_prior != 0);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.cwnd == initcwnd);
    ok(cc.ssthresh == UINT32_MAX);
    ok(cc.recovery_end == 0);
    ok(cc.state.pico.cubic.cwnd_prior == 0);
    ok(cc.num_loss_episodes_undone == 1);
}

static void test_cubic_legacy_name(void)
{
    quicly_cc_t cc;

    quicly_cc_cubic_legacy_init.cb(&quicly_cc_cubic_legacy_init, &cc, 12000, 0, 0);
    ok(cc.type == &quicly_cc_type_cubic_legacy);
    ok(strcmp(cc.type->name, "cubic-legacy") == 0);
}

static void test_pico_ack_countdown(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_acked(&cc, &loss, mtu - 1, 1, mtu - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);

    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd + mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == mtu);

    /* The interval switches to Pico's congestion-avoidance rate when an increase reaches ssthresh. */
    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, initcwnd, 0, 0);
    cc.ssthresh = initcwnd + mtu;
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 100, mtu);
    ok(cc.cwnd == cc.ssthresh);
    ok(cc.state.pico.bytes_to_mtu_increase == initcwnd * QUICLY_BETA_LOSS);
}

static void test_pico_switch_resets_ack_credit(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 0, 0);
    cc.ssthresh = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, initcwnd - 1, 1, initcwnd - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);

    ok(quicly_cc_type_pico.cc_switch(&cc));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == initcwnd * QUICLY_BETA_LOSS - 1);

    ok(quicly_cc_type_reno.cc_switch(&cc));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
}

static void test_reno(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    /* Reno grows by one MTU for each current-CWND bytes acknowledged. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 0, 0);
    cc.ssthresh = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, initcwnd - 1, 1, initcwnd - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd + mtu);

    /* Packet-size normalization shortens the ACK deficit so that actual-MTU CWND steps amortize to the reference MTU per RTT. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 1, 0);
    cc.ssthresh = cc.cwnd;
    uint32_t normalized_deficit = (uint64_t)initcwnd * mtu / QUICLY_CC_REFERENCE_MTU;
    cc.type->cc_on_acked(&cc, &loss, normalized_deficit - 1, 1, normalized_deficit - 1, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu);
    ok(cc.cwnd == initcwnd + mtu);

    /* Normalization does not alter slow start. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 1, 0);
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 100, mtu);
    ok(cc.cwnd == initcwnd + mtu);

    /* Startup uses the shared 0.5 reduction; subsequent loss uses the policy beta. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.cwnd == initcwnd / 2);
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1100, mtu);
    ok(cwnd_is(cc.cwnd, 40 * mtu * QUICLY_BETA_RENO));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    cc.type->cc_on_acked(&cc, &loss, mtu, 30, mtu, 1, 31, 1200, mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == cc.cwnd - mtu);

    /* Reno uses the same beta for ECN and packet loss. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, 0, 20, 30, 1100, mtu);
    ok(cwnd_is(cc.cwnd, 40 * mtu * QUICLY_BETA_RENO));
}

static void test_cuback_reno_bytes_per_mtu_increase(void)
{
    uint32_t mtu = 1200, cwnd_epoch = 7 * mtu, w_max = 10 * mtu;
    struct st_quicly_cc_cuback_t state = {.cwnd_prior = w_max};

    /* Reno curve, before Wmax: each MTU increase consumes the current CWND divided by the friendly alpha. */
    state.bandwidth = 1e12;
    ok(cwnd_is(cuback_bytes_per_mtu_increase(&state, cwnd_epoch, cwnd_epoch, mtu, mtu),
               (double)cwnd_epoch / cubic_friendly_alpha[0]));
    ok(cwnd_is(cuback_bytes_per_mtu_increase(&state, cwnd_epoch + mtu, cwnd_epoch, mtu, mtu),
               (double)(cwnd_epoch + mtu) / cubic_friendly_alpha[0]));

    /* Reno curve, at and above Wmax: alpha is one, so each increase consumes the current CWND. */
    ok(cuback_bytes_per_mtu_increase(&state, w_max, cwnd_epoch, mtu, mtu) == w_max);
    ok(cuback_bytes_per_mtu_increase(&state, w_max + mtu, cwnd_epoch, mtu, mtu) == w_max + mtu);

    /* Normalization scales the ACK thresholds by actual_MTU / reference_MTU without changing the actual-MTU CWND step. */
    ok(cwnd_is(cuback_bytes_per_mtu_increase(&state, cwnd_epoch, cwnd_epoch, mtu, QUICLY_CC_REFERENCE_MTU),
               (double)cwnd_epoch / cubic_friendly_alpha[0] * mtu / QUICLY_CC_REFERENCE_MTU));
    ok(cwnd_is(cuback_bytes_per_mtu_increase(&state, w_max, cwnd_epoch, mtu, QUICLY_CC_REFERENCE_MTU),
               (double)w_max * mtu / QUICLY_CC_REFERENCE_MTU));
}

static void check_cuback_cubic_bytes_per_mtu_increase(uint32_t cwnd_epoch, uint32_t w_max, uint32_t actual_mtu,
                                                      uint32_t reference_mtu)
{
    /* A two-second RTT makes the Cubic curve cheaper than the Reno curve throughout the points being tested. */
    struct st_quicly_cc_cuback_t state = {.cwnd_prior = w_max, .bandwidth = w_max / 2.};
    double k = cbrt((double)(w_max - cwnd_epoch) / (QUICLY_CUBIC_C * reference_mtu));

    /* By point symmetry, the continuous Cubic curve is one eighth of the epoch-to-Wmax gap below Wmax at K / 2, and the same
     * distance above Wmax at 3 * K / 2. Cuback exposes only whole-MTU windows, so record the times bracketing those points. */
    double gap = w_max - cwnd_epoch;
    double w_half_k = w_max - gap / 8, w_three_halves_k = w_max + gap / 8;
    uint32_t before_half_k = (uint32_t)(w_half_k / actual_mtu) * actual_mtu, after_half_k = before_half_k + actual_mtu;
    uint32_t before_three_halves_k = (uint32_t)(w_three_halves_k / actual_mtu) * actual_mtu;
    uint32_t after_three_halves_k = before_three_halves_k + actual_mtu;
    uint64_t bytes = 0, bytes_before_half_k = 0, bytes_after_half_k = 0, bytes_at_w_max = 0, bytes_before_three_halves_k = 0,
             bytes_after_three_halves_k = 0;

    for (uint32_t cwnd = cwnd_epoch;; cwnd += actual_mtu) {
        if (cwnd == before_half_k)
            bytes_before_half_k = bytes;
        if (cwnd == after_half_k)
            bytes_after_half_k = bytes;
        if (cwnd == w_max)
            bytes_at_w_max = bytes;
        if (cwnd == before_three_halves_k)
            bytes_before_three_halves_k = bytes;
        if (cwnd == after_three_halves_k) {
            bytes_after_three_halves_k = bytes;
            break;
        }
        bytes += cuback_bytes_per_mtu_increase(&state, cwnd, cwnd_epoch, actual_mtu, reference_mtu);
    }

    ok(bytes_before_half_k / state.bandwidth < k / 2);
    ok(bytes_after_half_k / state.bandwidth > k / 2);
    ok(fabs(bytes_at_w_max / state.bandwidth - k) / k < 1e-3);
    ok(bytes_before_three_halves_k / state.bandwidth < 3 * k / 2);
    ok(bytes_after_three_halves_k / state.bandwidth > 3 * k / 2);
}

static void test_cuback_cubic_bytes_per_mtu_increase(void)
{
    static const struct {
        uint32_t cwnd_epoch_in_mtu;
        uint32_t w_max_in_mtu;
    } cases[] = {{7, 10}, {700, 1000}};
    uint32_t mtu = 1200;

    for (size_t i = 0; i != PTLS_ELEMENTSOF(cases); ++i) {
        uint32_t cwnd_epoch = cases[i].cwnd_epoch_in_mtu * mtu, w_max = cases[i].w_max_in_mtu * mtu;
        check_cuback_cubic_bytes_per_mtu_increase(cwnd_epoch, w_max, mtu, mtu);
        check_cuback_cubic_bytes_per_mtu_increase(cwnd_epoch, w_max, mtu, QUICLY_CC_REFERENCE_MTU);
    }
}

static void test_cuback_ack_countdown(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, w_max = 2 * mtu;

    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, w_max, 0, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cuback.cwnd_prior = w_max;
    cc.state.pico.cuback.bandwidth = w_max * 1000. / loss.rtt.smoothed;
    cc.state.pico.bytes_to_mtu_increase = 0;

    /* Above W_max, alpha is one, so moving from 2 to 3 MTUs requires 2 MTUs newly acknowledged after recovery. */
    cc.type->cc_on_acked(&cc, &loss, 1, 1, 1, 1, 2, 100, mtu);
    ok(cc.cwnd == w_max);
    ok(cc.state.pico.bytes_to_mtu_increase == 2 * mtu - 1);
    cc.type->cc_on_acked(&cc, &loss, 2 * mtu - 2, 2, 2 * mtu - 2, 1, 3, 100, mtu);
    ok(cc.cwnd == w_max);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 3, 1, 1, 4, 100, mtu);
    ok(cc.cwnd == w_max + mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == 3 * mtu);

    /* The policy-level option selects the normalized ACK threshold while retaining actual-MTU CWND steps. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, w_max, 1, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cuback.cwnd_prior = w_max;
    cc.state.pico.cuback.bandwidth = w_max * 1000. / loss.rtt.smoothed;
    cc.type->cc_on_acked(&cc, &loss, 1, 1, 1, 1, 2, 100, mtu);
    uint32_t normalized_deficit = (uint64_t)w_max * mtu / QUICLY_CC_REFERENCE_MTU;
    ok(cc.cwnd == w_max);
    ok(cc.state.pico.bytes_to_mtu_increase == normalized_deficit - 1);
}

static void test_cuback_deferred_bdp_estimate(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    /* An ordinary first loss retains the estimated BDP as W_max, matching HEAD's special 0.5 startup reduction. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, initcwnd, 0, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cuback.cwnd_prior == initcwnd / 2);

    /* Rapid Start continues adjusting CWND throughout recovery, so W_max is derived from the final CWND afterward, using twice
     * the BDP estimate. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, initcwnd, 0, 0);
    cc.type->enable_rapid_start(&cc, 900);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cuback.bandwidth > 0);
    ok(cc.state.pico.cuback.cwnd_prior == 0);
    ok(cc.state.pico.bytes_to_mtu_increase == 0);

    uint32_t cwnd_after_recovery = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 1, 20, 1, 0, 21, 1100, mtu);
    ok(cc.state.pico.cuback.cwnd_prior == (uint32_t)(2. * cwnd_after_recovery / QUICLY_BETA_LOSS));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    ok(!quicly_cc_rapid_start_is_enabled(&cc.rapid_start));

    /* Losses from the completed recovery no longer revise CWND or the initialized Cuback epoch. */
    cwnd_after_recovery = cc.cwnd;
    uint32_t ssthresh_after_recovery = cc.ssthresh;
    struct st_quicly_cc_cuback_t cuback_after_recovery = cc.state.pico.cuback;
    cc.type->cc_on_lost(&cc, &loss, mtu, 19, 21, 1150, mtu);
    ok(cc.cwnd == cwnd_after_recovery);
    ok(cc.ssthresh == ssthresh_after_recovery);
    ok(memcmp(&cc.state.pico.cuback, &cuback_after_recovery, sizeof(cuback_after_recovery)) == 0);

    cc.type->cc_on_acked(&cc, &loss, 1, 21, 1, 1, 22, 1200, mtu);
    ok(cc.state.pico.bytes_to_mtu_increase != 0);
}

static void test_zero_byte_ack_exits_rapid_start_recovery(void)
{
    static quicly_init_cc_t *const policies[] = {&quicly_cc_cuback_init, &quicly_cc_cubic_init};
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    for (size_t i = 0; i != PTLS_ELEMENTSOF(policies); ++i) {
        for (int second_by_ecn = 0; second_by_ecn != 2; ++second_by_ecn) {
            quicly_cc_t cc;
            policies[i]->cb(policies[i], &cc, initcwnd, 0, 0);
            cc.type->enable_rapid_start(&cc, 900);

            cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
            ok(quicly_cc_rapid_start_is_in_recovery(&cc.rapid_start));

            /* A subsequent packet-loss or ECN episode can be detected from an ACK carrying no congestion-controlled bytes. The
             * loss callback finalizes Rapid Start before processing that episode. */
            cc.type->cc_on_lost(&cc, &loss, second_by_ecn ? 0 : mtu, 20, 30, 1200, mtu);
            ok(!quicly_cc_rapid_start_is_enabled(&cc.rapid_start));
            ok(cc.num_loss_episodes == 2);
            ok((policies[i] == &quicly_cc_cuback_init ? cc.state.pico.cuback.by_ecn : cc.state.pico.cubic.by_ecn) == second_by_ecn);
            ok(policies[i] == &quicly_cc_cuback_init ? cc.state.pico.cuback.fast_convergence
                                                     : cc.state.pico.cubic.fast_convergence);
        }
    }
}

static void test_rapid_start(void)
{
    struct st_quicly_cc_rapid_start_t rs;
    quicly_rtt_t rtt = {};

    quicly_cc_init_rapid_start(&rs, 1);
    rtt.minimum = rtt.latest = 16;

    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* no sample => 2x */
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 1);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* 2 samples after 1/4 min_rtt */
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 5);
    ok(rs.rtt_samples[0] == 16);
    ok(rs.rtt_samples[1] == 16);
    ok(rs.rtt_samples[2] == UINT32_MAX);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* after another 1/2 min_rtt, rtt increases to min + 5 */
    rtt.latest = 21;
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 13);
    ok(rs.rtt_samples[0] == 21);
    ok(rs.rtt_samples[1] == UINT32_MAX);
    ok(rs.rtt_samples[2] == 16);
    ok(rs.rtt_samples[3] == 16);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* after another 1/2 min_rtt, smaller samples are pushed out */
    quicly_cc_rapid_start_update_rtt(&rs, &rtt, 21);
    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt));
}

void test_cc(void)
{
    subtest("fast-cbrt", test_fast_cbrt);
    subtest("rapid-start", test_rapid_start);
    subtest("reno", test_reno);
    subtest("cubic-fast-convergence", test_cubic_fast_convergence);
    subtest("cubic-target-bounds", test_cubic_target_bounds);
    subtest("cubic-w-est", test_cubic_w_est);
    subtest("cubic-mtu-normalization", test_cubic_mtu_normalization);
    subtest("cubic-cc-limited", test_cubic_cc_limited);
    subtest("cubic-recovery-epoch", test_cubic_recovery_epoch);
    subtest("cubic-rapid-start-epoch", test_cubic_rapid_start_epoch);
    subtest("cubic-abe", test_cubic_abe);
    subtest("cubic-undo-loss", test_cubic_undo_loss);
    subtest("cubic-legacy-name", test_cubic_legacy_name);
    subtest("pico-ack-countdown", test_pico_ack_countdown);
    subtest("pico-switch-resets-ack-credit", test_pico_switch_resets_ack_credit);
    subtest("cuback-reno-bytes-per-mtu-increase", test_cuback_reno_bytes_per_mtu_increase);
    subtest("cuback-cubic-bytes-per-mtu-increase", test_cuback_cubic_bytes_per_mtu_increase);
    subtest("cuback-ack-countdown", test_cuback_ack_countdown);
    subtest("cuback-deferred-bdp-estimate", test_cuback_deferred_bdp_estimate);
    subtest("zero-byte-ack-exits-rapid-start-recovery", test_zero_byte_ack_exits_rapid_start_recovery);
    subtest("pico-undo-loss", test_pico_undo_loss);
    subtest("pico-undo-multiple-losses", test_pico_undo_multiple_losses);
    subtest("pico-undo-rapid-start-loss", test_pico_undo_rapid_start_loss);
    subtest("pico-undo-jumpstart-loss", test_pico_undo_jumpstart_loss);
    subtest("pico-ecn", test_pico_ecn);
    subtest("pico-ecn-rapid-start", test_pico_ecn_rapid_start);
}
