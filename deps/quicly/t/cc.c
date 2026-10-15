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
#include "quicly/defaults.h"
#include "../lib/cc-pico.c"
#include "test.h"

#define TEST_CC_CONF(_initcwnd_packets, _normalize_mtu, _abba, _rapid_start)                                                       \
    (&(const quicly_cc_conf_t){.initcwnd_packets = (_initcwnd_packets),                                                            \
                               .normalize_mtu = (_normalize_mtu),                                                                  \
                               .abba = (_abba),                                                                                    \
                               .rapid_start = (_rapid_start)})
#define TEST_CC_CONF_WITHOUT_ABBA(conf) TEST_CC_CONF((conf)->initcwnd_packets, (conf)->normalize_mtu, 0, (conf)->rapid_start)

static void test_pico_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
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

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);

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

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 1), mtu, 900);
    ok(quicly_cc_rapid_start_is_active(&cc.rapid_start));

    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.rapid_start.state == QUICLY_CC_RAPID_START_STATE_RECOVERY);

    cc.type->cc_on_late_ack(&cc, 10, 1100);
    ok(cc.rapid_start.state == QUICLY_CC_RAPID_START_STATE_INACTIVE);
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

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
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

    cc.type->cc_on_acked(&cc, &loss, mtu, 11, 18 * mtu, 1, 20, 1200, mtu, NULL);
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

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);

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

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 1), mtu, 900);

    /* upon a CE mark, the silence factor derived from QUICLY_BETA_ECN (i.e., 0.95x) is applied */
    cc.type->cc_on_lost(&cc, &loss, 0, 10, 20, 1000, mtu);
    ok(cc.rapid_start.state == QUICLY_CC_RAPID_START_STATE_RECOVERY);
    ok(cc.rapid_start.by_ecn);
    ok(cwnd_is(cc.cwnd, initcwnd * QUICLY_RAPID_START_LOSS_FACTOR(QUICLY_BETA_ECN)));
    uint32_t cwnd_entering_recovery = cc.cwnd;

    /* during the recovery period, CWND is reduced by ack_factor (0.1x) per byte newly acked */
    cc.type->cc_on_acked(&cc, &loss, 4 * mtu, 15, 8 * mtu, 1, 20, 1100, mtu, NULL);
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

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);

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

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.epoch_start = 1;

    cc.type->cc_on_acked(&cc, &loss, 2 * mtu, 1, cc.cwnd, 1, 2, 1000000, mtu, NULL);
    ok(cc.cwnd == initcwnd + mtu);

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd / 2;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd / 2;
    cc.state.pico.cubic.w_est = cc.state.pico.cubic.cwnd_prior - 1;
    cc.state.pico.cubic.epoch_start = 1;
    cc.state.pico.cubic.k = 0;
    cc.type->cc_on_acked(&cc, &loss, 1, 1, cc.cwnd, 0, 2, 1, mtu, NULL);
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
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.epoch_start = 1000;
    cc.state.pico.cubic.k = 0;
    cc.type->cc_on_acked(&cc, &loss, initcwnd, 1, initcwnd, 0, 2, 2000, mtu, NULL);
    ok(cwnd_is(cc.cwnd, initcwnd + QUICLY_CUBIC_C * QUICLY_CC_REFERENCE_MTU));

    /* In the Reno-friendly region, growth uses the reference MTU but CWND is still exposed in actual-MTU steps. Five windows of
     * ACKs therefore accumulate six 1200-byte steps (floor(5 * 1462 / 1200)). */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cubic.w_est = cc.cwnd;
    cc.state.pico.cubic.cwnd_prior = cc.cwnd;
    cc.state.pico.cubic.epoch_start = 1000;
    cc.state.pico.cubic.k = 100;
    for (size_t i = 0; i != 5; ++i) {
        uint32_t cwnd = cc.cwnd;
        cc.type->cc_on_acked(&cc, &loss, cwnd, i + 1, cwnd, 1, i + 2, 1000, mtu, NULL);
    }
    ok(cc.cwnd == initcwnd + 6 * mtu);
}

static void test_cubic_cc_limited(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
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
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 2100, mtu, NULL);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(cc.state.pico.cubic.w_est > initcwnd);

    /* Resumption starts the wall clock. An ACK that is not locally CC-limited advances W_cubic but not W_est. */
    double w_est_before = cc.state.pico.cubic.w_est;
    cc.type->cc_update_cc_limited(&cc, 1, 3000);
    ok(cc.state.pico.cubic.cc_limited);
    cc.type->cc_on_acked(&cc, &loss, mtu, 2, mtu, 0, 3, 3100, mtu, NULL);
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
    cc.type->cc_on_acked(&cc, &loss, mtu, 3, mtu, 1, 4, 3100, mtu, NULL);
    ok(cc.cwnd > cwnd_before);
    ok(cc.state.pico.cubic.w_est > w_est_before);
}

static void test_cubic_recovery_epoch(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    /* RFC 9438 starts the epoch when congestion avoidance begins, not when congestion is detected. */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 0);
    cc.type->cc_on_acked(&cc, &loss, 0, 19, 0, 1, 20, 1100, mtu, NULL);
    ok(cc.state.pico.cubic.epoch_start == 0);
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1200, mtu, NULL);
    ok(cc.state.pico.cubic.w_est == cc.cwnd);
    ok(cc.state.pico.cubic.epoch_start == 1200);

    /* If recovery exits while app-limited, initialize W_est but defer the wall-clock epoch until sending resumes. */
    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    cc.type->cc_update_cc_limited(&cc, 0, 1050);
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 0, 21, 1200, mtu, NULL);
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

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 1), mtu, 900);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cubic.cwnd_prior != 0);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.w_est == 0);
    ok(cc.state.pico.cubic.epoch_start == 0);
    ok(isnan(cc.state.pico.cubic.k));

    cc.type->cc_on_acked(&cc, &loss, 4 * mtu, 15, 8 * mtu, 1, 20, 1100, mtu, NULL);
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
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1200, mtu, NULL);
    ok(cc.state.pico.cubic.cwnd_prior == (uint32_t)(2. * cwnd_epoch / QUICLY_BETA_LOSS));
    ok(cc.state.pico.cubic.cwnd_prior != cwnd_prior_during_recovery);
    ok(!cc.state.pico.cubic.fast_convergence);
    ok(cc.state.pico.cubic.w_est == cwnd_epoch);
    ok(cc.state.pico.cubic.epoch_start == 1200);
    ok(!isnan(cc.state.pico.cubic.k));
    ok(!quicly_cc_rapid_start_is_active(&cc.rapid_start));

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

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);

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
    cc.type->cc_on_acked(&cc, &loss, mtu, 30, mtu, 1, 31, 1200, mtu, NULL);
    ok(cc.state.pico.cubic.k > 0);
    ok((uint32_t)cc.state.pico.cubic.w_est == (uint32_t)expected_w_est);
}

static void test_cubic_undo_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_cubic_init.cb(&quicly_cc_cubic_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
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

    quicly_cc_cubic_legacy_init.cb(&quicly_cc_cubic_legacy_init, &cc, TEST_CC_CONF(10, 0, 0, 0), 1200, 0);
    ok(cc.type == &quicly_cc_type_cubic_legacy);
    ok(strcmp(cc.type->name, "cubic-legacy") == 0);
}

static void test_pico_ack_countdown(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.type->cc_on_acked(&cc, &loss, mtu - 1, 1, mtu - 1, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);

    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd + mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == mtu);

    /* The interval switches to Pico's congestion-avoidance rate when an increase reaches ssthresh. */
    quicly_cc_pico_init.cb(&quicly_cc_pico_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.ssthresh = initcwnd + mtu;
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == cc.ssthresh);
    ok(cc.state.pico.bytes_to_mtu_increase == initcwnd * QUICLY_BETA_LOSS);
}

static void test_pico_switch_resets_ack_credit(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    uint32_t mtu = 1200, initcwnd = 10 * mtu;

    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, initcwnd - 1, 1, initcwnd - 1, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);

    ok(quicly_cc_type_pico.cc_switch(&cc));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu, NULL);
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
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, initcwnd - 1, 1, initcwnd - 1, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd + mtu);

    /* Packet-size normalization shortens the ACK deficit so that actual-MTU CWND steps amortize to the reference MTU per RTT. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    uint32_t normalized_deficit = (uint64_t)initcwnd * mtu / QUICLY_CC_REFERENCE_MTU;
    cc.type->cc_on_acked(&cc, &loss, normalized_deficit - 1, 1, normalized_deficit - 1, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 2, 1, 1, 3, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd + mtu);

    /* Normalization does not alter slow start. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 0, 0), mtu, 0);
    cc.type->cc_on_acked(&cc, &loss, mtu, 1, mtu, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == initcwnd + mtu);

    /* Startup uses the shared 0.5 reduction; subsequent loss uses the policy beta. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.cwnd == initcwnd / 2);
    cc.cwnd = 40 * mtu;
    cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1100, mtu);
    ok(cwnd_is(cc.cwnd, 40 * mtu * QUICLY_BETA_RENO));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    cc.type->cc_on_acked(&cc, &loss, mtu, 30, mtu, 1, 31, 1200, mtu, NULL);
    ok(cc.state.pico.bytes_to_mtu_increase == cc.cwnd - mtu);

    /* Reno uses the same beta for ECN and packet loss. */
    quicly_cc_reno_init.cb(&quicly_cc_reno_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
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

    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, TEST_CC_CONF(w_max / mtu, 0, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cuback.cwnd_prior = w_max;
    cc.state.pico.cuback.bandwidth = w_max * 1000. / loss.rtt.smoothed;
    cc.state.pico.bytes_to_mtu_increase = 0;

    /* Above W_max, alpha is one, so moving from 2 to 3 MTUs requires 2 MTUs newly acknowledged after recovery. */
    cc.type->cc_on_acked(&cc, &loss, 1, 1, 1, 1, 2, 100, mtu, NULL);
    ok(cc.cwnd == w_max);
    ok(cc.state.pico.bytes_to_mtu_increase == 2 * mtu - 1);
    cc.type->cc_on_acked(&cc, &loss, 2 * mtu - 2, 2, 2 * mtu - 2, 1, 3, 100, mtu, NULL);
    ok(cc.cwnd == w_max);
    ok(cc.state.pico.bytes_to_mtu_increase == 1);
    cc.type->cc_on_acked(&cc, &loss, 1, 3, 1, 1, 4, 100, mtu, NULL);
    ok(cc.cwnd == w_max + mtu);
    ok(cc.state.pico.bytes_to_mtu_increase == 3 * mtu);

    /* The policy-level option selects the normalized ACK threshold while retaining actual-MTU CWND steps. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, TEST_CC_CONF(w_max / mtu, 1, 0, 0), mtu, 0);
    cc.ssthresh = cc.cwnd;
    cc.state.pico.cuback.cwnd_prior = w_max;
    cc.state.pico.cuback.bandwidth = w_max * 1000. / loss.rtt.smoothed;
    cc.type->cc_on_acked(&cc, &loss, 1, 1, 1, 1, 2, 100, mtu, NULL);
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
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cuback.cwnd_prior == initcwnd / 2);

    /* Rapid Start continues adjusting CWND throughout recovery, so W_max is derived from the final CWND afterward, using twice
     * the BDP estimate. */
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 1), mtu, 900);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.state.pico.cuback.bandwidth > 0);
    ok(cc.state.pico.cuback.cwnd_prior == 0);
    ok(cc.state.pico.bytes_to_mtu_increase == 0);

    uint32_t cwnd_after_recovery = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 1, 20, 1, 0, 21, 1100, mtu, NULL);
    ok(cc.state.pico.cuback.cwnd_prior == (uint32_t)(2. * cwnd_after_recovery / QUICLY_BETA_LOSS));
    ok(cc.state.pico.bytes_to_mtu_increase == 0);
    ok(!quicly_cc_rapid_start_is_active(&cc.rapid_start));

    /* Losses from the completed recovery no longer revise CWND or the initialized Cuback epoch. */
    cwnd_after_recovery = cc.cwnd;
    uint32_t ssthresh_after_recovery = cc.ssthresh;
    struct st_quicly_cc_cuback_t cuback_after_recovery = cc.state.pico.cuback;
    cc.type->cc_on_lost(&cc, &loss, mtu, 19, 21, 1150, mtu);
    ok(cc.cwnd == cwnd_after_recovery);
    ok(cc.ssthresh == ssthresh_after_recovery);
    ok(memcmp(&cc.state.pico.cuback, &cuback_after_recovery, sizeof(cuback_after_recovery)) == 0);

    cc.type->cc_on_acked(&cc, &loss, 1, 21, 1, 1, 22, 1200, mtu, NULL);
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
            policies[i]->cb(policies[i], &cc, TEST_CC_CONF(initcwnd / mtu, 0, 0, 1), mtu, 900);

            cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
            ok(quicly_cc_rapid_start_is_in_first_recovery(&cc.rapid_start));

            /* A subsequent packet-loss or ECN episode can be detected from an ACK carrying no congestion-controlled bytes. The
             * loss callback finalizes Rapid Start before processing that episode. */
            cc.type->cc_on_lost(&cc, &loss, second_by_ecn ? 0 : mtu, 20, 30, 1200, mtu);
            ok(!quicly_cc_rapid_start_is_active(&cc.rapid_start));
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
    quicly_rtt_t rtt;

    quicly_cc_init_rapid_start(&rs, 1);
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 16);

    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* no sample => 2x */
    ok(quicly_cc_rapid_start_is_active(&rs));
    quicly_rtt_update(&rtt, 16, 0, 1);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* 2 samples after 1/4 min_rtt */
    quicly_rtt_update(&rtt, 16, 0, 5);
    ok(rtt.floor.samples[0] == 16);
    ok(rtt.floor.samples[1] == 16);
    ok(rtt.floor.samples[2] == FLT_MAX);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* after another 1/2 min_rtt, rtt increases to min + 5 */
    quicly_rtt_update(&rtt, 21, 0, 13);
    ok(rtt.floor.samples[0] == 21);
    ok(rtt.floor.samples[1] == FLT_MAX);
    ok(rtt.floor.samples[2] == 16);
    ok(rtt.floor.samples[3] == 16);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* floor == min => 3x */

    /* after another 1/2 min_rtt, smaller samples are pushed out */
    quicly_rtt_update(&rtt, 21, 0, 21);
    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt));

    /* Rapid Start remains disabled on paths shorter than four milliseconds even though the core floor tracker supports them. */
    quicly_cc_init_rapid_start(&rs, 22);
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 16);
    quicly_rtt_update(&rtt, 3, 0, 22);
    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt));
    ok(!quicly_cc_rapid_start_is_active(&rs));
}

static void test_abba_model(void)
{
    struct st_quicly_cc_abba_t state = {.high = {100000, 120}, .low = {70000, 100}};
    abba_fit_model(&state);
    ok(fabs(state.a - 1. / 2250) < FLT_EPSILON / 2250);
    ok(fabs(state.b - 620. / 9) < FLT_EPSILON * 620 / 9);
    ok(fabs((double)state.a * 70000 + state.b - 100) < FLT_EPSILON * 100);
    ok(fabs((double)state.a * 100000 + state.b - (100 + 40. / 3)) < FLT_EPSILON * 120);

    /* A steep fit is capped at the origin before flattening about the low point. */
    state.high.rtt = 200;
    abba_fit_model(&state);
    ok(state.a == (float)(100. / 70000 * (2. / 3)));
    ok(state.b == (float)(100. / 3));
    state.high.rtt = 100;
    abba_fit_model(&state);
    ok(state.a == 0 && state.b == 100);
    state.high.rtt = 120;
    abba_fit_model(&state);
    float a = state.a, b = state.b;
    state.low.cwnd = 100000;
    abba_fit_model(&state);
    ok(state.a == a && state.b == b);
    state.low.cwnd = 110000;
    abba_fit_model(&state);
    ok(state.a == a && state.b == b);

    /* The high watermark pairs the pre-reduction window with the recovery minimum, not SRTT. */
    quicly_rtt_t rtt = {.latest = 80, .smoothed = 115, .minimum = 20};
    abba_on_congestion(&state, 100000, &rtt, 0);
    ok(state.high.cwnd == 100000 && state.high.rtt == 80);
    ok(state.low.cwnd == 0);
    rtt.latest = 70;
    abba_on_acked(&state, 80000, &rtt, 1, 0, QUICLY_BETA_LOSS);
    ok(state.high.cwnd == 100000 && state.high.rtt == 70);
    ok(state.low.cwnd == 0);
    rtt.latest = 75;
    rtt.smoothed = 110;
    abba_on_acked(&state, 75000, &rtt, 1, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 70 && state.low.cwnd == 0);
    rtt.latest = 90;
    abba_on_acked(&state, 70000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.low.cwnd == 70000 && state.low.rtt == 70);
    ok(state.high.rtt == 70);
    ok(state.a == 0 && state.b == 70);
    a = state.a;
    b = state.b;
    abba_on_acked(&state, 72000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.low.cwnd == 70000 && state.low.rtt == 70);
    ok(state.a == a && state.b == b);
    rtt.latest = 70;
    abba_on_acked(&state, 75000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.low.cwnd == 70000); /* Equal samples do not move the point. */
    ok(state.a == a && state.b == b);
    /* Sub-millisecond improvements retain both low-point fields and the model until the total reaches 1ms. */
    const float samples[] = {69.5f, 69.001f};
    for (size_t i = 0; i != sizeof(samples) / sizeof(samples[0]); ++i) {
        rtt.latest = samples[i];
        abba_on_acked(&state, 76000, &rtt, 0, 0, QUICLY_BETA_LOSS);
        ok(state.low.cwnd == 70000 && state.low.rtt == 70);
        ok(state.a == a && state.b == b);
    }
    rtt.latest = 69;
    abba_on_acked(&state, 76000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.low.cwnd == 76000 && state.low.rtt == 69);
    ok(state.high.rtt == 70 && state.a == 0 && state.b == 69);
    rtt.latest = 65;
    abba_on_acked(&state, 78000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 70 && state.low.rtt == 65);
    ok(state.a == (float)(5. / 22000 * (2. / 3)) && state.b > 0);

    /* Without an intervening recovery ACK, retain the congestion sample even when SRTT is lower. */
    rtt.latest = 160;
    rtt.smoothed = 125;
    abba_on_congestion(&state, 100000, &rtt, 0);
    ok(state.high.rtt == 160 && state.low.cwnd == 0);
    rtt.latest = 170;
    abba_on_acked(&state, 70000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 160 && state.low.rtt == 160);
    ok(state.a == 0 && state.b == 160);

    /* Without a sample at congestion, SRTT supplies the initial estimate; recovery samples can lower it. */
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 120);
    abba_on_congestion(&state, 100000, &rtt, 0);
    ok(state.high.rtt == 120 && state.low.cwnd == 0);
    abba_on_acked(&state, 70000, &rtt, 1, 0, QUICLY_BETA_LOSS);
    abba_on_acked(&state, 70000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 120 && state.low.cwnd == 0);
    ok(state.a == 0 && isnan(state.b));
    quicly_rtt_update(&rtt, 140, 0, 1);
    abba_on_acked(&state, 70000, &rtt, 1, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 120 && state.low.cwnd == 0);
    quicly_rtt_update(&rtt, 100, 0, 2);
    abba_on_acked(&state, 70000, &rtt, 1, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 100 && state.low.cwnd == 0);
    abba_on_acked(&state, 70000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.low.cwnd == 70000 && state.low.rtt == 100);
    ok(state.a == 0 && state.b == 100);

    /* If there are no recovery samples, the SRTT fallback remains the high watermark at recovery exit. */
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 120);
    abba_on_congestion(&state, 100000, &rtt, 0);
    quicly_rtt_update(&rtt, 150, 0, 3);
    abba_on_acked(&state, 70000, &rtt, 0, 0, QUICLY_BETA_LOSS);
    ok(state.high.rtt == 120 && state.low.rtt == 120);
    ok(state.a == 0 && state.b == 120);
}

static void test_abba_fit_growth(void)
{
    /* Flattening changes the high-window prediction from 112ms to 96ms, but leaves the low point at 64ms. */
    struct st_quicly_cc_abba_t state = {.high = {65536, 112}, .low = {32768, 64}};
    quicly_rtt_t rtt = {.latest = 64, .smoothed = 64, .minimum = 20};
    abba_fit_model(&state);
    ok(abba_on_growth(&state, 32768, 32768, 32768, &rtt, 0, &(int){0}) == 32768);
    rtt.latest = 95;
    ok(abba_on_growth(&state, 65536, 65536, 65536, &rtt, 0, &(int){0}) == 66150);
    rtt.latest = 94;
    /* Include the fractional carry from the preceding ACK. */
    ok(abba_on_growth(&state, 65536, 65536, 65536, &rtt, 0, &(int){0}) == 66765);

    /* Apply the factor after the origin cap: the high-window prediction is 160ms, not the unscaled cap's 192ms. */
    state = (struct st_quicly_cc_abba_t){.high = {65536, 256}, .low = {32768, 96}};
    abba_fit_model(&state);
    rtt.latest = 96;
    ok(abba_on_growth(&state, 32768, 32768, 32768, &rtt, 0, &(int){0}) == 32768);
    rtt.latest = 160;
    ok(abba_on_growth(&state, 65536, 65536, 65536, &rtt, 0, &(int){0}) == 65536);
    rtt.latest = 120;
    ok(abba_on_growth(&state, 65536, 65536, 65536, &rtt, 0, &(int){0}) == 77824);
}

static void test_abba_min_rtt_span(void)
{
    /* The fitting boundary is inclusive, including fractional stored RTTs. */
    struct st_quicly_cc_abba_t state = {.high = {100000, 104.999f}, .low = {70000, 100}};
    abba_fit_model(&state);
    ok(state.a == 0 && state.b == 100);
    state.high.rtt = 105;
    abba_fit_model(&state);
    ok(state.a == (float)(5. / 30000 * (2. / 3)) && state.b > 0);
    state.high.rtt = 105.001f;
    abba_fit_model(&state);
    ok(state.a > (float)(5. / 30000 * (2. / 3)) && state.b > 0);

    for (int by_ecn = 0; by_ecn != 2; ++by_ecn) {
        for (int beyond_threshold = 0; beyond_threshold != 2; ++beyond_threshold) {
            state = (struct st_quicly_cc_abba_t){.high = {100000, 100}, .low = {0, 100}, .a = 0, .b = NAN};
            quicly_rtt_t rtt;
            quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 96);
            quicly_rtt_update(&rtt, 96, 0, 0);
            uint32_t cwnd = beyond_threshold ? 140000 : 70000;
            abba_on_acked(&state, cwnd, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == cwnd && state.low.rtt == 96);
            if (beyond_threshold) {
                /* A proportional model can be established without an RTT span, but anchoring at the floor does not
                 * immediately create a shortfall. Further window growth can enable acceleration. */
                ok(state.a == (float)(96. / cwnd) && state.b == 0);
                ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd);
                ok(abba_on_growth(&state, cwnd + 10000, cwnd + 10000, cwnd, &rtt, 0, &(int){0}) > cwnd + 10000);
            } else {
                ok(state.a == 0);
                /* Proximity to minRTT alone does not accelerate growth. */
                ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd);
                ok(abba_on_growth(&state, cwnd, cwnd + 1200, cwnd, &rtt, 0, &(int){0}) == cwnd + 1200);
            }
            quicly_rtt_update(&rtt, 95, 0, 1);
            abba_on_acked(&state, cwnd, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.a > 0);
            if (beyond_threshold) {
                ok(state.a == (float)(96. / cwnd) && state.b == 0);
            } else {
                ok(state.a == (float)(5. / 30000 * (2. / 3)) && state.b > 0);
            }
        }
    }
}

static void test_abba_proportional_switch(void)
{
    for (int by_ecn = 0; by_ecn != 2; ++by_ecn) {
        struct st_quicly_cc_abba_t state = {.high = {100000, 120}, .low = {70000, 100}, .a = 0, .b = NAN};
        quicly_rtt_t rtt;
        quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 105);
        quicly_rtt_update(&rtt, 20, 0, 0);
        quicly_rtt_update(&rtt, 110, 0, 1000);
        uint32_t threshold = by_ecn ? 115000 : 130000;
        abba_fit_model(&state);
        /* Check either side of the threshold without depending on rounding at the exact boundary. */
        abba_on_acked(&state, threshold - 1, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(state.b > 0);
        double target = (double)state.a * (threshold + 1) + state.b;
        abba_on_acked(&state, threshold + 1, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        double a = state.a;
        ok(a == (float)(target / (threshold + 1)) && state.b == 0);

        /* New minima invoke fitting, which preserves the model when the low window is at or beyond the congestion window. */
        quicly_rtt_update(&rtt, 80, 0, 1001);
        abba_on_acked(&state, 150000, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(state.low.cwnd == 150000 && state.low.rtt == 80);
        ok(state.a == a && state.b == 0);

        /* Flattening an origin-capped fit leaves a positive intercept, permitting the later proportional switch. */
        state = (struct st_quicly_cc_abba_t){.high = {100000, 200}, .low = {70000, 100}};
        abba_fit_model(&state);
        target = (double)state.a * 150000 + state.b;
        abba_on_acked(&state, 150000, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(state.a == (float)(target / 150000) && state.b == 0);

        /* An unfitted model with no ordered window span is anchored at the RTT floor, not SRTT. */
        state = (struct st_quicly_cc_abba_t){.high = {100000, 120}, .low = {100000, 80}, .a = 0, .b = NAN};
        abba_on_acked(&state, threshold - 1, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(state.a == 0 && isnan(state.b));
        ok(abba_on_growth(&state, threshold - 1, threshold - 1, 1000, &rtt, 0, &(int){0}) == threshold - 1);
        abba_on_acked(&state, threshold + 1, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(state.a == (float)(80. / (threshold + 1)) && state.b == 0);

        /* Preserve the affine prediction of 128ms rather than lowering it to the 80ms floor or SRTT. */
        state = (struct st_quicly_cc_abba_t){.high = {40000, 120}, .low = {30000, 60}, .a = 1.f / 1024, .b = 64};
        quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 80);
        quicly_rtt_update(&rtt, 80, 0, 0);
        quicly_rtt_update(&rtt, 96, 0, 1);
        abba_on_acked(&state, 65536, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(abba_on_growth(&state, 65536, 65536, 12288, &rtt, 0, &(int){0}) == 67379);

        /* Once proportional, the model is not redrawn even if the floor rises above its prediction. */
        quicly_rtt_update(&rtt, 160, 0, 1000);
        abba_on_acked(&state, 65536, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        quicly_rtt_update(&rtt, 120, 0, 1001);
        abba_on_acked(&state, 65536, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(abba_on_growth(&state, 65536, 65536, 12288, &rtt, 0, &(int){0}) == 65997);
        quicly_rtt_update(&rtt, 80, 0, 1002);
        abba_on_acked(&state, 65536, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(abba_on_growth(&state, 65536, 65536, 12288, &rtt, 0, &(int){0}) == 68300);

        /* With RTT staying flat, a larger window increases the gain per acknowledged byte. */
        abba_on_acked(&state, 81920, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
        ok(abba_on_growth(&state, 81920, 81920, 12288, &rtt, 0, &(int){0}) == 85607);
    }
}

static void test_abba_minimum_at_larger_window(void)
{
    for (int by_ecn = 0; by_ecn != 2; ++by_ecn) {
        for (int beyond = 0; beyond != 2; ++beyond) {
            struct st_quicly_cc_abba_t state = {.high = {65536, 120}, .low = {49152, 100}};
            quicly_rtt_t rtt = {.latest = 100, .smoothed = 110, .minimum = 20};
            abba_fit_model(&state);
            float a = state.a, b = state.b;
            ok(a > 0 && b > 0);

            /* Reaching or passing the congestion window without a new minimum preserves both points and their fit. */
            uint32_t cwnd = beyond ? 73728 : 65536;
            abba_on_acked(&state, cwnd, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == 49152 && state.low.rtt == 100);
            ok(state.a == a && state.b == b);
            /* ACK half a window so the per-ACK cap does not mask increases in model gain. */
            uint32_t previous_growth = abba_on_growth(&state, cwnd, cwnd, cwnd / 2, &rtt, 0, &(int){0}) - cwnd;

            /* A new minimum moves the low point but preserves the model, increasing acceleration as RTT falls. */
            rtt.latest = beyond ? 72 : 64;
            abba_on_acked(&state, cwnd, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == cwnd && state.low.rtt == rtt.latest);
            ok(state.high.cwnd == 65536 && state.high.rtt == 120);
            ok(state.a == a && state.b == b);
            ok(abba_on_growth(&state, cwnd, cwnd, cwnd / 2, &rtt, 0, &(int){0}) - cwnd > previous_growth);

            /* Further window growth without a new minimum leaves both the low point and the model unchanged. */
            uint32_t grown_cwnd = cwnd + 512;
            abba_on_acked(&state, grown_cwnd, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == cwnd);
            ok(state.a == a && state.b == b);
            previous_growth = abba_on_growth(&state, grown_cwnd, grown_cwnd, grown_cwnd / 2, &rtt, 0, &(int){0}) - grown_cwnd;

            /* Another minimum below the switch threshold likewise increases acceleration without refitting. */
            --rtt.latest;
            abba_on_acked(&state, grown_cwnd, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == grown_cwnd && state.low.rtt == rtt.latest);
            ok(state.a == a && state.b == b);
            ok(abba_on_growth(&state, grown_cwnd, grown_cwnd, grown_cwnd / 2, &rtt, 0, &(int){0}) - grown_cwnd > previous_growth);

            /* Crossing the switch threshold preserves the model's prediction when establishing the proportional model. */
            --rtt.latest;
            rtt.smoothed = 90;
            double target = (double)state.a * 90000 + state.b;
            abba_on_acked(&state, 90000, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == 90000 && state.low.rtt == rtt.latest);
            a = state.a;
            ok(a == (float)(target / 90000) && state.b == 0);
            --rtt.latest;
            rtt.smoothed = 80;
            abba_on_acked(&state, 91000, &rtt, 0, by_ecn, (QUICLY_USE_ABE && by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS));
            ok(state.low.cwnd == 91000 && state.low.rtt == rtt.latest);
            ok(state.a == a && state.b == 0);
        }
    }
}

static void test_abba_growth(void)
{
    struct st_quicly_cc_abba_t state = {.a = 0.001, .b = 50};
    quicly_rtt_t rtt = {.latest = 100, .smoothed = 100, .minimum = 20};
    /* The inverse model gives 50kB, so a 100kB flight adds three fifths of the 50kB gap. */
    ok(abba_on_growth(&state, 100000, 101000, 100000, &rtt, 0, &(int){0}) == 130000);
    ok(abba_on_growth(&state, 100000, 140000, 100000, &rtt, 0, &(int){0}) == 140000);
    rtt.latest = 150;
    ok(abba_on_growth(&state, 100000, 101000, 100000, &rtt, 0, &(int){0}) == 101000);
    rtt.latest = 200;
    ok(abba_on_growth(&state, 100000, 90000, 100000, &rtt, 0, &(int){0}) == 100000);

    /* Being near minRTT does not accelerate a horizontal or unfitted model, even with a higher congestion watermark. */
    state.high.rtt = 100;
    state.a = 0;
    rtt.latest = rtt.minimum = 20;
    ok(abba_on_growth(&state, 100000, 101000, 100000, &rtt, 0, &(int){0}) == 101000);
    state.b = NAN;
    ok(abba_on_growth(&state, 100000, 100000, 100000, &rtt, 0, &(int){0}) == 100000);
    state.increase_remainder = 0;
    rtt.latest = 22;
    ok(abba_on_growth(&state, 100000, 101000, 100000, &rtt, 0, &(int){0}) == 101000);

    /* A usable model can still accelerate at minRTT. */
    state.a = 0.001;
    state.b = 0;
    rtt.latest = 20;
    ok(abba_on_growth(&state, 100000, 101000, 100000, &rtt, 0, &(int){0}) == 148000);

    /* A negative inverse window is allowed; the final per-ACK cap bounds its increase. */
    state.b = 100;
    ok(abba_on_growth(&state, 100001, 100001, 100001, &rtt, 0, &(int){0}) == 150001);
    state.increase_remainder = 0.9;
    ok(abba_on_growth(&state, 100001, 100001, 100001, &rtt, 0, &(int){0}) == 150001);
    /* The cap applies to acceleration, not the ordinary CUBIC candidate. */
    ok(abba_on_growth(&state, 100000, 160000, 100000, &rtt, 0, &(int){0}) == 160000);
    rtt.latest = rtt.minimum = 1;
    ok(abba_on_growth(&state, 100000, 100000, 100000, &rtt, 0, &(int){0}) == 150000);
    ok(abba_on_growth(&state, UINT32_MAX - 10, UINT32_MAX - 10, 100, &rtt, 0, &(int){0}) == UINT32_MAX);

    /* Three-fifths-byte increments accumulate: five one-byte ACKs add three bytes to CWND. */
    state = (struct st_quicly_cc_abba_t){.a = 1.f / 1024, .b = 8};
    rtt.latest = rtt.minimum = 8;
    uint32_t cwnd = 100000;
    for (int i = 0; i != 5; ++i)
        cwnd = abba_on_growth(&state, cwnd, cwnd, 1, &rtt, 0, &(int){0});
    ok(cwnd == 100003);
    ok(abba_on_growth(&state, cwnd, cwnd, 1, &rtt, 0, &(int){0}) == cwnd);
    /* Ordinary growth discards the fractional carry. */
    ok(abba_on_growth(&state, cwnd, cwnd + 2, 1, &rtt, 0, &(int){0}) == cwnd + 2);
    ok(abba_on_growth(&state, cwnd, cwnd, 1, &rtt, 0, &(int){0}) == cwnd);

    /* An absent RTT sample and zero-byte ACKs cannot grow the window. */
    rtt.latest = 0;
    ok(abba_on_growth(&state, cwnd, cwnd, 1000, &rtt, 0, &(int){0}) == cwnd);
    rtt.latest = 8;
    /* A zero-byte ACK retains pending fractional growth, as seen on the next one-byte ACK. */
    ok(abba_on_growth(&state, cwnd, cwnd, 1, &rtt, 0, &(int){0}) == cwnd);
    ok(abba_on_growth(&state, cwnd, cwnd, 0, &rtt, 0, &(int){0}) == cwnd);
    ok(abba_on_growth(&state, cwnd, cwnd, 1, &rtt, 0, &(int){0}) == cwnd + 1);
}

static void test_abba_gain_cap(void)
{
    for (int by_ecn = 0; by_ecn != 2; ++by_ecn) {
        double beta = by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS;
        double cap = pow(beta, -2. / 3) - 1;
        uint32_t prior = by_ecn ? 85000 : 70000;
        quicly_rtt_t rtt = {.latest = 8};

        /* A model gain of 3/5 is capped below prior / beta (100000), but not at or above it. */
        for (uint32_t cwnd = 99999; cwnd <= 100001; ++cwnd) {
            struct st_quicly_cc_abba_t state = {.a = 1.f / 1024, .b = 8};
            uint32_t expected = cwnd + 12000 * (cwnd < 100000 ? cap : 3. / 5);
            ok(abba_on_growth(&state, cwnd, cwnd, 12000, &rtt, prior, &(int){by_ecn}) == expected);
        }

        /* The gain cap does not cap ordinary growth or raise a smaller model gain. */
        struct st_quicly_cc_abba_t state = {.a = 1.f / 1024, .b = 8};
        ok(abba_on_growth(&state, 65536, 70000, 12000, &rtt, prior, &(int){by_ecn}) == 70000);
        rtt.latest = 68; /* Wref = 61440, giving a gain of 3/80. */
        ok(abba_on_growth(&state, 65536, 65536, 12000, &rtt, prior, &(int){by_ecn}) == 65986);

        /* Capped fractional increments survive ACK splitting. */
        rtt.latest = 8;
        state.increase_remainder = 0;
        uint32_t cwnd = 50000;
        for (int i = 0; i != 1000; ++i)
            cwnd = abba_on_growth(&state, cwnd, cwnd, 1, &rtt, prior, &(int){by_ecn});
        ok(cwnd == 50000 + (uint32_t)(1000 * cap));
    }
}

static void test_abba_gain_cap_policy(quicly_init_cc_t *init)
{
    for (int by_ecn = 0; by_ecn != 2; ++by_ecn) {
        double beta = by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS;
        uint32_t prior = by_ecn ? 85000 : 70000, mtu = 1200, acked = 12000;
        for (uint32_t cwnd = 99999; cwnd <= 100001; ++cwnd) {
            quicly_cc_t cc;
            quicly_loss_t loss = {.rtt = {.latest = 8, .smoothed = 8, .minimum = 8}};
            init->cb(init, &cc, TEST_CC_CONF(120000 / mtu, 0, 1, 0), mtu, 0);
            cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
            cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1100, mtu, NULL);
            /* A subsequent congestion event records the policy's prior window and loss/ECN beta. */
            cc.cwnd = prior;
            cc.type->cc_on_lost(&cc, &loss, by_ecn ? 0 : mtu, 30, 40, 1200, mtu);
            cc.type->cc_on_acked(&cc, &loss, 0, 40, 0, 1, 41, 1300, mtu, NULL);
            cc.cwnd = cwnd;
            cc.state.pico.abba.a = 1.f / 1024;
            cc.state.pico.abba.b = 0;
            double gain = cwnd < 100000 ? pow(beta, -2. / 3) - 1 : 3. / 5 * (1 - 8192. / cwnd);
            uint32_t expected = cwnd + acked * gain;
            cc.type->cc_on_acked(&cc, &loss, acked, 41, acked, 1, 42, 1300, mtu, NULL);
            ok(cc.cwnd == expected);
        }
    }
}

static void test_abba_model_shortfall(void)
{
    struct st_quicly_cc_abba_t state = {.a = 1.f / 1024, .b = 50};
    quicly_rtt_t rtt = {.latest = 112, .smoothed = 112, .minimum = 20};
    uint32_t cwnd = 65536;

    /* A 1.5ms shortfall yields three fifths of the 1536-byte inverse-window gap, unless ordinary growth is larger. */
    state.b = 49.5f;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd + 921);
    ok(abba_on_growth(&state, cwnd, cwnd + 1200, cwnd, &rtt, 0, &(int){0}) == cwnd + 1200);

    /* Gain scales continuously with the shortfall; 2ms is no longer a threshold. */
    state.b = 50;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd + 1228);
    ok(abba_on_growth(&state, cwnd, cwnd + 2048, cwnd, &rtt, 0, &(int){0}) == cwnd + 2048);
    state.b = 50.5f;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd + 1536);

    /* At or above the prediction, the model supplies no acceleration. */
    state.b = 48;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd);
    state.b = 47;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd);
    ok(abba_on_growth(&state, cwnd, cwnd + 1200, cwnd, &rtt, 0, &(int){0}) == cwnd + 1200);

    /* A proportional model also accelerates for a shortfall smaller than 2ms. */
    state.b = 0;
    rtt.latest = 63;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd + 614);
    rtt.latest = 62;
    /* The preceding ACK's fractional carry supplies the extra byte. */
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd + 1229);

    /* Reaching minRTT does not add acceleration beyond the model's gain. */
    state.high.rtt = 68;
    rtt.latest = rtt.minimum = 63;
    ok(abba_on_growth(&state, cwnd, cwnd, cwnd, &rtt, 0, &(int){0}) == cwnd + 614);
}

static void test_abba_float_precision(void)
{
    /* A nearly flat model at a large window must retain its slope and small ACK-driven increments. */
    uint32_t cwnd = (1U << 30) + 1;
    struct st_quicly_cc_abba_t state = {.high = {cwnd, 105.125f}, .low = {1U << 29, 100}};
    abba_fit_model(&state);
    ok(state.a > 0 && state.b > 0);
    ok(fabs((double)state.a * state.low.cwnd + state.b - 100) < 100 * FLT_EPSILON);
    ok(fabs((double)state.a * cwnd + state.b - (100 + 5.125 * (2. / 3))) < 105.125 * FLT_EPSILON);
    quicly_rtt_t rtt = {.latest = 100, .smoothed = 100, .minimum = 20};
    ok(abba_on_growth(&state, cwnd, cwnd, 16, &rtt, 0, &(int){0}) == cwnd + 4);

    /* Window coordinates a byte apart must not collapse to the same float during fitting. */
    state = (struct st_quicly_cc_abba_t){.high = {cwnd, 105}, .low = {cwnd - 1, 100}};
    abba_fit_model(&state);
    ok(state.a > 0 && state.b == (float)(100. / 3));

    /* Fractional growth must survive when the entire window is far larger than a float's byte-level precision. */
    state = (struct st_quicly_cc_abba_t){.a = 1.f / 1024, .b = 8};
    rtt.latest = rtt.minimum = 8;
    uint32_t before = cwnd;
    for (int i = 0; i != 10; ++i)
        cwnd = abba_on_growth(&state, cwnd, cwnd, 1, &rtt, 0, &(int){0});
    ok(cwnd == before + 5);
}

static void test_abba_lifecycle(quicly_init_cc_t *init)
{
    quicly_cc_t cc, control;
    quicly_loss_t loss = {.rtt = {.latest = 120, .smoothed = 120, .minimum = 20}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;
    init->cb(init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 1, 0), mtu, 0);
    init->cb(init, &control, TEST_CC_CONF(initcwnd / mtu, 0, 0, 0), mtu, 0);

    /* Startup and its congestion response are identical to CUBIC; the high watermark keeps the actual pre-reduction window. */
    cc.type->cc_on_acked(&cc, &loss, mtu, 9, mtu, 1, 10, 900, mtu, NULL);
    control.type->cc_on_acked(&control, &loss, mtu, 9, mtu, 1, 10, 900, mtu, NULL);
    ok(cc.cwnd == control.cwnd);
    uint32_t peak = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    control.type->cc_on_lost(&control, &loss, mtu, 10, 20, 1000, mtu);
    ok(cc.cwnd == control.cwnd && cc.ssthresh == control.ssthresh);
    ok(cc.state.pico.abba.high.cwnd == peak);
    ok((cc.type == &quicly_cc_type_cubic ? cc.state.pico.cubic.cwnd_prior : cc.state.pico.cuback.cwnd_prior) == peak / 2);
    loss.rtt.latest = 80;
    cc.type->cc_on_acked(&cc, &loss, mtu, 19, mtu, 1, 20, 1050, mtu, NULL);
    ok(cc.cwnd == control.cwnd && cc.state.pico.abba.high.rtt == 80);
    ok(cc.state.pico.abba.low.cwnd == 0);
    ok(cc.state.pico.abba.a == 0 && isnan(cc.state.pico.abba.b));
    loss.rtt.latest = 90;
    uint32_t reduced = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1100, mtu, NULL);
    ok(cc.state.pico.abba.low.cwnd == reduced);
    ok(cc.state.pico.abba.low.rtt == 80);

    /* A rapid bandwidth increase after the proportional switch lowers RTT and accelerates growth. */
    cc.cwnd = 2 * peak;
    quicly_rtt_init(&loss.rtt, &quicly_spec_context.egress[0].loss, 100);
    quicly_rtt_update(&loss.rtt, 100, 0, 1150);
    cc.type->cc_on_acked(&cc, &loss, 0, 21, 0, 1, 22, 1150, mtu, NULL);
    quicly_rtt_update(&loss.rtt, 50, 0, 1200);
    control = cc;
    control.conf = TEST_CC_CONF_WITHOUT_ABBA(control.conf);
    uint32_t before = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, before, 21, before, 1, 22, 1200, mtu, NULL);
    control.type->cc_on_acked(&control, &loss, before, 21, before, 1, 22, 1200, mtu, NULL);
    ok(cc.state.pico.abba.a == (float)(100. / before) && cc.state.pico.abba.b == 0);
    ok(fabs((double)cc.cwnd - before * 1.3) <= 1);
    ok(cc.cwnd > control.cwnd);

    /* Neither historical nor current app limitation permits acceleration. */
    before = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, mtu, 22, mtu, 0, 23, 1200, mtu, NULL);
    ok(cc.cwnd == before);
    if (cc.type->cc_update_cc_limited != NULL) {
        cc.type->cc_update_cc_limited(&cc, 0, 1200);
        cc.type->cc_on_acked(&cc, &loss, mtu, 23, mtu, 1, 24, 1300, mtu, NULL);
        ok(cc.cwnd == before);
        cc.type->cc_update_cc_limited(&cc, 1, 1300);
    }

    /* The next loss retains CUBIC's reduction, resets the model, and can be undone with its fractional credit. */
    cc.state.pico.abba.increase_remainder = 0.25;
    struct st_quicly_cc_abba_t saved = cc.state.pico.abba;
    loss.rtt.latest = 80;
    loss.rtt.smoothed = 115;
    cc.type->cc_on_lost(&cc, &loss, mtu, 24, 30, 1400, mtu);
    ok(cc.cwnd == (uint32_t)(before * QUICLY_BETA_LOSS));
    ok(cc.state.pico.abba.high.cwnd == before);
    ok(cc.state.pico.abba.high.rtt == 80);
    ok(cc.state.pico.abba.a == 0 && isnan(cc.state.pico.abba.b));
    ok(cc.state.pico.abba.increase_remainder == 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 25, 30, 1401, mtu);
    cc.type->cc_on_late_ack(&cc, 24, 1450);
    ok(cc.cwnd < before);
    cc.type->cc_on_late_ack(&cc, 25, 1451);
    ok(cc.cwnd == before);
    ok(memcmp(&cc.state.pico.abba, &saved, sizeof(saved)) == 0);

    /* ECN uses its own beta and cannot be undone by a late ACK. */
    quicly_rtt_init(&loss.rtt, &quicly_spec_context.egress[0].loss, 115);
    quicly_rtt_update(&loss.rtt, 80, 0, 1500);
    cc.type->cc_on_lost(&cc, &loss, 0, 30, 40, 1500, mtu);
    ok(cc.cwnd == (uint32_t)(before * QUICLY_BETA_ECN));
    cc.type->cc_on_late_ack(&cc, 30, 1550);
    ok(cc.cwnd == (uint32_t)(before * QUICLY_BETA_ECN));
    /* A new loss can arrive beyond recovery without an intervening ACK. */
    before = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 40, 50, 1600, mtu);
    ok(cc.state.pico.abba.high.cwnd == before);
    cc.type->cc_on_acked(&cc, &loss, 0, 50, 0, 1, 51, 1700, mtu, NULL);
    ok(cc.state.pico.abba.low.cwnd == cc.cwnd);
}

static void test_abba_ecn_floor(quicly_init_cc_t *init)
{
    uint32_t mtu = 1200, initcwnd = 100 * mtu;
    for (int no_sample = 0; no_sample != 2; ++no_sample) {
        for (int undo_loss = 0; undo_loss != 2; ++undo_loss) {
            quicly_cc_t cc, control;
            quicly_loss_t loss = {};
            init->cb(init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 1, 0), mtu, 0);
            quicly_rtt_init(&loss.rtt, &quicly_spec_context.egress[0].loss, 80);
            if (!no_sample) {
                quicly_rtt_update(&loss.rtt, 80, 0, 900);
                quicly_rtt_update(&loss.rtt, 120, 0, 901);
            }

            /* CE captures a floor of 80, distinct from latest (120) and SRTT (85), or the initial estimate without samples. */
            cc.type->cc_on_lost(&cc, &loss, 0, 10, 20, 1000, mtu);
            ok(cc.cwnd == initcwnd / 2);
            quicly_rtt_update(&loss.rtt, 60, 0, 1050);
            cc.type->cc_on_acked(&cc, &loss, mtu, 19, mtu, 1, 20, 1050, mtu, NULL);

            if (undo_loss) {
                /* Undoing a later packet loss must restore the fixed CE watermark. */
                cc.type->cc_on_lost(&cc, &loss, mtu, 20, 30, 1060, mtu);
                quicly_rtt_update(&loss.rtt, 50, 0, 1070);
                cc.type->cc_on_acked(&cc, &loss, mtu, 29, mtu, 1, 30, 1070, mtu, NULL);
                cc.type->cc_on_late_ack(&cc, 20, 1080);
                ok(cc.cwnd == initcwnd / 2);
            }

            if (!undo_loss) {
                quicly_rtt_update(&loss.rtt, 60, 0, 1090);
                cc.type->cc_on_acked(&cc, &loss, mtu, 19, mtu, 1, 20, 1090, mtu, NULL);
            }
            quicly_rtt_update(&loss.rtt, 70, 0, 1100);
            cc.type->cc_on_acked(&cc, &loss, 0, 30, 0, 1, 31, 1100, mtu, NULL);

            /* Flattening the fit between (120000, 80) and (60000, 70) about the low point maps RTT 74 to CWND 96000.
             * At CWND 120000, acknowledging 24000 bytes adds 24000 * (1 - 96000 / 120000) * 3/5 = 2880 bytes. */
            cc.cwnd = initcwnd;
            control = cc;
            control.conf = TEST_CC_CONF_WITHOUT_ABBA(control.conf);
            quicly_rtt_update(&loss.rtt, 74, 0, 1150);
            cc.type->cc_on_acked(&cc, &loss, 24000, 40, 24000, 1, 41, 1150, mtu, NULL);
            control.type->cc_on_acked(&control, &loss, 24000, 40, 24000, 1, 41, 1150, mtu, NULL);
            ok(abs((int)cc.cwnd - 122880) <= 1);
            ok(cc.cwnd > control.cwnd);

            /* A subsequent packet-loss event must resume tracking recovery minima. With a recovery minimum of 45
             * and exit RTT of 50, the model is horizontal, so growth at RTT 55 must match the unaccelerated policy. */
            uint32_t peak = cc.cwnd;
            cc.type->cc_on_lost(&cc, &loss, mtu, 41, 50, 1200, mtu);
            quicly_rtt_update(&loss.rtt, 45, 0, 1250);
            cc.type->cc_on_acked(&cc, &loss, mtu, 49, mtu, 1, 50, 1250, mtu, NULL);
            quicly_rtt_update(&loss.rtt, 50, 0, 1300);
            cc.type->cc_on_acked(&cc, &loss, 0, 50, 0, 1, 51, 1300, mtu, NULL);
            cc.cwnd = peak;
            control = cc;
            control.conf = TEST_CC_CONF_WITHOUT_ABBA(control.conf);
            quicly_rtt_update(&loss.rtt, 55, 0, 1350);
            cc.type->cc_on_acked(&cc, &loss, 24000, 51, 24000, 1, 52, 1350, mtu, NULL);
            control.type->cc_on_acked(&control, &loss, 24000, 51, 24000, 1, 52, 1350, mtu, NULL);
            ok(cc.cwnd == control.cwnd);
        }
    }
}

static void test_abba_ack_accounting(quicly_init_cc_t *init)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 8, .smoothed = 8, .minimum = 8}};
    uint32_t mtu = 1200, initcwnd = 100 * mtu;
    init->cb(init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 1, 0), mtu, 0);
    cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
    cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1100, mtu, NULL);
    /* Above the gain-cap threshold, isolate fractional-byte accounting with a gain of three fifths per byte ACKed. */
    cc.cwnd = initcwnd;
    uint32_t before = cc.cwnd;
    cc.state.pico.abba.a = 1.f / 1024;
    cc.state.pico.abba.b = 8;
    for (uint64_t pn = 21; pn != 26; ++pn) {
        cc.type->cc_on_acked(&cc, &loss, 1, pn, 1, 1, pn + 1, 1100, mtu, NULL);
        ok(cc.cwnd == before + (pn - 20) * 3 / 5);
    }

    /* Fast convergence changes the policy's Wmax but not the ABBA switching threshold. */
    cc.cwnd = 100000;
    if (cc.type == &quicly_cc_type_cubic) {
        cc.state.pico.cubic.cwnd_prior = 200000;
    } else {
        cc.state.pico.cuback.cwnd_prior = 200000;
    }
    loss.rtt.latest = 100;
    loss.rtt.smoothed = 117.5;
    cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 1200, mtu);
    ok(cc.type == &quicly_cc_type_cubic ? cc.state.pico.cubic.fast_convergence : cc.state.pico.cuback.fast_convergence);
    ok(cc.state.pico.abba.high.cwnd == 100000);
    cc.type->cc_on_acked(&cc, &loss, 0, 40, 0, 1, 41, 1300, mtu, NULL);
    cc.cwnd = 120000;
    loss.rtt.latest = 110;
    cc.type->cc_on_acked(&cc, &loss, 0, 41, 0, 1, 42, 1300, mtu, NULL);
    ok(cc.state.pico.abba.b > 0);
}

static void test_abba_cuback_partial_credit(void)
{
    uint32_t mtu = 1200, initcwnd = 100 * mtu;
    for (int crosses_interval = 0; crosses_interval != 2; ++crosses_interval) {
        quicly_cc_t cc, control;
        quicly_loss_t loss = {.rtt = {.latest = 8, .smoothed = 8, .minimum = 8}};
        quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, TEST_CC_CONF(initcwnd / mtu, 0, 1, 0), mtu, 0);
        cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
        cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1100, mtu, NULL);

        /* Seed model acceleration independently of the Cuback interval under test. */
        cc.state.pico.abba.a = 1.f / 1024;
        cc.state.pico.abba.b = 0;
        /* Begin partway through an interval. Exercise both an ACK staying within that interval and one completing it. */
        cc.state.pico.bytes_to_mtu_increase = crosses_interval ? mtu : 3 * mtu;
        uint32_t acked = crosses_interval ? 10 * mtu : 2 * mtu;
        control = cc;
        control.conf = TEST_CC_CONF_WITHOUT_ABBA(control.conf);
        cc.type->cc_on_acked(&cc, &loss, acked, 21, acked, 1, 22, 1100, mtu, NULL);
        control.type->cc_on_acked(&control, &loss, acked, 21, acked, 1, 22, 1100, mtu, NULL);
        ok(cc.cwnd > control.cwnd);
        uint32_t remaining = control.state.pico.bytes_to_mtu_increase;
        ok(remaining > 1);
        ok(cc.state.pico.bytes_to_mtu_increase == remaining);

        /* Once acceleration closes, the retained credit completes an ordinary MTU increase at exactly the original boundary. */
        loss.rtt.latest = 128;
        uint32_t before = cc.cwnd;
        cc.type->cc_on_acked(&cc, &loss, remaining - 1, 22, remaining - 1, 1, 23, 1100, mtu, NULL);
        ok(cc.cwnd == before);
        ok(cc.state.pico.bytes_to_mtu_increase == 1);
        cc.type->cc_on_acked(&cc, &loss, 1, 23, 1, 1, 24, 1100, mtu, NULL);
        ok(cc.cwnd == before + mtu);

        /* A spurious loss must restore the same pending interval as well as the model. */
        remaining = cc.state.pico.bytes_to_mtu_increase;
        cc.type->cc_on_lost(&cc, &loss, mtu, 30, 40, 1200, mtu);
        cc.type->cc_on_late_ack(&cc, 30, 1250);
        ok(cc.cwnd == before + mtu);
        ok(cc.state.pico.bytes_to_mtu_increase == remaining);
    }
}

static void test_abba_startup_and_switch(quicly_init_cc_t *init)
{
    uint32_t mtu = 1200, initcwnd = 100 * mtu;
    for (int rapid = 0; rapid != 2; ++rapid) {
        quicly_cc_t cc, control;
        quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 20}};
        init->cb(init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 1, rapid), mtu, 0);
        init->cb(init, &control, TEST_CC_CONF(initcwnd / mtu, 1, 0, rapid), mtu, 0);
        if (!rapid) {
            cc.type->cc_jumpstart(&cc, initcwnd * 2, 5);
            control.type->cc_jumpstart(&control, initcwnd * 2, 5);
        }
        cc.type->cc_on_lost(&cc, &loss, mtu, 10, 20, 1000, mtu);
        control.type->cc_on_lost(&control, &loss, mtu, 10, 20, 1000, mtu);
        cc.type->cc_on_acked(&cc, &loss, initcwnd, 19, initcwnd, 1, 20, 1050, mtu, NULL);
        control.type->cc_on_acked(&control, &loss, initcwnd, 19, initcwnd, 1, 20, 1050, mtu, NULL);
        ok(cc.cwnd == control.cwnd);
        cc.type->cc_on_acked(&cc, &loss, 0, 20, 0, 1, 21, 1100, mtu, NULL);
        control.type->cc_on_acked(&control, &loss, 0, 20, 0, 1, 21, 1100, mtu, NULL);
        ok(cc.cwnd == control.cwnd);
        ok(cc.state.pico.abba.low.cwnd == cc.cwnd);
        cc.type->cc_on_late_ack(&cc, 10, 1150);
        ok(cc.num_loss_episodes == 0 && cc.ssthresh == UINT32_MAX);
        ok(cc.state.pico.abba.high.cwnd == 0);
        ok(cc.state.pico.abba.a == 0 && isnan(cc.state.pico.abba.b));
    }

    /* Switching policies preserves the configured flag and resets stale model state. */
    for (quicly_cc_type_t **type = quicly_cc_all_types; *type != NULL; ++type) {
        quicly_cc_t cc;
        init->cb(init, &cc, TEST_CC_CONF(initcwnd / mtu, 1, 1, 0), mtu, 0);
        quicly_cc_type_t *original = cc.type;
        cc.cwnd_exiting_slow_start = initcwnd;
        cc.ssthresh = cc.cwnd;
        ok((*type)->cc_switch(&cc));
        ok(cc.type == *type && cc.conf->normalize_mtu && cc.conf->abba);
        ok(original->cc_switch(&cc));
        ok(cc.type == original && cc.conf->normalize_mtu && cc.conf->abba);
        ok(cc.state.pico.abba.high.cwnd == 0);
    }
}

static void test_abba(void)
{
    subtest("model", test_abba_model);
    subtest("fit-growth", test_abba_fit_growth);
    subtest("minimum-rtt-span", test_abba_min_rtt_span);
    subtest("proportional-switch", test_abba_proportional_switch);
    subtest("minimum-at-larger-window", test_abba_minimum_at_larger_window);
    subtest("growth", test_abba_growth);
    subtest("gain-cap", test_abba_gain_cap);
    subtest("cubic-gain-cap", test_abba_gain_cap_policy, &quicly_cc_cubic_init);
    subtest("cuback-gain-cap", test_abba_gain_cap_policy, &quicly_cc_cuback_init);
    subtest("model-shortfall", test_abba_model_shortfall);
    subtest("float-precision", test_abba_float_precision);
    subtest("cubic-lifecycle", test_abba_lifecycle, &quicly_cc_cubic_init);
    subtest("cuback-lifecycle", test_abba_lifecycle, &quicly_cc_cuback_init);
    subtest("cubic-ecn-floor", test_abba_ecn_floor, &quicly_cc_cubic_init);
    subtest("cuback-ecn-floor", test_abba_ecn_floor, &quicly_cc_cuback_init);
    subtest("cubic-ack-accounting", test_abba_ack_accounting, &quicly_cc_cubic_init);
    subtest("cuback-ack-accounting", test_abba_ack_accounting, &quicly_cc_cuback_init);
    subtest("cuback-partial-credit", test_abba_cuback_partial_credit);
    subtest("cubic-startup-and-switch", test_abba_startup_and_switch, &quicly_cc_cubic_init);
    subtest("cuback-startup-and-switch", test_abba_startup_and_switch, &quicly_cc_cuback_init);
}

static void test_rapid_start_fractional_rtt(void)
{
    struct st_quicly_cc_rapid_start_t rs;
    quicly_rtt_t rtt;
    quicly_rtt_init(&rtt, &quicly_spec_context.egress[0].loss, 16.25f);
    quicly_rtt_update(&rtt, 16.25f, 0, 1);
    quicly_cc_init_rapid_start(&rs, 21);
    quicly_rtt_update(&rtt, 20.5f, 0, 21);
    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* 20.5ms is above the 20.25ms threshold */
    quicly_rtt_update(&rtt, 20.125f, 0, 21);
    ok(quicly_cc_rapid_start_use_3x(&rs, &rtt));
    quicly_rtt_update(&rtt, 20.5f, 0, 41);
    ok(!quicly_cc_rapid_start_use_3x(&rs, &rtt)); /* the lower fractional sample has expired */
}

static void init_prague(quicly_cc_t *cc, uint32_t mtu)
{
    /* static, as the congestion controller retains the pointer */
    static const quicly_cc_conf_t conf = {.initcwnd_packets = 100};
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, cc, &conf, mtu, 0);
}

/* ECN counters left unchanged by an ACK on an L4S path */
static const quicly_cc_ecn_counts_t no_ecn_counts = {0};

static void l4s_acked(quicly_cc_t *cc, quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint64_t next_pn, int64_t now,
                      uint32_t mtu, uint64_t acked, uint64_t ce)
{
    cc->type->cc_on_acked(cc, loss, bytes, largest_acked, bytes, 1, next_pn, now, mtu, &(quicly_cc_ecn_counts_t){acked, ce});
    if (ce != 0)
        cc->type->cc_on_lost(cc, loss, 0, largest_acked, next_pn, now, mtu);
}

static void test_prague_estimator(void)
{
    struct st_quicly_cc_prague_t prague;

    prague_stop(&prague);
    ok(!prague_is_running(&prague) && isnan(prague.alpha));

    /* Once started, the first sample spans a virtual RTT and initializes alpha directly. */
    prague_start(&prague, 100, 0, QUICLY_BETA_ECN);
    ok(prague_is_running(&prague) && prague.update_at == 100 && isnan(prague.alpha) && prague.beta == (float)QUICLY_BETA_ECN);
    prague_on_acked(&prague, 100, 50, &(quicly_cc_ecn_counts_t){12, 3});
    ok(isnan(prague.alpha));
    prague_on_acked(&prague, 100, 100, &(quicly_cc_ecn_counts_t){4, 1});
    ok(prague.alpha == 0.25 && prague.update_at == 200);

    /* Subsequent samples are applied once per virtual RTT, with gain 1/16. */
    prague_on_acked(&prague, 100, 200, &(quicly_cc_ecn_counts_t){16, 0});
    float alpha = 0.25 * 15 / 16;
    ok(prague.alpha == alpha && prague.update_at == 300);

    /* The virtual RTT is at least 25ms. */
    prague_on_acked(&prague, 5, 300, &(quicly_cc_ecn_counts_t){16, 16});
    alpha = (float)(alpha + (1 - (double)alpha) / 16);
    ok(prague.alpha == alpha && prague.update_at == 325);

    /* Silence is not an unmarked sample. */
    prague_on_acked(&prague, 5, 1000, &no_ecn_counts);
    ok(prague.alpha == alpha);

    prague_stop(&prague);
    ok(!prague_is_running(&prague) && isnan(prague.alpha) && isnan(prague.beta));
}

static void test_prague_grow(void)
{
    struct st_quicly_cc_prague_t prague = {.alpha = 1};
    uint32_t mtu = 1200, cwnd = 100 * mtu;

    /* With SRTT above the virtual RTT, one MTU is added per CWND acknowledged, carrying the fraction. */
    ok(prague_grow(&prague, cwnd, 0, 100, cwnd / 2, mtu, &no_ecn_counts) == cwnd);
    ok(prague.increase_carry == 0.5);
    ok(prague_grow(&prague, cwnd, 0, 100, cwnd / 2, mtu, &no_ecn_counts) == cwnd + mtu);
    ok(prague.increase_carry == 0);
    ok(prague_grow(&prague, cwnd, 0, 100, 3 * cwnd, mtu, &no_ecn_counts) == cwnd + 3 * mtu);

    /* Only unmarked bytes count, estimated from the packet ratio. */
    ok(prague_grow(&prague, cwnd, 0, 100, cwnd, mtu, &(quicly_cc_ecn_counts_t){4, 2}) == cwnd);
    ok(prague.increase_carry == 0.5);
    prague.increase_carry = 0;

    /* At 1/5 of the virtual RTT, 25 CWNDs are needed per MTU. */
    ok(prague_grow(&prague, cwnd, 0, 5, 24 * cwnd, mtu, &no_ecn_counts) == cwnd);
    ok(prague_grow(&prague, cwnd, 0, 5, 2 * cwnd, mtu, &no_ecn_counts) == cwnd + mtu);
    prague.increase_carry = 0;

    /* With MTU normalization, the bytes needed per increase are proportional to the actual MTU. */
    ok(prague_grow(&prague, cwnd, 1, 100, cwnd / 2, mtu / 2, &no_ecn_counts) == cwnd + mtu / 2);
}

static void test_prague_growth(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100}};
    uint32_t mtu = 1200;
    init_prague(&cc, mtu);

    /* The first CE exits startup like classic CE does; the estimator does not run until the recovery ends. */
    l4s_acked(&cc, &loss, 0, 90, 100, 1000, mtu, 10, 1);
    ok(cc.cwnd == 50 * mtu && cc.ssthresh == cc.cwnd);
    ok(!prague_is_running(&cc.state.pico.prague) && cc.state.pico.cuback.by_ecn);
    ok(cc.recovery_end == 100);
    ok(cc.num_loss_episodes == 1 && cc.num_ecn_loss_episodes == 1 && cc.num_prague_reductions == 0);
    ok(cc.cwnd_exiting_slow_start == 100 * mtu);
    l4s_acked(&cc, &loss, 25 * mtu, 99, 100, 1010, mtu, 25, 1);
    ok(cc.cwnd == 50 * mtu && cc.num_loss_episodes == 1 && cc.num_ecn_loss_episodes == 1);

    /* Past recovery, the estimator starts, and Prague adds one MTU per CWND acknowledged (as SRTT is above the virtual RTT),
     * carrying the fraction. */
    cc.type->cc_on_acked(&cc, &loss, 25 * mtu, 100, 50 * mtu, 1, 200, 1100, mtu, &no_ecn_counts);
    ok(prague_is_running(&cc.state.pico.prague) && cc.state.pico.prague.update_at == 1200);
    ok(cc.cwnd == 50 * mtu && cc.state.pico.prague.increase_carry == 0.5);
    cc.type->cc_on_acked(&cc, &loss, 25 * mtu, 101, 50 * mtu, 1, 200, 1110, mtu, &no_ecn_counts);
    ok(cc.cwnd == 51 * mtu && cc.state.pico.prague.increase_carry == 0);
    cc.type->cc_on_acked(&cc, &loss, 17 * mtu, 102, 51 * mtu, 1, 200, 1120, mtu, &no_ecn_counts);
    double carry = cc.state.pico.prague.increase_carry;
    ok(cc.cwnd == 51 * mtu && fabs(carry - 1. / 3) < 1e-9);

    /* CE is ignored until the first sample completes. */
    uint32_t before = cc.cwnd, cwnd_prior = cc.state.pico.cuback.cwnd_prior;
    l4s_acked(&cc, &loss, 0, 150, 200, 1150, mtu, 10, 1);
    ok(cc.cwnd == before && cc.num_prague_reductions == 0);

    /* Then, CE reduces by alpha / 2 without starting a loss episode or entering recovery; the carried fraction is retained. */
    l4s_acked(&cc, &loss, 0, 160, 200, 1200, mtu, 10, 1);
    ok(cc.state.pico.prague.alpha == 0.1f && cc.state.pico.prague.beta == 1 - 0.1f / 2);
    ok(cc.cwnd == (uint32_t)(before * (double)cc.state.pico.prague.beta));
    ok(cc.recovery_end == 100 && cc.num_loss_episodes == 1 && cc.num_ecn_loss_episodes == 1 && cc.num_prague_reductions == 1);
    ok(cc.state.pico.cuback.cwnd_prior == cwnd_prior);
    ok(cc.state.pico.prague.increase_carry == carry);

    /* Growth continues in CWR state, driven only by unmarked bytes, while CE remains suppressed until the virtual RTT has
     * passed. */
    before = cc.cwnd;
    l4s_acked(&cc, &loss, 2 * mtu, 190, 200, 1210, mtu, 2, 1);
    ok(cc.cwnd == before && cc.num_loss_episodes == 1);
    ok(fabs(cc.state.pico.prague.increase_carry - (carry + (double)mtu / before)) < 1e-9);
    uint32_t bytes = (uint32_t)ceil((1 - cc.state.pico.prague.increase_carry) * before);
    cc.type->cc_on_acked(&cc, &loss, bytes, 191, bytes, 1, 200, 1220, mtu, &no_ecn_counts);
    ok(cc.cwnd == before + mtu);
    before = cc.cwnd;
    l4s_acked(&cc, &loss, 0, 201, 300, 1290, mtu, 1, 1);
    ok(cc.cwnd == before && cc.num_loss_episodes == 1 && cc.num_prague_reductions == 1);
    l4s_acked(&cc, &loss, 0, 202, 300, 1300, mtu, 1, 1);
    ok(cc.cwnd == before && cc.num_prague_reductions == 1); /* suppression is inclusive of `ignore_ce_until` */
    l4s_acked(&cc, &loss, 0, 203, 300, 1301, mtu, 1, 1);
    ok(cc.cwnd < before && cc.num_loss_episodes == 1 && cc.num_ecn_loss_episodes == 1 && cc.num_prague_reductions == 2);
}

static void test_prague_loss(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100}};
    uint32_t mtu = 1200;
    init_prague(&cc, mtu);
    /* Exit startup by CE, then take the first sample past its recovery, during which CE is ignored. */
    l4s_acked(&cc, &loss, 0, 9, 10, 0, mtu, 1, 1);
    l4s_acked(&cc, &loss, 0, 20, 30, 100, mtu, 15, 0);
    l4s_acked(&cc, &loss, 0, 30, 50, 150, mtu, 8, 4);
    l4s_acked(&cc, &loss, 0, 40, 50, 200, mtu, 8, 0);
    double alpha = cc.state.pico.prague.alpha;
    ok(alpha == 0.25 && cc.num_prague_reductions == 0);

    /* Loss selects CUBACK growth, leaving alpha intact; the estimator keeps running during loss recovery. */
    uint32_t before = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 45, 50, 210, mtu);
    ok(cc.cwnd == (uint32_t)(before * QUICLY_BETA_LOSS));
    ok(!cc.state.pico.cuback.by_ecn && cc.state.pico.prague.alpha == alpha);
    ok(cc.state.pico.cuback.cwnd_prior == before && !cc.state.pico.cuback.fast_convergence);
    ok(cc.recovery_end == 50);
    uint32_t reduced = cc.cwnd;
    l4s_acked(&cc, &loss, 0, 49, 60, 300, mtu, 16, 0);
    ok(cc.state.pico.prague.alpha == (float)(alpha * 15 / 16));
    cc.type->cc_on_acked(&cc, &loss, mtu, 49, reduced, 1, 60, 300, mtu, &no_ecn_counts);
    ok(cc.cwnd == reduced);

    /* Undo restores the growth policy and window, but does not roll back newer alpha samples. */
    cc.type->cc_on_late_ack(&cc, 45, 301);
    ok(cc.cwnd == before && cc.state.pico.cuback.by_ecn);
    ok(cc.state.pico.prague.alpha == (float)(alpha * 15 / 16));

    cc.type->cc_on_lost(&cc, &loss, mtu, 60, 70, 310, mtu);
    cc.type->cc_on_acked(&cc, &loss, 0, 70, 0, 1, 80, 320, mtu, &no_ecn_counts);
    ok(calc_bytes_per_mtu_increase(&cc, &loss, mtu) ==
       cuback_bytes_per_mtu_increase(&cc.state.pico.cuback, cc.cwnd, cc.ssthresh, mtu, mtu));
    before = cc.cwnd;
    alpha = cc.state.pico.prague.alpha;
    l4s_acked(&cc, &loss, 0, 71, 80, 330, mtu, 1, 1);
    ok(cc.state.pico.prague.beta == (float)(1 - alpha / 2));
    ok(cc.cwnd == (uint32_t)(before * (double)cc.state.pico.prague.beta));
    ok(cc.state.pico.cuback.by_ecn);
    before = cc.cwnd;
    cc.type->cc_on_late_ack(&cc, 60, 331);
    ok(cc.cwnd == before); /* cannot undo intervening CE */

    /* A loss following the Prague reduction is acted on as a new episode, selecting CUBACK growth
     * and leaving alpha intact. */
    uint32_t num_loss_episodes = cc.num_loss_episodes, num_ecn_loss_episodes = cc.num_ecn_loss_episodes;
    cc.type->cc_on_lost(&cc, &loss, mtu, 72, 85, 332, mtu);
    ok(cc.cwnd == (uint32_t)(before * QUICLY_BETA_LOSS));
    ok(cc.recovery_end == 85);
    ok(cc.num_loss_episodes == num_loss_episodes + 1 && cc.num_ecn_loss_episodes == num_ecn_loss_episodes);
    ok(!cc.state.pico.cuback.by_ecn);
    ok(cc.state.pico.prague.alpha == alpha);
    /* Once CUBACK growth is selected, a further loss in the new recovery period is ignored as usual. */
    before = cc.cwnd;
    cc.type->cc_on_lost(&cc, &loss, mtu, 73, 86, 333, mtu);
    ok(cc.cwnd == before && cc.num_loss_episodes == num_loss_episodes + 1);
    l4s_acked(&cc, &loss, 0, 81, 90, 450, mtu, 1, 1);
    ok(!cc.state.pico.cuback.by_ecn); /* feedback from before loss does not override loss recovery */
}

static void test_prague_recovery_exit(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100}};
    uint32_t mtu = 1200;
    init_prague(&cc, mtu);

    /* Exit startup by CE; Prague does not run during the recovery, in which CE is suppressed as usual. */
    l4s_acked(&cc, &loss, 0, 9, 10, 0, mtu, 1, 1);
    ok(cc.recovery_end == 10 && !prague_is_running(&cc.state.pico.prague));
    uint32_t cwnd = cc.cwnd;
    l4s_acked(&cc, &loss, 0, 9, 10, 50, mtu, 1, 1);
    ok(cc.cwnd == cwnd && !prague_is_running(&cc.state.pico.prague));

    /* The ACK frame observing recovery exit starts Prague; its CE, which may be stale, is ignored as alpha is yet to be sampled, as
     * is CE within the same millisecond. */
    l4s_acked(&cc, &loss, 0, 12, 20, 100, mtu, 2, 1);
    ok(prague_is_running(&cc.state.pico.prague) && isnan(cc.state.pico.prague.alpha));
    ok(cc.cwnd == cwnd && cc.num_prague_reductions == 0);
    l4s_acked(&cc, &loss, 0, 13, 20, 100, mtu, 1, 1);
    ok(cc.cwnd == cwnd && cc.num_prague_reductions == 0);

    /* Past the recovery that ended startup, CE is also ignored until the first sample completes. */
    l4s_acked(&cc, &loss, 0, 14, 20, 101, mtu, 1, 1);
    ok(cc.cwnd == cwnd && cc.num_prague_reductions == 0);
    l4s_acked(&cc, &loss, 0, 15, 20, 200, mtu, 1, 1);
    ok(cc.state.pico.prague.alpha == 1);
    ok(cc.cwnd < cwnd && cc.num_prague_reductions == 1);

    /* Loss recovery suppresses CE likewise, until its exit is observed; the estimator keeps running. */
    cc.type->cc_on_lost(&cc, &loss, mtu, 16, 30, 400, mtu);
    ok(cc.recovery_end == 30 && cc.state.pico.prague.ignore_ce_until == INFINITY);
    cwnd = cc.cwnd;
    l4s_acked(&cc, &loss, 0, 25, 30, 1000, mtu, 1, 1);
    ok(cc.cwnd == cwnd && cc.num_prague_reductions == 1);
    l4s_acked(&cc, &loss, 0, 31, 40, 1100, mtu, 2, 1);
    ok(cc.state.pico.prague.ignore_ce_until == 1100);
    ok(cc.cwnd == cwnd && cc.num_prague_reductions == 1);
    l4s_acked(&cc, &loss, 0, 32, 40, 1101, mtu, 1, 1);
    ok(cc.cwnd < cwnd && cc.num_prague_reductions == 2);
}

static void test_prague_abba(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {};
    uint32_t mtu = 1200;
    quicly_cc_cuback_init.cb(&quicly_cc_cuback_init, &cc, TEST_CC_CONF(100, 0, 1, 0), mtu, 0);
    quicly_rtt_init(&loss.rtt, &quicly_spec_context.egress[0].loss, 100);
    quicly_rtt_update(&loss.rtt, 100, 0, 0);

    /* Exit startup by CE, then reduce by Prague with alpha = 0.1 (i.e., beta = 0.95) once the first sample past its recovery
     * completes. */
    l4s_acked(&cc, &loss, 0, 9, 10, 0, mtu, 1, 1);
    l4s_acked(&cc, &loss, 0, 19, 30, 100, mtu, 10, 0);
    uint32_t high = cc.cwnd;
    l4s_acked(&cc, &loss, 0, 20, 30, 200, mtu, 10, 1);
    ok(cc.num_prague_reductions == 1);

    /* The Prague reduction starts a new ABBA period at the window before the reduction. */
    ok(cc.state.pico.abba.high.cwnd == high);

    /* Prague growth to 1.07 * high, which is beyond high * (2 - 0.95) but not beyond high * (2 - QUICLY_BETA_ECN), makes the model
     * proportional. */
    uint32_t reduced = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 6 * reduced, 21, 6 * reduced, 1, 40, 210, mtu, &no_ecn_counts);
    cc.type->cc_on_acked(&cc, &loss, cc.cwnd, 22, cc.cwnd, 1, 40, 220, mtu, &no_ecn_counts);
    ok(cc.state.pico.abba.b == 0);

    /* With RTT staying flat, Prague growth beyond the window at which the model became proportional is accelerated. */
    uint32_t cwnd = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 10 * mtu, 23, 10 * mtu, 1, 40, 230, mtu, &no_ecn_counts);
    ok(cc.cwnd > cwnd && cc.cwnd_increase_accel == cc.cwnd - cwnd);
}

static void test_prague_ecn_disabled(void)
{
    quicly_cc_t cc;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100}};
    uint32_t mtu = 1200;
    init_prague(&cc, mtu);
    /* Exit startup by CE, then reduce by Prague once the first sample past its recovery completes. */
    l4s_acked(&cc, &loss, 0, 9, 10, 0, mtu, 1, 1);
    l4s_acked(&cc, &loss, 0, 19, 30, 190, mtu, 1, 0);
    l4s_acked(&cc, &loss, 0, 20, 30, 200, mtu, 1, 1);
    l4s_acked(&cc, &loss, 0, 21, 30, 290, mtu, 1, 1);
    ok(cc.num_prague_reductions == 1 && in_prague_ca(&cc));

    /* Once ECN is disabled, the estimator stops and CUBACK growth resumes. */
    uint32_t before = cc.cwnd;
    cc.type->cc_on_acked(&cc, &loss, 0, 22, before, 1, 30, 300, mtu, NULL);
    ok(!prague_is_running(&cc.state.pico.prague) && isnan(cc.state.pico.prague.alpha));
    ok(!cc.state.pico.cuback.by_ecn && !in_prague_ca(&cc));
    ok(cc.cwnd == before);
    cc.type->cc_on_acked(&cc, &loss, mtu, 23, before, 1, 30, 310, mtu, NULL);
    ok(cc.state.pico.prague.increase_carry == 0);
    ok(calc_bytes_per_mtu_increase(&cc, &loss, mtu) ==
       cuback_bytes_per_mtu_increase(&cc.state.pico.cuback, cc.cwnd, cc.ssthresh, mtu, mtu));

    /* Subsequent congestion signals receive the classic response. */
    before = cc.cwnd;
    uint32_t num_loss_episodes = cc.num_loss_episodes;
    cc.type->cc_on_lost(&cc, &loss, 0, 25, 40, 320, mtu);
    ok(cc.num_loss_episodes == num_loss_episodes + 1 && cc.num_prague_reductions == 1);
    ok(cc.cwnd == (uint32_t)(before * (QUICLY_USE_ABE ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS)));
}

void test_cc(void)
{
    subtest("prague-estimator", test_prague_estimator);
    subtest("prague-grow", test_prague_grow);
    subtest("prague-growth", test_prague_growth);
    subtest("prague-loss", test_prague_loss);
    subtest("prague-recovery-exit", test_prague_recovery_exit);
    subtest("prague-abba", test_prague_abba);
    subtest("prague-ecn-disabled", test_prague_ecn_disabled);
    subtest("fast-cbrt", test_fast_cbrt);
    subtest("rapid-start", test_rapid_start);
    subtest("abba", test_abba);
    subtest("rapid-start-fractional-rtt", test_rapid_start_fractional_rtt);
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
