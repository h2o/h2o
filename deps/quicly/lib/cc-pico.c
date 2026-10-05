/*
 * Copyright (c) 2019-2026 Fastly, Janardhan Iyengar, Kazuho Oku
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
#include <float.h>
#include <math.h>
#include <stdlib.h>
#include "quicly/pacer.h"
#include "quicly/cc.h"
#include "quicly.h"

/**
 * C of Cubic
 */
#define QUICLY_CUBIC_C 0.4

/**
 * Fast approximation of cbrt(). The input is reduced to a mantissa in [1, 2), to which a fourth-degree polynomial is applied.
 * The polynomial's value and slope join smoothly at powers of two; continuity of the slope is important to Cuback, which
 * subtracts the inverse curve at adjacent CWNDs to calculate each per-MTU increase. The maximum relative error of the result is
 * about 3.5e-5, which becomes about 1.1e-4 when K is cubed by Cubic. The relative slope error is below 8.5e-4, keeping Cuback's
 * per-MTU inverse-curve calculation accurate to roughly 0.1%.
 *
 * Throughput on Zen 3 is ~9 clocks per call. Cuback currently invokes cbrt 3 times for each CWND increment, therefore if CWND grows
 * by one MTU per MTU acknowledged (i.e., the worst case), the overhead relative to QUIC packet encryption becomes ~3% (throughput
 * of an optimized aes-gcm-128 pipeline is 1.6 bytes / clock). Ordinary CWND grows much more slowly, making the overhead negligible.
 *
 * Inputs whose double representation is not IEEE 754 binary64, as well as subnormal and non-finite values, are handled by libc's
 * cbrt().
 */
static double fast_cbrt(double x)
{
#define DBL2BITS(x)                                                                                                                \
    (((union {                                                                                                                     \
         double f;                                                                                                                 \
         uint64_t u;                                                                                                               \
     }){x})                                                                                                                        \
         .u)
#define BITS2DBL(x)                                                                                                                \
    (((union {                                                                                                                     \
         uint64_t u;                                                                                                               \
         double f;                                                                                                                 \
     }){x})                                                                                                                        \
         .f)

    if (!(FLT_RADIX == 2 && DBL_MANT_DIG == 53 && DBL_MIN_EXP == -1021 && DBL_MAX_EXP == 1024 &&
          sizeof(double) == sizeof(uint64_t) && DBL2BITS(1.0) == UINT64_C(0x3ff0000000000000) &&
          DBL2BITS(-1.0) == UINT64_C(0xbff0000000000000)))
        return cbrt(x);

    uint64_t u = DBL2BITS(x);
    uint64_t abs_u = u & UINT64_C(0x7fffffffffffffff);
    uint64_t exp = abs_u >> 52;

    if (abs_u == 0)
        return x;
    if (exp == 0 || exp == 0x7ff)
        return cbrt(x);

    int e = (int)exp - 1023;
    int q = e / 3;
    int r = e - 3 * q;
    if (r < 0) {
        r += 3;
        --q;
    }

    double m = BITS2DBL((abs_u & UINT64_C(0x000fffffffffffff)) | (UINT64_C(1023) << 52));
    double y = 0.5066598330689034 +
               m * (0.7177663288981584 + m * (-0.2988437245358902 + m * (0.08469719299100167 + m * -0.010279630422175424)));

    static const double cbrt2_to_r[3] = {1.0, 1.2599210498948731648, 1.5874010519681994748};
    double two_to_q = BITS2DBL((uint64_t)(q + 1023) << 52);

    y *= cbrt2_to_r[r] * two_to_q;
    return (u >> 63) ? -y : y;

#undef DBL2BITS
#undef BITS2DBL
}

#define CALC_FRIENDLY_ALPHA(Breno, Bcubic) (((1 + (Breno)) * (1 - (Bcubic))) / ((1 - (Breno)) * (1 + (Bcubic))))
/* Loss follows RFC 9438's AIMD(1, 0.5) friendliness. For ABE, match Reno's beta_ecn=0.8 with Cubic's beta_ecn=0.85. */
static const double cubic_friendly_alpha[2] = {CALC_FRIENDLY_ALPHA(0.5, QUICLY_BETA_LOSS),
                                               CALC_FRIENDLY_ALPHA(0.8, QUICLY_BETA_ECN)};
#undef CALC_FRIENDLY_ALPHA

static double cubic_fast_convergence_w_max(double cwnd_prior, double cwnd_epoch)
{
    /* Equivalent to (1 + beta) / 2 * cwnd_prior when cwnd_epoch is beta * cwnd_prior, including with ABE. */
    return (cwnd_prior + cwnd_epoch) / 2;
}

/**
 * Calculates Wmax after Rapid Start.
 *
 * Traditional Slow Start overshoots the path BDP by roughly 2x before detecting congestion, and Cubic retains that loss-time CWND
 * as Wmax, its BDP estimate. When there is no competing flow, doing so overflows the bottleneck once again almost immediately and
 * causes head-of-line blocking. However, if there are competing flows, this overshoot helps the new flow increase its share of
 * bottleneck bandwidth rapidly.
 *
 * Rapid Start prevents the stated downside by obtaining a good BDP estimate and by adjusting CWND to beta * estimate, but does not
 * provide guidance on how fast the Cubic curve should grow. We set Wmax to 2 * estimate, the same value that Cubic with traditional
 * Slow Start adopts.
 */
static uint32_t cubic_post_rapid_start_wmax(uint32_t cwnd_epoch, int by_ecn)
{
    double beta = by_ecn ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS;
    double w_max = 2. * cwnd_epoch / beta;
    return w_max < UINT32_MAX ? w_max : UINT32_MAX;
}

/**
 * Calculates the increase ratio to be used in congestion avoidance phase.
 */
static uint32_t pico_bytes_per_mtu_increase(uint32_t cwnd, double rtt, uint32_t mtu, double beta)
{
    /* Reno: CWND size after reduction */
    uint32_t reno = cwnd * beta;

    /* Cubic: Cubic reaches original CWND (i.e., Wmax) in K seconds, therefore:
     *   amount_to_increase = (1 - beta) * Wmax
     *   amount_to_be_acked = K * Wmax / RTT_at_Wmax
     * where
     *   K = ((1 - beta) / 0.4 * Wmax / MTU)^(1/3)
     *
     * Hence:
     *   bytes_per_mtu_increase = amount_to_be_acked / amount_to_increase * MTU
     *     = (K * Wmax / RTT_at_Wmax) / ((1 - beta) * Wmax) * MTU
     *     = K * MTU / ((1 - beta) * RTT_at_Wmax)
     *
     * In addition, we have to adjust the value to take fast convergence into account. When competition causes congestion peaks to
     * decline gradually, fast-convergence and normal epochs are expected to alternate: a peak below the retained Wmax triggers fast
     * convergence, while the resulting Wmax of (1 + beta) / 2 makes the next peak a normal event unless it declines further.
     *
     * When fast convergence occurs, Wmax becomes (1 + beta) / 2 * Wmax while cwnd_epoch remains beta * Wmax. The modified K (K')
     * is therefore:
     *
     *   K' = (((1 - beta) / 2) / 0.4 * Wmax / MTU)^(1/3) = 0.5^(1/3) * K
     *
     * where K' represents the time to reach (1 + beta) / 2 * Wmax. As the cubic curve is point symmetric around that point,
     * reaching the original Wmax takes 2 * K'. Amortizing one fast-convergence period and one normal period gives:
     *
     *   bytes_per_mtu_increase = ((1 + 0.5^(1/3) * 2) / 2) * K * MTU / ((1 - beta) * RTT_at_Wmax)
     *                          ~= 1.293700525984 * K * MTU / ((1 - beta) * RTT_at_Wmax)
     */
    double cubic = 1.293700525984 / (1 - beta) * 1000 * fast_cbrt((1 - beta) / 0.4 * cwnd / mtu) / rtt * mtu;

    double bytes = reno < cubic ? reno : cubic;
    return bytes < 1 ? 1 : bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
}

/**
 * Returns the number of bytes sent when the Cuback CWND reaches `w`.
 *
 * Cuback is an ACK-driven variant of Cubic. It traces the same two curves as Cubic - W_cubic and the Reno-friendly W_reno shown
 * below - but drives them by the bytes being acked rather than by the clock.
 *
 * Let Tr be the time at which the Reno-friendly curve reaches cwnd_prior:
 *
 *   Tr = sum(w, w = Wepoch .. cwnd_prior - MSS, step MSS) / (alpha * bandwidth)
 *      = (cwnd_prior - Wepoch) * (cwnd_prior + Wepoch - MSS) / (2 * alpha * MSS * bandwidth)
 *
 * The Cubic curve and the continuous interpolation through Reno's MSS-spaced points are:
 *
 *   W_cubic(t) = C * MSS * (t - K)^3 + Wmax
 *   W_reno(t)  = W_reno_pre(t),                                                      t <= Tr
 *                W_reno_post(t),                                                     t > Tr
 *
 * Each Reno branch is obtained by inverting the sum of its MSS-spaced ACK thresholds:
 *
 *   bandwidth * t = sum(w, w = Wepoch .. W_reno_pre(t) - MSS, step MSS) / alpha
 *   W_reno_pre(t) = (MSS + sqrt((2 * Wepoch - MSS)^2 + 8 * alpha * MSS * bandwidth * t)) / 2
 *
 *   bandwidth * (t - Tr) = sum(w, w = cwnd_prior .. W_reno_post(t) - MSS, step MSS)
 *   W_reno_post(t) = (MSS + sqrt((2 * cwnd_prior - MSS)^2 + 8 * MSS * bandwidth * (t - Tr))) / 2
 *
 * As both curves are monotonically increasing, CWND - being their maximum - is monotonically increasing as well. Therefore, the
 * amount sent can be recovered from CWND, the inverse of a maximum being the minimum of the inverses. Inverting the curves gives
 * the time at which each reaches `w`. Multiplying that time by bandwidth converts the result to bytes sent since the epoch began:
 *
 *   bytes_cubic(w) = bandwidth * (K + cbrt((w - Wmax) / (C * MSS)))
 *   bytes_reno(w)  = (w - Wepoch) * (w + Wepoch - MSS) / (2 * alpha * MSS),          w <= cwnd_prior
 *                    (cwnd_prior - Wepoch) * (cwnd_prior + Wepoch - MSS) / (2 * alpha * MSS)
 *                      + (w - cwnd_prior) * (w + cwnd_prior - MSS) / (2 * MSS),      w > cwnd_prior
 *   bytes_sent(w)  = min(bytes_cubic(w), bytes_reno(w))
 *
 * Wepoch is equal to ssthresh, therefore the only Cuback-specific states that need to be retained are:
 *
 * * Wmax
 * * bandwidth observed at the last congestion event
 * * (cwnd_prior as a value separate from Wmax, if fast convergence is needed)
 * * (alpha, if ABE is supported and uses a different alpha when reacting to ECN-CE)
 *
 * These values remain immutable during each epoch. The congestion-avoidance trajectory is expressed entirely as pure functions
 * using them, taking CWND as the only parameter.
 *
 * Using the `bytes_sent` function, the congestion controller calculates bytes needed to be acked before incrementing the CWND
 * (`bytes_sent(cwnd + mtu) - bytes_sent(cwnd)`) and drives congestion avoidance, the same way as in the case of Reno.
 * When packet-size normalization is enabled, the reference MTU replaces MSS in the Cubic coefficient and in the denominator of
 * the Reno sums, while `w` remains spaced by the actual MTU. In particular, the normalized pre-Wmax Reno inverse is:
 *
 *   bytes_reno(w) = (w - Wepoch) * (w + Wepoch - actual_MTU) / (2 * alpha * reference_MTU)
 *
 * In addition to being simple, the approach has two positive side-effects:
 *
 * * As CWND is driven by acks rather than by time, CWND does not advance while nothing is inflight. Congestion control becomes
 *   safer without accurate app-limited tracking.
 * * Because the clock is the ack stream, a flow whose share is being taken advances more slowly than one that is taking, thereby
 *   yielding bandwidth. Fast convergence could be still helpful.
 *
 * __Note on the reno-friendly region__
 *
 * Cubic and Cuback represent the Reno-friendly estimate differently while the cubic curve controls CWND.
 *
 * Cubic updates `W_est += alpha * segments_acked / cwnd`, where cwnd is the combined window. Therefore, W_est increases by alpha
 * segments per RTT, as Reno does.
 *
 * Cuback instead uses the inverse of the standalone, packet-granular Reno recurrence. Its acknowledged-byte threshold is derived
 * from the Reno-friendly window, rather than from the larger cubic-controlled window. Therefore, if the congestion avoidance stage
 * starts outside the Reno-friendly region, each acknowledged byte advances Cuback's estimate farther until the two curves converge,
 * and Cuback's Reno-friendly curve takes control earlier than W_est does in Cubic, making Cuback more aggressive.
 *
 * In a simulator 2x2 varying the Reno estimator and cubic clock independently, the clock-source effect was larger by point estimate
 * in every tested configuration. Even in the 100 ms / four-Reno case where isolated curve analysis predicted the largest
 * divergence, the standalone estimator increased Cuback's throughput by 2.3%, versus 3.1% for changing the cubic curve from the
 * wall clock to the ACK clock.
 */
static double cuback_cwnd_to_bytes_sent(double w, double w_epoch, double w_max, double cwnd_prior, double bandwidth, double k,
                                        uint32_t actual_mtu, uint32_t reference_mtu, double friendly_alpha)
{
    double bytes_cubic = (k + fast_cbrt((w - w_max) / (QUICLY_CUBIC_C * reference_mtu))) * bandwidth;
    /* RFC 9438, Section 4.3 switches alpha to one after the Reno-friendly estimate reaches the congestion window prior to
     * reduction. Bandwidth cancels when converting the Reno time to bytes sent. */
    double w_friendly = w < cwnd_prior ? w : cwnd_prior;
    double bytes_reno = (w_friendly - w_epoch) * (w_friendly + w_epoch - actual_mtu) / (2 * friendly_alpha * reference_mtu);
    if (w > cwnd_prior)
        bytes_reno += (w - cwnd_prior) * (w + cwnd_prior - actual_mtu) / (2 * reference_mtu);
    double bytes = bytes_cubic < bytes_reno ? bytes_cubic : bytes_reno;
    return bytes > 0 ? bytes : 0;
}

/**
 * Calculates the number of bytes that have to be acked for incrementing CWND by one MTU, when Cuback is used.
 */
static uint32_t cuback_bytes_per_mtu_increase(const struct st_quicly_cc_cuback_t *state, uint32_t cwnd, uint32_t cwnd_epoch,
                                              uint32_t actual_mtu, uint32_t reference_mtu)
{
    /* Fast convergence: derive Wmax as the midpoint of cwnd_prior and cwnd_epoch rather than hard-coding it to 0.85 * cwnd_prior.
     * Otherwise, with ABE using QUICLY_BETA_ECN (0.85), Wmax equals cwnd_epoch and K becomes zero, causing the CC to skip the
     * concave region and start at the plateau. */
    double w_max = state->fast_convergence ? cubic_fast_convergence_w_max(state->cwnd_prior, cwnd_epoch) : state->cwnd_prior;
    /* Seconds taken by the cubic curve to climb from `cwnd_epoch` back to W_max. Derived from the gap between the two rather than
     * from W_max alone, as fast convergence and the varying reduction ratios move them apart. */
    double k = fast_cbrt((w_max - cwnd_epoch) / (QUICLY_CUBIC_C * reference_mtu));

    double bytes0 = cuback_cwnd_to_bytes_sent(cwnd, cwnd_epoch, w_max, state->cwnd_prior, state->bandwidth, k, actual_mtu,
                                              reference_mtu, cubic_friendly_alpha[state->by_ecn]);
    double bytes1 = cuback_cwnd_to_bytes_sent((double)cwnd + actual_mtu, cwnd_epoch, w_max, state->cwnd_prior, state->bandwidth, k,
                                              actual_mtu, reference_mtu, cubic_friendly_alpha[state->by_ecn]);
    double bytes = bytes1 - bytes0;

    /* Past W_max the curve grows without bound, therefore the increase is capped at 50% of CWND per RTT as RFC 9438 does. Below
     * W_max the cap is not applied, it being the climb back to a window that the path had already sustained. */
    if (cwnd > w_max && bytes < (double)actual_mtu * 2)
        bytes = (double)actual_mtu * 2;

    return bytes < 1 ? 1 : bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
}

static double cubic_w_max(const struct st_quicly_cc_cubic_t *state, uint32_t cwnd_epoch)
{
    return state->fast_convergence ? cubic_fast_convergence_w_max(state->cwnd_prior, cwnd_epoch) : state->cwnd_prior;
}

static double cubic_calc_w(const struct st_quicly_cc_cubic_t *state, uint32_t cwnd_epoch, double t_sec, uint32_t mtu)
{
    double tk = t_sec - state->k;
    return QUICLY_CUBIC_C * tk * tk * tk * mtu + cubic_w_max(state, cwnd_epoch);
}

static int cubic_start_epoch(struct st_quicly_cc_cubic_t *state, uint32_t cwnd, uint32_t cwnd_epoch, uint32_t mtu)
{
    if (state->epoch_start == 0)
        return 0;
    assert(state->w_est != 0);
    if (isnan(state->k))
        state->k = fast_cbrt((cubic_w_max(state, cwnd_epoch) - cwnd) / (QUICLY_CUBIC_C * mtu));
    return 1;
}

static void cubic_set_cc_limited(struct st_quicly_cc_cubic_t *state, int cc_limited, int64_t now)
{
    state->cc_limited = cc_limited;
    if (!cc_limited) {
        state->k = NAN;
        state->epoch_start = 0;
    } else if (state->epoch_start == 0 && state->w_est != 0) {
        state->epoch_start = now;
        state->k = NAN;
    }
}

static uint32_t cubic_quantized_w_est(const struct st_quicly_cc_cubic_t *state, uint32_t cwnd_epoch, uint32_t mtu)
{
    /* Keep the estimator continuous as defined by RFC 9438 Figure 4; only the value exposed as CWND is quantized, in whole-MTU
     * steps from the epoch's initial window. */
    double quantized = cwnd_epoch + floor((state->w_est - cwnd_epoch) / mtu) * mtu;
    return quantized < UINT32_MAX ? quantized : UINT32_MAX;
}

static uint32_t cubic_update_w_est(struct st_quicly_cc_cubic_t *state, uint32_t cwnd, uint32_t cwnd_epoch, uint32_t bytes,
                                   uint32_t actual_mtu, uint32_t reference_mtu)
{
    double alpha = state->w_est >= state->cwnd_prior ? 1 : cubic_friendly_alpha[state->by_ecn];
    state->w_est += alpha * bytes / cwnd * reference_mtu;
    return cubic_quantized_w_est(state, cwnd_epoch, actual_mtu);
}

static void cubic_on_acked(struct st_quicly_cc_cubic_t *state, uint32_t *cwnd, uint32_t cwnd_epoch, uint32_t bytes, int cc_limited,
                           uint32_t rtt, int64_t now, uint32_t actual_mtu, uint32_t reference_mtu)
{
    uint32_t w_est = cubic_quantized_w_est(state, cwnd_epoch, actual_mtu);
    if (cc_limited)
        w_est = cubic_update_w_est(state, *cwnd, cwnd_epoch, bytes, actual_mtu, reference_mtu);

    /* W_est is ACK-clocked even while the CUBIC clock is stopped, but CWND does not grow while currently app-limited. */
    if (!cubic_start_epoch(state, *cwnd, cwnd_epoch, reference_mtu) || bytes == 0)
        return;

    double t_sec = (now - state->epoch_start) / 1000.;
    double w_cubic = cubic_calc_w(state, cwnd_epoch, t_sec, reference_mtu);

    if (w_cubic < w_est) {
        /* RFC 9438, Section 4.3; Reno-Friendly Region. */
        *cwnd = w_est;
    } else {
        /* RFC 9438, Sections 4.4 and 4.5; Concave and Convex Regions, but the amount added to CWND is  `(target - cwnd) / cwnd`
         * per MTU acked rather than per ACK (see https://mailarchive.ietf.org/arch/msg/ccwg/ZTYECT1NQijwwxq2sDLE0scbQAg/).
         * Unlike Cuback and W_est, increments to `cwnd` are not rounded down to an MTU multiple. This can permit a full-sized
         * packet when `cwnd - bytes_in_flight` is positive but smaller than an MTU, however the impact is assumed negilible due to
         * the following reasons:
         *  - The resulting overshoot is retained as debt, preventing further transmission until it is repaid.
         *  - W_cubic is time-based, so an earlier ACK does not directly advance the curve.
         *  - The cubic curve generally dominates at larger windows, where a sub-packet error is relatively minor. */
        double target = cubic_calc_w(state, cwnd_epoch, t_sec + rtt / 1000., reference_mtu);
        if (target < *cwnd)
            target = *cwnd;
        if (target > 1.5 * *cwnd)
            target = 1.5 * *cwnd;
        *cwnd = quicly_u32_add_saturating(*cwnd, (target / *cwnd - 1) * bytes);
    }
}

static void cubic_on_congestion(struct st_quicly_cc_cubic_t *state, uint32_t cwnd_prior, uint32_t previous_cwnd_epoch, int by_ecn)
{
    double previous_w_max = cubic_w_max(state, previous_cwnd_epoch);

    state->by_ecn = by_ecn;
    state->k = NAN;
    state->epoch_start = 0;
    state->w_est = 0;
    state->fast_convergence = state->cwnd_prior != 0 && cwnd_prior < previous_w_max;
    state->cwnd_prior = cwnd_prior;
}

/**
 * Calculates the size of the next ACK interval from the current congestion-control state.
 */
static uint32_t calc_bytes_per_mtu_increase(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t max_udp_payload_size)
{
    if (cc->cwnd < cc->ssthresh) {
        return quicly_cc_rapid_start_use_3x(&cc->rapid_start, &loss->rtt) ? max_udp_payload_size / 2 : max_udp_payload_size;
    } else if (cc->type == &quicly_cc_type_cuback) {
        if (cc->state.pico.cuback.bandwidth == 0) {
            /* The curve remains undefined until the first congestion event; this is reachable only when the CC has been switched
             * while in congestion avoidance. Use Reno until then. */
            return cc->cwnd;
        }
        uint32_t reference_mtu = cc->normalize_mtu ? QUICLY_CC_REFERENCE_MTU : max_udp_payload_size;
        return cuback_bytes_per_mtu_increase(&cc->state.pico.cuback, cc->cwnd, cc->ssthresh, max_udp_payload_size, reference_mtu);
    } else if (cc->type == &quicly_cc_type_cubic) {
        assert(!"Cubic congestion avoidance bypasses the byte-counter path");
        abort();
    } else if (cc->type == &quicly_cc_type_pico) {
        return cc->state.pico.bytes_per_mtu_increase;
    } else {
        assert(cc->type == &quicly_cc_type_reno);
        if (cc->normalize_mtu) {
            uint64_t bytes = (uint64_t)cc->cwnd * max_udp_payload_size / QUICLY_CC_REFERENCE_MTU;
            return bytes < 1 ? 1 : bytes > UINT32_MAX ? UINT32_MAX : (uint32_t)bytes;
        }
        return cc->cwnd;
    }
}

static void pico_on_acked(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t largest_acked, uint32_t inflight,
                          int cc_limited, uint64_t next_pn, int64_t now, uint32_t max_udp_payload_size)
{
    assert(inflight >= bytes);

    /* In recovery period: CWND remains the same (but either jumpstart or rapid start may handle it differently). */
    if (largest_acked < cc->recovery_end) {
        if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            if (cc->num_loss_episodes == 1) {
                quicly_cc_rapid_start_on_recovery(&cc->rapid_start, &cc->cwnd, bytes, 0);
                cc->ssthresh = cc->cwnd;
            }
        } else {
            quicly_cc_jumpstart_on_acked(cc, 1, bytes, largest_acked, inflight, next_pn);
        }
        return;
    }

    quicly_cc_jumpstart_on_acked(cc, 0, bytes, largest_acked, inflight, next_pn);

    /* Cubic: unlike other policies, congestion avoidance cannot be driven by bytes_to_mtu_increase. */
    if (cc->type == &quicly_cc_type_cubic && cc->cwnd >= cc->ssthresh) {
        struct st_quicly_cc_cubic_t *state = &cc->state.pico.cubic;
        if (state->w_est == 0) {
            if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
                state->cwnd_prior = cubic_post_rapid_start_wmax(cc->cwnd, cc->rapid_start.recovery.by_ecn);
                state->fast_convergence = 0;
            }
            assert(state->cwnd_prior != 0);
            state->w_est = cc->cwnd;
            state->epoch_start = state->cc_limited ? now : 0;
            state->k = NAN;
        }
        uint32_t reference_mtu = cc->normalize_mtu ? QUICLY_CC_REFERENCE_MTU : max_udp_payload_size;
        cubic_on_acked(state, &cc->cwnd, cc->ssthresh, bytes, cc_limited, loss->rtt.smoothed, now, max_udp_payload_size,
                       reference_mtu);
        goto Cleanup;
    }

    /* Cuback: set cwnd_prior deferred under Rapid Start, as its BDP estimate becomes available only after recovery ends. */
    if (cc->type == &quicly_cc_type_cuback && quicly_cc_rapid_start_is_in_recovery(&cc->rapid_start)) {
        assert(cc->state.pico.cuback.bandwidth > 0 && cc->state.pico.cuback.cwnd_prior == 0);
        cc->state.pico.cuback.cwnd_prior = cubic_post_rapid_start_wmax(cc->cwnd, cc->rapid_start.recovery.by_ecn);
    }

    if (!cc_limited)
        goto Cleanup;

    /* Rapid Start: update its RTT_floor measurement used for detecting queue build-up */
    if (bytes != 0 && cc->cwnd < cc->ssthresh && cc->num_loss_episodes == 0)
        quicly_cc_rapid_start_update_rtt(&cc->rapid_start, &loss->rtt, now);

    /* Apply this ACK to the current interval. One ACK can span multiple intervals. */
    uint32_t bytes_available = bytes;
    if (cc->state.pico.bytes_to_mtu_increase == 0)
        cc->state.pico.bytes_to_mtu_increase = calc_bytes_per_mtu_increase(cc, loss, max_udp_payload_size);
    while (bytes_available >= cc->state.pico.bytes_to_mtu_increase) {
        bytes_available -= cc->state.pico.bytes_to_mtu_increase;
        cc->cwnd = quicly_u32_add_saturating(cc->cwnd, max_udp_payload_size);
        cc->state.pico.bytes_to_mtu_increase = calc_bytes_per_mtu_increase(cc, loss, max_udp_payload_size);
    }
    cc->state.pico.bytes_to_mtu_increase -= bytes_available;
    assert(cc->state.pico.bytes_to_mtu_increase != 0);

Cleanup:
    if (cc->cwnd_maximum < cc->cwnd)
        cc->cwnd_maximum = cc->cwnd;
    if (quicly_cc_rapid_start_is_in_recovery(&cc->rapid_start))
        quicly_cc_rapid_start_exit_recovery(&cc->rapid_start);
}

static void pico_on_lost(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, uint64_t lost_pn, uint64_t next_pn,
                         int64_t now, uint32_t max_udp_payload_size)
{
    quicly_cc__update_ecn_episodes(cc, bytes, lost_pn);

    /* Nothing to do if loss is in recovery window (modulo when exiting rapid start, in which case CWND is further reduced relative
     * to the number of bytes lost. */
    if (lost_pn < cc->recovery_end) {
        if (bytes != 0 && cc->state.pico.undo.num_packets_lost != 0)
            ++cc->state.pico.undo.num_packets_lost;
        if (cc->num_loss_episodes == 1 && quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            quicly_cc_rapid_start_on_recovery(&cc->rapid_start, &cc->cwnd, 0, bytes);
            if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
                cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;
            goto UpdateMetrics;
        }
        return;
    }

    /* Rapid Start: if recovery exits and the first CC event is a loss instead of an ack, call `pico_on_acked` to reflect recovery
     * exit to Rapid Start and related states, before entering the next recovery period in the following blocks. */
    if (quicly_cc_rapid_start_is_in_recovery(&cc->rapid_start))
        pico_on_acked(cc, loss, 0, cc->recovery_end, (uint32_t)loss->sentmap.bytes_in_flight, 0, next_pn, now,
                      max_udp_payload_size);

    double beta = cc->type == &quicly_cc_type_reno ? QUICLY_BETA_RENO : (bytes == 0 ? QUICLY_BETA_ECN : QUICLY_BETA_LOSS);

    /* Zero-byte congestion reports are ECN signals, not lost packets. They still enter recovery below, but cannot be undone by
     * late ACKs because no packet was deemed lost. */
    if (bytes != 0) {
        cc->state.pico.undo.num_packets_lost = 1;
        cc->state.pico.undo.start_pn = lost_pn;
        cc->state.pico.undo.cwnd = cc->cwnd;
        if (quicly_cc_in_jumpstart(cc)) {
            cc->state.pico.undo.cwnd /= 2;
            if (cc->state.pico.undo.cwnd < cc->cwnd_initial)
                cc->state.pico.undo.cwnd = cc->cwnd_initial;
        }
        cc->state.pico.undo.ssthresh = cc->ssthresh;
        cc->state.pico.undo.bytes_to_mtu_increase = cc->state.pico.bytes_to_mtu_increase;
        if (cc->type == &quicly_cc_type_cuback) {
            cc->state.pico.undo.cuback = cc->state.pico.cuback;
        } else if (cc->type == &quicly_cc_type_cubic) {
            cc->state.pico.undo.cubic = cc->state.pico.cubic;
        } else if (cc->type == &quicly_cc_type_pico) {
            cc->state.pico.undo.bytes_per_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
        } else {
            assert(cc->type == &quicly_cc_type_reno);
        }
    } else {
        cc->state.pico.undo.num_packets_lost = 0;
    }

    cc->recovery_end = next_pn;
    ++cc->num_loss_episodes;

    /* end of slow start */
    if (cc->cwnd_exiting_slow_start == 0) {
        assert(cc->ssthresh == UINT32_MAX);
        /* jumpstart: if detected loss during the validating phase, advance to validating phase */
        quicly_cc_jumpstart_on_first_loss(cc, lost_pn, quicly_cc_rapid_start_is_enabled(&cc->rapid_start));
        /* save values */
        cc->cwnd_exiting_slow_start = cc->cwnd;
        cc->exit_slow_start_at = now;
    }

    /* estimate BDP (usually from CWND before reduction) */
    uint32_t bdp = cc->cwnd;
    if (cc->num_loss_episodes == 1) {
        if (quicly_cc_is_jumpstart_ack(cc, lost_pn)) {
            bdp = cc->jumpstart.bytes_acked;
        } else if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            /* Rapid Start might have already switched to 2x, but it's unclear if the entire RT was in 2x. Therefore, use a
             * conservative estimate of BDP. It could make the next CA epoch slightly aggressive, but nowhere near as aggressive as
             * startup, so we're fine. */
            bdp = cc->cwnd / 3;
        } else {
            bdp = cc->cwnd / 2;
        }
        if (bdp < QUICLY_MIN_CWND * max_udp_payload_size)
            bdp = QUICLY_MIN_CWND * max_udp_payload_size;
    }

    /* Reduce congestion window. At the end of Slow Start, 0.5x is used, because the 1 RTT delay in ACK causes the sender to
     * overshoot by 2x (note: after 0.5x reduction, CWND is still as large as BDP+QUEUE, so further reduction is preferable). That
     * 2x overshoot builds up regardless of if congestion is signalled by a CE mark or by a packet loss, therefore `beta` is not
     * used here.
     *
     * In rapid start, upon the first congestion signal we multiply CWND by QUICLY_RAPID_START_LOSS_FACTOR (0.9x when beta is 0.7,
     * 0.95x when it is 0.85), then reduce proportionally to the bytes acked and deemed lost during recovery, with a lower bound of
     * 1/3 * beta.
     * Rationale: at a small loss, reducing by beta mirrors CA's single signal behavior. With up to ~67% loss (typical for 3x
     * growth under tail-drop), CWND upon loss detection is 3 * (BDP + Q); therefore clamping to 1/3 * beta reproduces the CA
     * target. For loss >67% (i.e., beyond queue overflow), we keep the lower bound to avoid over-shrinking. */
    if (cc->ssthresh == UINT32_MAX) {
        if (quicly_cc_rapid_start_is_enabled(&cc->rapid_start)) {
            uint32_t base = cc->cwnd_initial;
            if (base < cc->jumpstart.bytes_acked)
                base = cc->jumpstart.bytes_acked;
            quicly_cc_rapid_start_on_first_lost(&cc->rapid_start, &cc->cwnd, bytes == 0, base * 0.5);
        } else {
            cc->cwnd *= 0.5;
        }
    } else {
        cc->cwnd *= beta;
    }

    if (cc->cwnd < QUICLY_MIN_CWND * max_udp_payload_size)
        cc->cwnd = QUICLY_MIN_CWND * max_udp_payload_size;

    /* Update policy-specific state using the estimated BDP and reduced CWND.
     *
     * Note on Cubic/Cuback: When ordinary slow start is used, both Wmax and post-recovery CWND are set to the estimated BDP and K
     * becomes 0, therefore the cubic curve will only have the convex region. CWND is not reduced beyond x0.5, because doing so
     * risks bottleneck queue underflow. Compared to setting Wmax to CWND_at_loss, when there is no competing traffic, 2nd recovery
     * is delayed due to increasing CWND only gradually immediately after exiting recovery. When competing traffic exists, it is
     * likely to reach equilibrium earlier due to the convex region stealing bandwidth faster, once CWND goes past CWND_loss. When
     * rapid start is used, BDP, Wmax, and K are determined upon exitting recovery. */
    if (cc->type == &quicly_cc_type_cuback) {
        if (cc->num_loss_episodes == 1) {
            /* Exiting startup: adopt the calculated BDP as the prior CWND or defer until the exiting recovery. */
            cc->state.pico.cuback.cwnd_prior = quicly_cc_rapid_start_is_enabled(&cc->rapid_start) ? 0 : bdp;
            cc->state.pico.cuback.fast_convergence = 0;
        } else {
            /* Fast convergence kicks in if the BDP estimate comes out below the previous W_max (RFC 9438, Section 4.7). */
            double previous_w_max = cc->state.pico.cuback.fast_convergence
                                        ? cubic_fast_convergence_w_max(cc->state.pico.cuback.cwnd_prior, cc->ssthresh)
                                        : cc->state.pico.cuback.cwnd_prior;
            cc->state.pico.cuback.cwnd_prior = bdp;
            cc->state.pico.cuback.fast_convergence = bdp < previous_w_max;
        }
        cc->state.pico.cuback.by_ecn = bytes == 0;
        cc->state.pico.cuback.bandwidth = loss->rtt.smoothed != 0 ? bdp * 1000. / loss->rtt.smoothed : 0;
        cc->state.pico.bytes_to_mtu_increase = 0;
    } else if (cc->type == &quicly_cc_type_cubic) {
        cubic_on_congestion(&cc->state.pico.cubic, bdp, cc->ssthresh, bytes == 0);
        cc->state.pico.bytes_to_mtu_increase = 0;
    } else if (cc->type == &quicly_cc_type_pico) {
        /* Pico: Rapid Start might adjust CWND to a smaller value than `bdp`, but the increase is calculated using `bdp` regardless.
         * Doing so makes the 1st CA aggressive, but not too aggressive to observe the 2nd loss immediately. */
        cc->state.pico.bytes_per_mtu_increase = pico_bytes_per_mtu_increase(bdp, loss->rtt.smoothed, max_udp_payload_size, beta);
        cc->state.pico.bytes_to_mtu_increase = cc->state.pico.bytes_per_mtu_increase;
    } else {
        assert(cc->type == &quicly_cc_type_reno);
        cc->state.pico.bytes_to_mtu_increase = 0;
    }

UpdateMetrics:
    cc->ssthresh = cc->cwnd;
    if (cc->cwnd_minimum > cc->cwnd)
        cc->cwnd_minimum = cc->cwnd;
}

static void pico_on_late_ack(quicly_cc_t *cc, uint64_t pn, int64_t now)
{
    if (!(cc->state.pico.undo.start_pn <= pn && pn < cc->recovery_end))
        return;
    if (cc->state.pico.undo.num_packets_lost == 0)
        return;

    if (--cc->state.pico.undo.num_packets_lost != 0)
        return;

    int was_in_startup = cc->state.pico.undo.ssthresh == UINT32_MAX;
    cc->cwnd = cc->state.pico.undo.cwnd;
    cc->ssthresh = cc->state.pico.undo.ssthresh;
    cc->state.pico.bytes_to_mtu_increase = cc->state.pico.undo.bytes_to_mtu_increase;
    if (cc->type == &quicly_cc_type_cuback) {
        cc->state.pico.cuback = cc->state.pico.undo.cuback;
    } else if (cc->type == &quicly_cc_type_cubic) {
        int cc_limited = cc->state.pico.cubic.cc_limited;
        cc->state.pico.cubic = cc->state.pico.undo.cubic;
        cubic_set_cc_limited(&cc->state.pico.cubic, cc_limited, now);
    } else if (cc->type == &quicly_cc_type_pico) {
        cc->state.pico.bytes_per_mtu_increase = cc->state.pico.undo.bytes_per_mtu_increase;
    } else {
        assert(cc->type == &quicly_cc_type_reno);
    }
    cc->recovery_end = 0;
    --cc->num_loss_episodes;
    ++cc->num_loss_episodes_undone;
    if (was_in_startup) {
        ++cc->num_loss_episodes_undone_in_startup;
        cc->cwnd_exiting_slow_start = 0;
        cc->exit_slow_start_at = INT64_MAX;
        quicly_cc_jumpstart_reset(cc);
        cc->rapid_start.newest_rtt_sample_until = 0;
    }
}

static void pico_on_sent(quicly_cc_t *cc, const quicly_loss_t *loss, uint32_t bytes, int64_t now)
{
    /* Unused */
}

static void pico_init_pico_state(quicly_cc_t *cc)
{
    /* Initialize the state overlaid by each policy implemented in this file. */
    cc->state.pico.bytes_to_mtu_increase = 0;
    if (cc->type == &quicly_cc_type_cuback) {
        cc->state.pico.cuback = (struct st_quicly_cc_cuback_t){0};
    } else if (cc->type == &quicly_cc_type_cubic) {
        cc->state.pico.cubic = (struct st_quicly_cc_cubic_t){.k = NAN, .cc_limited = 1};
    } else if (cc->type == &quicly_cc_type_pico) {
        cc->state.pico.bytes_per_mtu_increase = cc->cwnd * QUICLY_BETA_LOSS;
    } else {
        assert(cc->type == &quicly_cc_type_reno);
    }
}

static void pico_reset(quicly_cc_t *cc, quicly_cc_type_t *type, uint32_t initcwnd, int normalize_mtu)
{
    *cc = (quicly_cc_t){
        .type = type,
        .normalize_mtu = normalize_mtu,
        .cwnd = initcwnd,
        .cwnd_initial = initcwnd,
        .cwnd_maximum = initcwnd,
        .cwnd_minimum = UINT32_MAX,
        .exit_slow_start_at = INT64_MAX,
        .ssthresh = UINT32_MAX,
    };
    pico_init_pico_state(cc);

    quicly_cc_jumpstart_reset(cc);
}

/**
 * Switches to a controller implemented by this file; all four share their state representation.
 */
static int switch_to(quicly_cc_t *cc, quicly_cc_type_t *type)
{
    if (cc->type == type) {
        return 1; /* nothing to do */
    } else if (cc->type == &quicly_cc_type_reno && (type != &quicly_cc_type_cubic || cc->cwnd_exiting_slow_start == 0)) {
        cc->type = type;
        pico_init_pico_state(cc);
        return 1;
    } else if (cc->type == &quicly_cc_type_reno || cc->type == &quicly_cc_type_cubic || cc->type == &quicly_cc_type_cubic_legacy ||
               cc->type == &quicly_cc_type_pico || cc->type == &quicly_cc_type_cuback) {
        /* When in slow start, state can be reused as-is; otherwise, restart. */
        if (cc->cwnd_exiting_slow_start == 0) {
            cc->type = type;
            pico_init_pico_state(cc);
        } else {
            pico_reset(cc, type, cc->cwnd_initial, cc->normalize_mtu);
        }
        return 1;
    }

    return 0;
}

static int pico_on_switch(quicly_cc_t *cc)
{
    return switch_to(cc, &quicly_cc_type_pico);
}

static int reno_on_switch(quicly_cc_t *cc)
{
    return switch_to(cc, &quicly_cc_type_reno);
}

static int cubic_on_switch(quicly_cc_t *cc)
{
    return switch_to(cc, &quicly_cc_type_cubic);
}

static int cuback_on_switch(quicly_cc_t *cc)
{
    return switch_to(cc, &quicly_cc_type_cuback);
}

static void pico_enable_rapid_start(quicly_cc_t *cc, int64_t now)
{
    quicly_cc_init_rapid_start(&cc->rapid_start, now);
}

static void cubic_update_cc_limited(quicly_cc_t *cc, int cc_limited, int64_t now)
{
    cubic_set_cc_limited(&cc->state.pico.cubic, cc_limited, now);
}

static void pico_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int normalize_mtu, int64_t now)
{
    pico_reset(cc, &quicly_cc_type_pico, initcwnd, normalize_mtu);
}

static void reno_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int normalize_mtu, int64_t now)
{
    pico_reset(cc, &quicly_cc_type_reno, initcwnd, normalize_mtu);
}

static void cubic_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int normalize_mtu, int64_t now)
{
    pico_reset(cc, &quicly_cc_type_cubic, initcwnd, normalize_mtu);
}

static void cuback_init(quicly_init_cc_t *self, quicly_cc_t *cc, uint32_t initcwnd, int normalize_mtu, int64_t now)
{
    pico_reset(cc, &quicly_cc_type_cuback, initcwnd, normalize_mtu);
}

quicly_cc_type_t quicly_cc_type_pico = {
    "pico",           &quicly_cc_pico_init,      pico_on_acked,          pico_on_lost, pico_on_sent, pico_on_switch,
    pico_on_late_ack, quicly_cc_jumpstart_enter, pico_enable_rapid_start};
quicly_init_cc_t quicly_cc_pico_init = {pico_init};

quicly_cc_type_t quicly_cc_type_reno = {
    "reno",           &quicly_cc_reno_init,      pico_on_acked,          pico_on_lost, pico_on_sent, reno_on_switch,
    pico_on_late_ack, quicly_cc_jumpstart_enter, pico_enable_rapid_start};
quicly_init_cc_t quicly_cc_reno_init = {reno_init};

quicly_cc_type_t quicly_cc_type_cubic = {
    "cubic",          &quicly_cc_cubic_init,     pico_on_acked,           pico_on_lost,           pico_on_sent, cubic_on_switch,
    pico_on_late_ack, quicly_cc_jumpstart_enter, pico_enable_rapid_start, cubic_update_cc_limited};
quicly_init_cc_t quicly_cc_cubic_init = {cubic_init};

quicly_cc_type_t quicly_cc_type_cuback = {
    "cuback",         &quicly_cc_cuback_init,    pico_on_acked,          pico_on_lost, pico_on_sent, cuback_on_switch,
    pico_on_late_ack, quicly_cc_jumpstart_enter, pico_enable_rapid_start};
quicly_init_cc_t quicly_cc_cuback_init = {cuback_init};

quicly_cc_type_t *quicly_cc_all_types[] = {&quicly_cc_type_reno, &quicly_cc_type_cubic,  &quicly_cc_type_cubic_legacy,
                                           &quicly_cc_type_pico, &quicly_cc_type_cuback, NULL};

uint32_t quicly_cc_calc_initial_cwnd(uint32_t max_packets, uint16_t max_udp_payload_size)
{
    static const uint32_t mtu_max = 1472;

    if (max_packets < QUICLY_MIN_CWND)
        max_packets = QUICLY_MIN_CWND;
    if (max_udp_payload_size > mtu_max)
        max_udp_payload_size = mtu_max;

    uint64_t cwnd_bytes = (uint64_t)max_packets * max_udp_payload_size;
    return cwnd_bytes <= UINT32_MAX ? (uint32_t)cwnd_bytes : UINT32_MAX;
}
