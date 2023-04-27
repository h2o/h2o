/*
 * Copyright (c) 2021 Fastly, Kazuho Oku
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
#include "picotls.h"
#include "quicly/rate.h"

static void start_sampling(quicly_ratemeter_t *meter, int64_t now, uint64_t bytes_acked)
{
    meter->current.start.at = now;
    meter->current.start.bytes_acked = bytes_acked;
}

static void commit_sample(quicly_ratemeter_t *meter)
{
    ++meter->past_samples.latest;
    if (meter->past_samples.latest >= PTLS_ELEMENTSOF(meter->past_samples.entries))
        meter->past_samples.latest = 0;
    meter->past_samples.entries[meter->past_samples.latest] = meter->current.sample;

    meter->current.start.at = INT64_MAX;
    meter->current.sample = (struct st_quicly_rate_sample_t){};
}

void quicly_ratemeter_init(quicly_ratemeter_t *meter)
{
    *meter = (quicly_ratemeter_t){
        .past_samples = {.latest = PTLS_ELEMENTSOF(meter->past_samples.entries) - 1},
        .pn_cwnd_limited = {.start = UINT64_MAX, .end = UINT64_MAX},
        .current = {.start = {.at = INT64_MAX}},
    };
}

void quicly_ratemeter_in_cwnd_limited(quicly_ratemeter_t *meter, uint64_t pn)
{
    /* bail out if already in cwnd-limited phase */
    if (meter->pn_cwnd_limited.start != UINT64_MAX && meter->pn_cwnd_limited.end == UINT64_MAX)
        return;

    /* if the estimator was waiting for the end of the previous phase, and if a valid partial sample exists, commit it now */
    if (meter->pn_cwnd_limited.end != UINT64_MAX && meter->current.sample.elapsed != 0)
        commit_sample(meter);

    /* begin new cwnd-limited phase */
    meter->pn_cwnd_limited = (quicly_range_t){.start = pn, .end = UINT64_MAX};
}

void quicly_ratemeter_not_cwnd_limited(quicly_ratemeter_t *meter, uint64_t pn)
{
    if (meter->pn_cwnd_limited.start != UINT64_MAX && meter->pn_cwnd_limited.end == UINT64_MAX)
        meter->pn_cwnd_limited.end = pn;
}

void quicly_ratemeter_on_ack(quicly_ratemeter_t *meter, int64_t now, uint64_t bytes_acked, uint64_t pn)
{
    if (meter->pn_cwnd_limited.start <= pn && pn < meter->pn_cwnd_limited.end) {
        /* At the moment, the flow is CWND-limited. Either start the timer or update. */
        if (meter->current.start.at == INT64_MAX) {
            start_sampling(meter, now, bytes_acked);
        } else {
            /* Update current sample whenever receiving an ACK, so that the sample can be committed other than when receiving an ACK
             * (i.e., when opening a new CWND-limited phase). */
            meter->current.sample = (struct st_quicly_rate_sample_t){
                .elapsed = (uint32_t)(now - meter->current.start.at),
                .bytes_acked = (uint32_t)(bytes_acked - meter->current.start.bytes_acked),
            };
            if (meter->current.sample.elapsed >= QUICLY_DELIVERY_RATE_SAMPLE_PERIOD) {
                commit_sample(meter);
                start_sampling(meter, now, bytes_acked);
            }
        }
    } else if (meter->pn_cwnd_limited.end <= pn) {
        /* We have exited CWND-limited state. Save current value, if any. */
        if (meter->current.start.at != INT64_MAX) {
            if (meter->current.sample.elapsed != 0)
                commit_sample(meter);
            meter->pn_cwnd_limited = (quicly_range_t){.start = UINT64_MAX, .end = UINT64_MAX};
            meter->current.start.at = INT64_MAX;
        }
    }
}

static uint64_t to_speed(uint64_t bytes_acked, uint32_t elapsed)
{
    return bytes_acked * 1000 / elapsed;
}

void quicly_ratemeter_report(quicly_ratemeter_t *meter, quicly_rate_t *rate)
{
    { /* Calculate latest, or return if there are no samples at all. `latest` being reported will be the most recent "full" sample
       * if available, or else a partial sample. */
        const struct st_quicly_rate_sample_t *latest_sample = &meter->past_samples.entries[meter->past_samples.latest];
        if (latest_sample->elapsed == 0) {
            latest_sample = &meter->current.sample;
            if (latest_sample->elapsed == 0) {
                rate->latest = rate->smoothed = rate->stdev = 0;
                return;
            }
        }
        rate->latest = to_speed(latest_sample->bytes_acked, latest_sample->elapsed);
    }

#define FOREACH_SAMPLE(func)                                                                                                       \
    do {                                                                                                                           \
        const struct st_quicly_rate_sample_t *sample;                                                                              \
        for (size_t i = 0; i < PTLS_ELEMENTSOF(meter->past_samples.entries); ++i) {                                                \
            if ((sample = &meter->past_samples.entries[i])->elapsed != 0) {                                                        \
                func                                                                                                               \
            }                                                                                                                      \
        }                                                                                                                          \
        if ((sample = &meter->current.sample)->elapsed != 0) {                                                                     \
            func                                                                                                                   \
        }                                                                                                                          \
    } while (0)

    { /* calculate average */
        uint64_t total_acked = 0;
        uint32_t total_elapsed = 0;
        FOREACH_SAMPLE({
            total_acked += sample->bytes_acked;
            total_elapsed += sample->elapsed;
        });
        rate->smoothed = to_speed(total_acked, total_elapsed);
    }

    { /* calculate stdev */
        uint64_t sum = 0;
        size_t count = 0;
        FOREACH_SAMPLE({
            uint64_t sample_speed = to_speed(sample->bytes_acked, sample->elapsed);
            sum += (sample_speed - rate->smoothed) * (sample_speed - rate->smoothed);
            ++count;
        });
        rate->stdev = sqrt(sum / count);
    }

#undef FOREACH_SAMPLE
}
