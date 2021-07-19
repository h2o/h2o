/*
 * Copyright (c) 2021 Fastly
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

#ifndef h2o__stats_h
#define h2o__stats_h

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

struct st_h2o_context_t;
#define H2O_STATS_MAX_BUCKETS 100

typedef struct st_h2o_stat_ops_t {
    h2o_iovec_t name;
    h2o_iovec_t desc;
    size_t offset;
    size_t nr_elements;
    const char **labels;
    void (*aggregate)(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, struct st_h2o_context_t *per_thread);
    void (*stringify)(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
    void (*prometheus)(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
} h2o_stat_ops_t;

typedef struct st_h2o_histogram_t {
    struct {
        uint64_t upper_bound;
        uint64_t value;
    } buckets[H2O_STATS_MAX_BUCKETS];
    uint64_t inf;
    uint64_t sum;
    uint64_t count;
} h2o_histogram_t;

typedef struct st_h2o_metric_t {
    uint64_t counter;
    uint64_t gauge;
} h2o_metric_t;

static inline void h2o_histogram_init(h2o_histogram_t *hist, uint64_t start)
{
    size_t i;

    memset(hist, 0, sizeof(*hist));

    uint64_t interval = start;
    for (i = 0; i < H2O_STATS_MAX_BUCKETS; i++) {
        hist->buckets[i].upper_bound = interval;
        if ((int)(interval * 0.1) <= 1)
            interval++;
        else
            interval = interval + (int)(interval * 0.1);
    }
}

static inline void h2o_histogram_add_one(h2o_histogram_t *hist, uint64_t value)
{
    size_t i;

    hist->sum += value;
    hist->count++;

    for (i = 0; i < H2O_STATS_MAX_BUCKETS; i++) {
        /* prometheus uses `le` for lower or equal, mimic this */
        if (value <= hist->buckets[i].upper_bound) {
            hist->buckets[i].value++;
            return;
        }
    }
    hist->inf++;
}

void hist_aggregate(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, struct st_h2o_context_t *per_thread);
void hist_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void hist_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void counter_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void counter_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void gauge_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void gauge_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void metric_aggregate(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, struct st_h2o_context_t *per_thread);
void metric_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);
void metric_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf);

#endif
