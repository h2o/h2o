/*
 * Copyright (c) Fastly, Inc.
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

#include "h2o.h"

#define APPEND(buf_, str_, len_)                                                                                                   \
    do {                                                                                                                           \
        h2o_buffer_reserve((buf_), (*(buf_))->size + (len_));                                                                      \
        memcpy((*(buf_))->bytes + (*(buf_))->size, (str_), (len_));                                                                \
        (*buf_)->size += (len_);                                                                                                   \
    } while (0)

#define APPEND_STRLIT(buf_, lit_) APPEND((buf_), (lit_), sizeof(lit_) - 1)

#define APPEND_UINT64(buf_, i_)                                                                                                    \
    do {                                                                                                                           \
        char n_[sizeof(H2O_UINT64_LONGEST_STR)];                                                                                   \
        APPEND(buf_, n_, sprintf(n_, "%" PRIu64, (uint64_t)(i_)));                                                                 \
    } while (0)

#define APPEND_INT64(buf_, i_)                                                                                                     \
    do {                                                                                                                           \
        char n_[sizeof(H2O_INT64_LONGEST_STR)];                                                                                    \
        APPEND(buf_, n_, sprintf(n_, "%" PRId64, (int64_t)(i_)));                                                                  \
    } while (0)

#define APPEND_TYPE(standalone)                                                                                                    \
    do {                                                                                                                           \
        if (self->nr_elements > 1) {                                                                                               \
            if (standalone)                                                                                                        \
                APPEND_STRLIT(buf, "{");                                                                                           \
            else                                                                                                                   \
                APPEND_STRLIT(buf, "\",");                                                                                         \
            APPEND_STRLIT(buf, "type=\"");                                                                                         \
            if (self->labels != NULL) {                                                                                            \
                APPEND(buf, self->labels[i], strlen(self->labels[i]));                                                             \
            } else {                                                                                                               \
                APPEND_UINT64(buf, i);                                                                                             \
            }                                                                                                                      \
            APPEND_STRLIT(buf, "\"");                                                                                              \
            if (standalone)                                                                                                        \
                APPEND_STRLIT(buf, "}");                                                                                           \
        }                                                                                                                          \
    } while (0)

void hist_aggregate(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, struct st_h2o_context_t *per_thread)
{
    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_histogram_t *hist_agg = (h2o_histogram_t *)((char *)agg + self->offset + (i * sizeof(*hist_agg)));
        h2o_histogram_t *hist_pt = (h2o_histogram_t *)((char *)per_thread + self->offset);
        for (size_t j = 0; j < H2O_STATS_MAX_BUCKETS; ++j)
            hist_agg->buckets[j].value += hist_pt->buckets[j].value;
        hist_agg->inf += hist_pt->inf;
        hist_agg->sum += hist_pt->sum;
        hist_agg->count += hist_pt->count;
    }
}

void hist_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_histogram_t *hist = (h2o_histogram_t *)((char *)agg + self->offset + (i * sizeof(*hist)));

        APPEND_STRLIT(buf, "\"");
        APPEND(buf, self->name.base, self->name.len);
        if (self->nr_elements > 1) {
            APPEND_STRLIT(buf, "_");
            if (self->labels == NULL) {
                APPEND_UINT64(buf, i);
            } else {
                APPEND(buf, self->labels[i], strlen(self->labels[i]));
            }
        }
        APPEND_STRLIT(buf, "\": [");
        for (size_t j = 0; j < H2O_STATS_MAX_BUCKETS; ++j) {
            APPEND_UINT64(buf, hist->buckets[j].value);
            APPEND_STRLIT(buf, ", ");
        }
        APPEND_UINT64(buf, hist->inf);
        APPEND_STRLIT(buf, "]\n");
        if (self->nr_elements > 1 && i != self->nr_elements - 1)
            APPEND_STRLIT(buf, ", ");
    }
}

void hist_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    APPEND_STRLIT(buf, "# HELP h2o_");
    APPEND(buf, self->name.base, self->name.len);
    APPEND_STRLIT(buf, " ");
    APPEND(buf, self->desc.base, self->desc.len);
    APPEND_STRLIT(buf, "\n");
    APPEND_STRLIT(buf, "# TYPE h2o_");
    APPEND(buf, self->name.base, self->name.len);
    APPEND_STRLIT(buf, " histogram\n");

    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_histogram_t *hist = (h2o_histogram_t *)((char *)agg + self->offset + (i * sizeof(*hist)));

        for (size_t j = 0; j < H2O_STATS_MAX_BUCKETS && hist->buckets[j].upper_bound != SIZE_MAX; j++) {
            APPEND_STRLIT(buf, "h2o_");
            APPEND(buf, self->name.base, self->name.len);
            APPEND_STRLIT(buf, "_bucket {le=\"");
            APPEND_UINT64(buf, hist->buckets[j].upper_bound);
            APPEND_TYPE(0);
            APPEND_STRLIT(buf, "\"} ");
            APPEND_UINT64(buf, hist->buckets[j].value);
            APPEND_STRLIT(buf, "\n");
        }
        APPEND_STRLIT(buf, "h2o_");
        APPEND(buf, self->name.base, self->name.len);
        APPEND_STRLIT(buf, "_bucket {le=\"Inf");
        APPEND_TYPE(0);
        APPEND_STRLIT(buf, "\"} ");
        APPEND_UINT64(buf, hist->inf);
        APPEND_STRLIT(buf, "\n");

        APPEND_STRLIT(buf, "h2o_");
        APPEND(buf, self->name.base, self->name.len);
        APPEND_STRLIT(buf, "_sum");
        APPEND_TYPE(1);
        APPEND_STRLIT(buf, " ");
        APPEND_UINT64(buf, hist->sum);
        APPEND_STRLIT(buf, "\n");

        APPEND_STRLIT(buf, "h2o_");
        APPEND(buf, self->name.base, self->name.len);
        if (self->nr_elements > 1) {
            APPEND_STRLIT(buf, "_");
            APPEND_UINT64(buf, i);
        }
        APPEND_STRLIT(buf, "_count");
        APPEND_TYPE(1);
        APPEND_STRLIT(buf, " ");
        APPEND_UINT64(buf, hist->count);
        APPEND_STRLIT(buf, "\n");
    }
}

void counter_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_metric_t *metric = (h2o_metric_t *)((char *)agg + self->offset + (i * sizeof(*metric)));

        APPEND_STRLIT(buf, "\"");
        APPEND(buf, self->name.base, self->name.len);
        if (self->nr_elements > 1) {
            APPEND_STRLIT(buf, "_");
            if (self->labels == NULL)
                APPEND_UINT64(buf, i);
            else
                APPEND(buf, self->labels[i], strlen(self->labels[i]));
        }
        APPEND_STRLIT(buf, "_total\": ");
        APPEND_UINT64(buf, metric->counter);
        APPEND_STRLIT(buf, "\n");
        if (self->nr_elements > 1 && i != self->nr_elements - 1)
            APPEND_STRLIT(buf, ", ");
    }
}

void counter_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    APPEND_STRLIT(buf, "# HELP h2o_");
    APPEND(buf, self->name.base, self->name.len);
    APPEND_STRLIT(buf, "_total");
    APPEND_STRLIT(buf, " ");
    APPEND(buf, self->desc.base, self->desc.len);
    APPEND_STRLIT(buf, "\n");
    APPEND_STRLIT(buf, "# TYPE h2o_");
    APPEND(buf, self->name.base, self->name.len);
    APPEND_STRLIT(buf, "_total");
    APPEND_STRLIT(buf, " counter\n");
    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_metric_t *metric = (h2o_metric_t *)((char *)agg + self->offset + (i * sizeof(*metric)));

        APPEND_STRLIT(buf, "h2o_");
        APPEND(buf, self->name.base, self->name.len);
        APPEND_STRLIT(buf, "_total");
        APPEND_TYPE(1);
        APPEND_STRLIT(buf, " ");
        APPEND_UINT64(buf, metric->counter);
        APPEND_STRLIT(buf, "\n");
    }
}

void gauge_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_metric_t *metric = (h2o_metric_t *)((char *)agg + self->offset + (i * sizeof(*metric)));

        APPEND_STRLIT(buf, "\"");
        APPEND(buf, self->name.base, self->name.len);
        if (self->nr_elements > 1) {
            APPEND_STRLIT(buf, "_");
            if (self->labels == NULL)
                APPEND_UINT64(buf, i);
            else
                APPEND(buf, self->labels[i], strlen(self->labels[i]));
        }
        APPEND_STRLIT(buf, "\": ");
        APPEND_UINT64(buf, metric->gauge);
        APPEND_STRLIT(buf, "\n");
        if (self->nr_elements > 1 && i != self->nr_elements - 1)
            APPEND_STRLIT(buf, ", ");
    }
}

void gauge_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    APPEND_STRLIT(buf, "# HELP h2o_");
    APPEND(buf, self->name.base, self->name.len);
    APPEND_STRLIT(buf, " ");
    APPEND(buf, self->desc.base, self->desc.len);
    APPEND_STRLIT(buf, "\n");
    APPEND_STRLIT(buf, "# TYPE h2o_");
    APPEND(buf, self->name.base, self->name.len);
    APPEND_STRLIT(buf, " gauge\n");

    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_metric_t *metric = (h2o_metric_t *)((char *)agg + self->offset + (i * sizeof(*metric)));

        h2o_buffer_reserve(buf, (*buf)->size + 256);

        APPEND_STRLIT(buf, "h2o_");
        APPEND(buf, self->name.base, self->name.len);
        APPEND_TYPE(1);
        APPEND_STRLIT(buf, " ");
        APPEND_UINT64(buf, metric->gauge);
        APPEND_STRLIT(buf, "\n");
    }
}

void metric_aggregate(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, struct st_h2o_context_t *per_thread)
{
    for (size_t i = 0; i < self->nr_elements; i++) {
        h2o_metric_t *metric_agg = (h2o_metric_t *)((char *)agg + self->offset + (i * sizeof(*metric_agg)));
        h2o_metric_t *metric_per_thread = (h2o_metric_t *)((char *)per_thread + self->offset + (i * sizeof(*metric_per_thread)));
        metric_agg->counter += metric_per_thread->counter;
        metric_agg->gauge += metric_per_thread->gauge;
    }
}

void metric_stringify(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    counter_stringify(self, agg, buf);
    APPEND_STRLIT(buf, ",\n");
    gauge_stringify(self, agg, buf);
}

void metric_prometheus(const struct st_h2o_stat_ops_t *self, struct st_h2o_context_t *agg, h2o_buffer_t **buf)
{
    counter_prometheus(self, agg, buf);
    gauge_prometheus(self, agg, buf);
}
