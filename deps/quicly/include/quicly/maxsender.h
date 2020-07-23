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
#ifndef quicly_maxsender_h
#define quicly_maxsender_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"

typedef struct st_quicly_maxsender_t {
    /**
     * maximum value being announced (never decreases)
     */
    int64_t max_committed;
    /**
     * maximum value being acked by remote peer
     */
    int64_t max_acked;
    /**
     * number of maximums inflight
     */
    size_t num_inflight;
    /**
     *
     */
    unsigned force_send : 1;
} quicly_maxsender_t;

typedef struct st_quicly_maxsender_sent_t {
    uint64_t inflight : 1;
    uint64_t value : 63;
} quicly_maxsender_sent_t;

static void quicly_maxsender_init(quicly_maxsender_t *m, int64_t initial_value);
static void quicly_maxsender_dispose(quicly_maxsender_t *m);
static void quicly_maxsender_request_transmit(quicly_maxsender_t *m);
static int quicly_maxsender_should_send_max(quicly_maxsender_t *m, int64_t buffered_from, uint32_t window_size,
                                            uint32_t update_ratio);
static int quicly_maxsender_should_send_blocked(quicly_maxsender_t *m, int64_t local_max);
static void quicly_maxsender_record(quicly_maxsender_t *m, int64_t value, quicly_maxsender_sent_t *sent);
static void quicly_maxsender_acked(quicly_maxsender_t *m, quicly_maxsender_sent_t *sent);
static void quicly_maxsender_lost(quicly_maxsender_t *m, quicly_maxsender_sent_t *sent);

/* inline definitions */

inline void quicly_maxsender_init(quicly_maxsender_t *m, int64_t initial_value)
{
    m->max_committed = initial_value;
    m->max_acked = initial_value;
    m->num_inflight = 0;
    m->force_send = 0;
}

inline void quicly_maxsender_dispose(quicly_maxsender_t *m)
{
}

inline void quicly_maxsender_request_transmit(quicly_maxsender_t *m)
{
    m->force_send = 1;
}

inline int quicly_maxsender_should_send_max(quicly_maxsender_t *m, int64_t buffered_from, uint32_t window_size,
                                            uint32_t update_ratio)
{
    if (m->force_send)
        return 1;

    /* ratio is permil (1/1024) */
    int64_t threshold = buffered_from + ((int64_t)window_size * update_ratio) / 1024;
    return (m->num_inflight != 0 ? m->max_committed : m->max_acked) <= threshold;
}

inline int quicly_maxsender_should_send_blocked(quicly_maxsender_t *m, int64_t local_max)
{
    return m->max_committed < local_max;
}

inline void quicly_maxsender_record(quicly_maxsender_t *m, int64_t value, quicly_maxsender_sent_t *sent)
{
    assert(value >= m->max_committed);
    m->max_committed = value;
    ++m->num_inflight;
    m->force_send = 0;
    sent->inflight = 1;
    sent->value = value;
}

inline void quicly_maxsender_acked(quicly_maxsender_t *m, quicly_maxsender_sent_t *sent)
{
    if (m->max_acked < sent->value)
        m->max_acked = sent->value;
    /* num_inflight should not be adjusted in case of a late ACK */
    if (sent->inflight) {
        assert(m->num_inflight != 0);
        --m->num_inflight;
        sent->inflight = 0;
    }
}

inline void quicly_maxsender_lost(quicly_maxsender_t *m, quicly_maxsender_sent_t *sent)
{
    /* the function must be called at most once (when LOST event occurs, but not EXPIRED), hence assert and always decrement */
    assert(m->num_inflight != 0);
    --m->num_inflight;
    sent->inflight = 0;
}

#ifdef __cplusplus
}
#endif

#endif
