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

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

typedef struct st_quicly_maxsender_t {
    uint64_t max_sent;
    uint64_t max_acked;
    size_t num_inflight;
} quicly_maxsender_t;

typedef struct st_quicly_maxsender_ackargs_t {
    uint64_t value;
} quicly_maxsender_ackargs_t;

static void quicly_maxsender_init(quicly_maxsender_t *m, uint64_t initial_value);
static void quicly_maxsender_dispose(quicly_maxsender_t *m);
static void quicly_maxsender_reset(quicly_maxsender_t *m, uint64_t initial_value);
static int quicly_maxsender_should_update(quicly_maxsender_t *m, uint64_t buffered_from, uint32_t window_size,
                                          uint32_t update_ratio);
uint64_t quicly_maxsender_should_update_stream_id(quicly_maxsender_t *m, uint64_t next_stream_id, uint32_t num_open_streams,
                                                  uint32_t max_concurrent_streams, uint32_t update_ratio);
static void quicly_maxsender_record(quicly_maxsender_t *m, uint64_t value, quicly_maxsender_ackargs_t *args);
static void quicly_maxsender_acked(quicly_maxsender_t *m, quicly_maxsender_ackargs_t *args);
static void quicly_maxsender_lost(quicly_maxsender_t *m, quicly_maxsender_ackargs_t *args);

/* inline definitions */

inline void quicly_maxsender_init(quicly_maxsender_t *m, uint64_t initial_value)
{
    m->max_sent = initial_value;
    m->max_acked = initial_value;
    m->num_inflight = 0;
}

inline void quicly_maxsender_dispose(quicly_maxsender_t *m)
{
}

inline void quicly_maxsender_reset(quicly_maxsender_t *m, uint64_t initial_value)
{
    m->max_sent = initial_value;
    m->max_acked = initial_value;
}

inline int quicly_maxsender_should_update(quicly_maxsender_t *m, uint64_t buffered_from, uint32_t window_size,
                                          uint32_t update_ratio)
{
    /* ratio is permil (1/1024) */
    uint64_t threshold = buffered_from + ((uint64_t)window_size * update_ratio) / 1024;
    return m->max_sent <= threshold;
}

inline void quicly_maxsender_record(quicly_maxsender_t *m, uint64_t value, quicly_maxsender_ackargs_t *args)
{
    if (m->max_sent < value)
        m->max_sent = value;
    ++m->num_inflight;
    args->value = value;
}

inline void quicly_maxsender_acked(quicly_maxsender_t *m, quicly_maxsender_ackargs_t *args)
{
    if (m->max_acked < args->value)
        m->max_acked = args->value;
    --m->num_inflight;
}

inline void quicly_maxsender_lost(quicly_maxsender_t *m, quicly_maxsender_ackargs_t *args)
{
    if (--m->num_inflight == 0)
        m->max_sent = m->max_acked;
}

#endif
