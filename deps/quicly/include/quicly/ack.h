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
#ifndef quicly_ack_h
#define quicly_ack_h

#include <assert.h>
#include <stdint.h>
#include "quicly/constants.h"
#include "quicly/maxsender.h"
#include "quicly/sendbuf.h"

struct st_quicly_conn_t;
typedef struct st_quicly_ack_t quicly_ack_t;

typedef int (*quicly_ack_cb)(struct st_quicly_conn_t *conn, int is_acked, quicly_ack_t *data);

struct st_quicly_ack_t {
    uint64_t packet_number;
    int64_t sent_at;
    quicly_ack_cb acked;
    union {
        struct {
            quicly_stream_id_t stream_id;
            quicly_sendbuf_ackargs_t args;
        } stream;
        struct {
            quicly_stream_id_t stream_id;
            quicly_maxsender_ackargs_t args;
        } max_stream_data;
        struct {
            quicly_maxsender_ackargs_t args;
        } max_data;
        struct {
            quicly_maxsender_ackargs_t args;
        } max_stream_id;
        struct {
            quicly_stream_id_t stream_id;
        } stream_state_sender;
        struct {
            size_t bytes_in_flight;
        } cc;
    } data;
    unsigned is_active : 1;
};

struct st_quicly_ack_block_t {
    struct st_quicly_ack_block_t *next;
    size_t total, active;
    quicly_ack_t entries[16];
};

typedef struct st_quicly_acks_t {
    /**
     * the linked list includes entries that are deemed lost (up to 3*SRTT) as well
     */
    struct st_quicly_ack_block_t *head, *tail;
    /**
     * number of active entries
     */
    size_t num_active;
} quicly_acks_t;

typedef struct st_quicly_acks_iter_t {
    quicly_ack_t *p;
    size_t count;
    struct st_quicly_ack_block_t **ref;
} quicly_acks_iter_t;

extern const quicly_ack_t quicly_acks__end_iter;

static void quicly_acks_init(quicly_acks_t *acks);
void quicly_acks_dispose(quicly_acks_t *acks);
static quicly_ack_t *quicly_acks_allocate(quicly_acks_t *acks, uint64_t packet_number, uint64_t now, quicly_ack_cb acked);
static int quicly_acks_is_empty(quicly_acks_t *acks);
static quicly_ack_t *quicly_acks_get_tail(quicly_acks_t *acks);
struct st_quicly_ack_block_t *quicly_acks__new_block(quicly_acks_t *acks);
static int quicly_acks_on_ack(quicly_acks_t *acks, int is_acked, quicly_ack_t *ack, struct st_quicly_conn_t *conn);
static void quicly_acks_init_iter(quicly_acks_t *acks, quicly_acks_iter_t *iter);
static quicly_ack_t *quicly_acks_get(quicly_acks_iter_t *iter);
static void quicly_acks_next(quicly_acks_iter_t *iter);
static void quicly_acks_release(quicly_acks_t *acks, quicly_acks_iter_t *iter);
struct st_quicly_ack_block_t **quicly_acks__release_block(quicly_acks_t *acks, struct st_quicly_ack_block_t **ref);

/* inline definitions */

inline void quicly_acks_init(quicly_acks_t *acks)
{
    acks->head = NULL;
    acks->tail = NULL;
}

inline quicly_ack_t *quicly_acks_allocate(quicly_acks_t *acks, uint64_t packet_number, uint64_t now, quicly_ack_cb acked)
{
    struct st_quicly_ack_block_t *block;

    if ((block = acks->tail) == NULL || block->total == sizeof(block->entries) / sizeof(block->entries[0])) {
        if ((block = quicly_acks__new_block(acks)) == NULL)
            return NULL;
    }

    quicly_ack_t *ack = block->entries + block->total++;
    ++block->active;

    ack->packet_number = packet_number;
    ack->sent_at = now;
    ack->acked = acked;
    ack->is_active = 1;
    ++acks->num_active;

    return ack;
}

inline int quicly_acks_is_empty(quicly_acks_t *acks)
{
    return acks->head == NULL;
}

inline quicly_ack_t *quicly_acks_get_tail(quicly_acks_t *acks)
{
    return acks->tail->entries + acks->tail->total - 1;
}

inline int quicly_acks_on_ack(quicly_acks_t *acks, int is_acked, quicly_ack_t *ack, struct st_quicly_conn_t *conn)
{
    int ret;

    assert(ack->is_active || is_acked);

    if ((ret = ack->acked(conn, is_acked, ack)) != 0)
        return ret;

    if (ack->is_active) {
        ack->is_active = 0;
        --acks->num_active;
    }
    return 0;
}

inline void quicly_acks_init_iter(quicly_acks_t *acks, quicly_acks_iter_t *iter)
{
    iter->ref = &acks->head;
    if (acks->head != NULL) {
        assert(acks->head->active != 0);
        for (iter->p = acks->head->entries; iter->p->acked == NULL; ++iter->p)
            ;
        iter->count = acks->head->active;
    } else {
        iter->p = (void *)&quicly_acks__end_iter;
        iter->count = 0;
    }
}

inline quicly_ack_t *quicly_acks_get(quicly_acks_iter_t *iter)
{
    return iter->p;
}

inline void quicly_acks_next(quicly_acks_iter_t *iter)
{
    if (--iter->count != 0) {
        ++iter->p;
    } else if (*(iter->ref = &(*iter->ref)->next) == NULL) {
        iter->p = (void *)&quicly_acks__end_iter;
        iter->count = 0;
        return;
    } else {
        assert((*iter->ref)->active != 0);
        iter->count = (*iter->ref)->active;
        iter->p = (*iter->ref)->entries;
    }
    while (iter->p->acked == NULL)
        ++iter->p;
}

inline void quicly_acks_release(quicly_acks_t *acks, quicly_acks_iter_t *iter)
{
    assert(iter->p->acked != NULL);
    assert(!iter->p->is_active);
    iter->p->acked = NULL;

    struct st_quicly_ack_block_t *block = *iter->ref;
    if (--block->active == 0) {
        iter->ref = quicly_acks__release_block(acks, iter->ref);
        block = *iter->ref;
        iter->p = block->entries - 1;
        iter->count = block->active + 1;
    }
}

#endif
