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
#ifndef quicly_sentmap_h
#define quicly_sentmap_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include "quicly/constants.h"
#include "quicly/maxsender.h"
#include "quicly/sendstate.h"

typedef struct st_quicly_sent_t quicly_sent_t;
typedef struct st_quicly_sentmap_t quicly_sentmap_t;

typedef struct st_quicly_sent_packet_t {
    /**
     *
     */
    uint64_t packet_number;
    /**
     *
     */
    int64_t sent_at;
    /**
     * epoch to be acked in
     */
    uint8_t ack_epoch;
    /**
     *
     */
    uint8_t ack_eliciting : 1;
    /**
     * if the frames being contained are considered inflight (becomes zero when deemed lost or when PTO fires)
     */
    uint8_t frames_in_flight : 1;
    /**
     * number of bytes in-flight for the packet, from the context of CC (becomes zero when deemed lost, but not when PTO fires)
     */
    uint16_t cc_bytes_in_flight;
} quicly_sent_packet_t;

typedef enum en_quicly_sentmap_event_t {
    /**
     * a packet has been acked
     */
    QUICLY_SENTMAP_EVENT_ACKED,
    /**
     * PTO - the packet is still considered inflight, but the contents of the frames are scheduled for retransmission
     */
    QUICLY_SENTMAP_EVENT_PTO,
    /**
     * a packet is deemed lost
     */
    QUICLY_SENTMAP_EVENT_LOST,
    /**
     * a packet is being removed from the sentmap (e.g., after 3 pto, the epoch being discarded)
     */
    QUICLY_SENTMAP_EVENT_EXPIRED
} quicly_sentmap_event_t;

/**
 * Callback called when a frame is either acknowledged or deemed lost. When there is a late ACK, an entry will get marked as acked
 * after first being deemed lost.
 * @param map     sentmap
 * @param packet  the packet to which `quicly_sent_t` belongs to
 * @param acked   true if acked, false if the information has to be scheduled for retransmission
 * @param data    data
 */
typedef int (*quicly_sent_acked_cb)(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *data);

struct st_quicly_sent_t {
    quicly_sent_acked_cb acked;
    union {
        quicly_sent_packet_t packet;
        struct {
            quicly_range_t range;
        } ack;
        struct {
            quicly_stream_id_t stream_id;
            quicly_sendstate_sent_t args;
        } stream;
        struct {
            quicly_stream_id_t stream_id;
            quicly_maxsender_sent_t args;
        } max_stream_data;
        struct {
            quicly_maxsender_sent_t args;
        } max_data;
        struct {
            int uni;
            quicly_maxsender_sent_t args;
        } max_streams;
        struct {
            uint64_t offset;
        } data_blocked;
        struct {
            quicly_stream_id_t stream_id;
            uint64_t offset;
        } stream_data_blocked;
        struct {
            int uni;
            quicly_maxsender_sent_t args;
        } streams_blocked;
        struct {
            quicly_stream_id_t stream_id;
        } stream_state_sender;
        struct {
            int is_inflight;
            uint64_t generation;
        } new_token;
        struct {
            uint64_t sequence;
        } new_connection_id;
        struct {
            uint64_t sequence;
        } retire_connection_id;
    } data;
};

struct st_quicly_sent_block_t {
    /**
     * next block if exists (or NULL)
     */
    struct st_quicly_sent_block_t *next;
    /**
     * number of entries in the block
     */
    size_t num_entries;
    /**
     * insertion index within `entries`
     */
    size_t next_insert_at;
    /**
     * slots
     */
    quicly_sent_t entries[16];
};

/**
 * quicly_sentmap_t is a structure that holds a list of sent objects being tracked.  The list is a list of packet header and
 * frame-level objects of that packet.  Packet header is identified by quicly_sent_t::acked being quicly_sent__type_header.
 *
 * The transport writes to the sentmap in the following way:
 * 1. call quicly_sentmap_prepare
 * 2. repeatedly call quicly_sentmap_allocate to allocate frame-level objects and initialize them
 * 3. call quicly_sentmap_commit
 *
 * The transport iterates (and mutates) the sentmap in the following way:
 * 1. call quicly_sentmap_init_iter
 * 2. call quicly_sentmap_get to obtain the packet header that the iterator points to
 * 3. call quicly_sentmap_update to update the states of the packet that the iterator points to (as well as the state of the frames
 *    that were part of the packet) and move the iterator to the next packet header.  The function is also used for discarding
 * entries from the sent map.
 * 4. call quicly_sentmap_skip to move the iterator to the next packet header
 *
 * Note that quicly_sentmap_update and quicly_sentmap_skip move the iterator to the next packet header.
 */
struct st_quicly_sentmap_t {
    /**
     * the linked list includes entries that are deemed lost, but not expired yet
     */
    struct st_quicly_sent_block_t *head, *tail;
    /**
     * number of packets contained
     */
    size_t num_packets;
    /**
     * bytes in-flight
     */
    size_t bytes_in_flight;
    /**
     * is non-NULL between prepare and commit, pointing to the packet header that is being written to
     */
    quicly_sent_t *_pending_packet;
};

typedef struct st_quicly_sentmap_iter_t {
    quicly_sent_t *p;
    size_t count;
    struct st_quicly_sent_block_t **ref;
} quicly_sentmap_iter_t;

extern const quicly_sent_t quicly_sentmap__end_iter;

/**
 * initializes the sentmap
 */
static void quicly_sentmap_init(quicly_sentmap_t *map);
/**
 *
 */
void quicly_sentmap_dispose(quicly_sentmap_t *map);

/**
 * if transaction is open (i.e. between prepare and commit)
 */
static int quicly_sentmap_is_open(quicly_sentmap_t *map);
/**
 * prepares a write
 */
int quicly_sentmap_prepare(quicly_sentmap_t *map, uint64_t packet_number, int64_t now, uint8_t ack_epoch);
/**
 * commits a write
 */
static void quicly_sentmap_commit(quicly_sentmap_t *map, uint16_t bytes_in_flight);
/**
 * Allocates a slot to contain a callback for a frame.  The function MUST be called after _prepare but before _commit.
 */
static quicly_sent_t *quicly_sentmap_allocate(quicly_sentmap_t *map, quicly_sent_acked_cb acked);

/**
 * initializes the iterator
 */
static void quicly_sentmap_init_iter(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter);
/**
 * returns the current packet pointed to by the iterator
 */
static const quicly_sent_packet_t *quicly_sentmap_get(quicly_sentmap_iter_t *iter);
/**
 * advances the iterator to the next packet
 */
void quicly_sentmap_skip(quicly_sentmap_iter_t *iter);
/**
 * updates the state of the packet being pointed to by the iterator, _and advances to the next packet_
 */
int quicly_sentmap_update(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter, quicly_sentmap_event_t event);

struct st_quicly_sent_block_t *quicly_sentmap__new_block(quicly_sentmap_t *map);
int quicly_sentmap__type_packet(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent);

/* inline definitions */

inline void quicly_sentmap_init(quicly_sentmap_t *map)
{
    *map = (quicly_sentmap_t){NULL};
}

inline int quicly_sentmap_is_open(quicly_sentmap_t *map)
{
    return map->_pending_packet != NULL;
}

inline void quicly_sentmap_commit(quicly_sentmap_t *map, uint16_t bytes_in_flight)
{
    assert(quicly_sentmap_is_open(map));

    if (bytes_in_flight != 0) {
        map->_pending_packet->data.packet.ack_eliciting = 1;
        map->_pending_packet->data.packet.cc_bytes_in_flight = bytes_in_flight;
        map->bytes_in_flight += bytes_in_flight;
    }
    map->_pending_packet->data.packet.frames_in_flight = 1;
    map->_pending_packet = NULL;

    ++map->num_packets;
}

inline quicly_sent_t *quicly_sentmap_allocate(quicly_sentmap_t *map, quicly_sent_acked_cb acked)
{
    struct st_quicly_sent_block_t *block;

    if ((block = map->tail) == NULL || block->next_insert_at == PTLS_ELEMENTSOF(block->entries)) {
        if ((block = quicly_sentmap__new_block(map)) == NULL)
            return NULL;
    }

    quicly_sent_t *sent = block->entries + block->next_insert_at++;
    ++block->num_entries;

    sent->acked = acked;

    return sent;
}

inline void quicly_sentmap_init_iter(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter)
{
    /* set up the iterator */
    iter->ref = &map->head;
    if (map->head != NULL) {
        assert(map->head->num_entries != 0);
        for (iter->p = map->head->entries; iter->p->acked == NULL; ++iter->p)
            ;
        assert(iter->p->acked == quicly_sentmap__type_packet);
        iter->count = map->head->num_entries;
    } else {
        iter->p = (quicly_sent_t *)&quicly_sentmap__end_iter;
        iter->count = 0;
    }
}

inline const quicly_sent_packet_t *quicly_sentmap_get(quicly_sentmap_iter_t *iter)
{
    assert(iter->p->acked == quicly_sentmap__type_packet);
    return &iter->p->data.packet;
}

#ifdef __cplusplus
}
#endif

#endif
