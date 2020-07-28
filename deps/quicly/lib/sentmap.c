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
#include <assert.h>
#include <stdlib.h>
#include "picotls.h"
#include "quicly/sentmap.h"

const quicly_sent_t quicly_sentmap__end_iter = {quicly_sentmap__type_packet, {{UINT64_MAX, INT64_MAX}}};

static void next_entry(quicly_sentmap_iter_t *iter)
{
    if (--iter->count != 0) {
        ++iter->p;
    } else if (*(iter->ref = &(*iter->ref)->next) == NULL) {
        iter->p = (quicly_sent_t *)&quicly_sentmap__end_iter;
        iter->count = 0;
        return;
    } else {
        assert((*iter->ref)->num_entries != 0);
        iter->count = (*iter->ref)->num_entries;
        iter->p = (*iter->ref)->entries;
    }
    while (iter->p->acked == NULL)
        ++iter->p;
}

static struct st_quicly_sent_block_t **free_block(quicly_sentmap_t *map, struct st_quicly_sent_block_t **ref)
{
    static const struct st_quicly_sent_block_t dummy = {NULL};
    static const struct st_quicly_sent_block_t *const dummy_ref = &dummy;
    struct st_quicly_sent_block_t *block = *ref;

    if (block->next != NULL) {
        *ref = block->next;
        assert((*ref)->num_entries != 0);
    } else {
        assert(block == map->tail);
        if (ref == &map->head) {
            map->head = NULL;
            map->tail = NULL;
        } else {
            map->tail = (void *)((char *)ref - offsetof(struct st_quicly_sent_block_t, next));
            map->tail->next = NULL;
        }
        ref = (struct st_quicly_sent_block_t **)&dummy_ref;
    }

    free(block);
    return ref;
}

static void discard_entry(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter)
{
    assert(iter->p->acked != NULL);
    iter->p->acked = NULL;

    struct st_quicly_sent_block_t *block = *iter->ref;
    if (--block->num_entries == 0) {
        iter->ref = free_block(map, iter->ref);
        block = *iter->ref;
        iter->p = block->entries - 1;
        iter->count = block->num_entries + 1;
    }
}

void quicly_sentmap_dispose(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;

    while ((block = map->head) != NULL) {
        map->head = block->next;
        free(block);
    }
}

int quicly_sentmap_prepare(quicly_sentmap_t *map, uint64_t packet_number, int64_t now, uint8_t ack_epoch)
{
    assert(map->_pending_packet == NULL);

    if ((map->_pending_packet = quicly_sentmap_allocate(map, quicly_sentmap__type_packet)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    map->_pending_packet->data.packet = (quicly_sent_packet_t){packet_number, now, ack_epoch};
    return 0;
}

struct st_quicly_sent_block_t *quicly_sentmap__new_block(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;

    if ((block = malloc(sizeof(*block))) == NULL)
        return NULL;

    block->next = NULL;
    block->num_entries = 0;
    block->next_insert_at = 0;
    if (map->tail != NULL) {
        map->tail->next = block;
        map->tail = block;
    } else {
        map->head = map->tail = block;
    }

    return block;
}

void quicly_sentmap_skip(quicly_sentmap_iter_t *iter)
{
    do {
        next_entry(iter);
    } while (iter->p->acked != quicly_sentmap__type_packet);
}

int quicly_sentmap_update(quicly_sentmap_t *map, quicly_sentmap_iter_t *iter, quicly_sentmap_event_t event)
{
    quicly_sent_packet_t packet;
    int ret = 0;

    assert(iter->p != &quicly_sentmap__end_iter);
    assert(iter->p->acked == quicly_sentmap__type_packet);

    /* copy packet info */
    packet = iter->p->data.packet;

    /* update CC state unless the event is PTO */
    if (packet.cc_bytes_in_flight != 0 && event != QUICLY_SENTMAP_EVENT_PTO) {
        assert(map->bytes_in_flight >= packet.cc_bytes_in_flight);
        map->bytes_in_flight -= packet.cc_bytes_in_flight;
        iter->p->data.packet.cc_bytes_in_flight = 0;
    }
    iter->p->data.packet.frames_in_flight = 0;

    int should_notify = event == QUICLY_SENTMAP_EVENT_ACKED || packet.frames_in_flight,
        should_discard = event == QUICLY_SENTMAP_EVENT_ACKED || event == QUICLY_SENTMAP_EVENT_EXPIRED;

    /* Advance to next packet, while if necessary, doing either or both of the following:
     * * discard entries (if should_discard is set)
     * * invoke the frame-level callbacks (if should_notify is set) */
    if (should_discard) {
        discard_entry(map, iter);
        --map->num_packets;
    }
    for (next_entry(iter); iter->p->acked != quicly_sentmap__type_packet; next_entry(iter)) {
        if (should_notify && (ret = iter->p->acked(map, &packet, event == QUICLY_SENTMAP_EVENT_ACKED, iter->p)) != 0)
            goto Exit;
        if (should_discard)
            discard_entry(map, iter);
    }

Exit:
    return ret;
}

int quicly_sentmap__type_packet(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    assert(!"quicly_sentmap__type_packet cannot be called");
    return QUICLY_TRANSPORT_ERROR_INTERNAL;
}
