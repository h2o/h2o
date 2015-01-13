/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http2.h"
#include "internal.h"

void h2o_http2_scheduler_init(h2o_http2_scheduler_t *scheduler)
{
    memset(&scheduler->_slots, 0, sizeof(scheduler->_slots));
    h2o_linklist_init_anchor(&scheduler->_starved);
}

void h2o_http2_scheduler_destroy(h2o_http2_scheduler_t *scheduler)
{
    if (scheduler->_slots.size != 0) {
        size_t i;
        for (i = 0; i != scheduler->_slots.size; ++i) {
            h2o_http2_sched_slot_t *slot = scheduler->_slots.entries[i];
            assert(slot->_refcnt == 0);
            assert(h2o_linklist_is_empty(&slot->_active));
            assert(h2o_linklist_is_empty(&slot->_blocked));
            free(slot);
        }
        free(scheduler->_slots.entries);
    }
    assert(h2o_linklist_is_empty(&scheduler->_starved));
}

h2o_linklist_t *h2o_http2_scheduler_iterate(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_iterator_t *iter)
{
    for (; iter->slot_index != scheduler->_slots.size; ++iter->slot_index) {
        h2o_http2_sched_slot_t *slot = scheduler->_slots.entries[iter->slot_index];
        if (! h2o_linklist_is_empty(&slot->_active)) {
            h2o_linklist_t *link = slot->_active.next;
            h2o_linklist_unlink(link);
            return link;
        }
    }
    return NULL;
}

h2o_http2_sched_slot_t *h2o_http2_scheduler_open(h2o_http2_scheduler_t *scheduler, uint16_t weight)
{
    h2o_http2_sched_slot_t *slot;
    size_t i;

    /* locate the slot */
    for (i = 0; i != scheduler->_slots.size; ++i) {
        slot = scheduler->_slots.entries[i];
        if (slot->weight == weight) {
            ++slot->_refcnt;
            return slot;
        } else if (slot->weight < weight) {
            break;
        }
    }
    /* not found, create new slot */
    slot = h2o_mem_alloc(sizeof(*slot));
    slot->weight = weight;
    h2o_linklist_init_anchor(&slot->_active);
    h2o_linklist_init_anchor(&slot->_blocked);
    slot->_refcnt = 1;
    h2o_vector_reserve(NULL, (h2o_vector_t*)&scheduler->_slots, sizeof(scheduler->_slots.entries[0]), scheduler->_slots.size + 1);
    memmove(scheduler->_slots.entries + i + 1, scheduler->_slots.entries + i, sizeof(scheduler->_slots.entries[0]) * (scheduler->_slots.size - i));
    scheduler->_slots.entries[i] = slot;
    ++scheduler->_slots.size;
    return slot;
}

void h2o_http2_scheduler_close(h2o_http2_scheduler_t *scheduler, h2o_http2_sched_slot_t *slot)
{
    assert(slot->_refcnt != 0);
    --slot->_refcnt;
}
