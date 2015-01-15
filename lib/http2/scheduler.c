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
#include "h2o.h"
#include "h2o/http2.h"

h2o_http2_scheduler_slot_t *h2o_http2_scheduler_open(h2o_http2_scheduler_t *scheduler, uint16_t weight)
{
    h2o_http2_scheduler_slot_t *slot;
    size_t i;

    ++scheduler->refcnt;

    /* locate the slot */
    for (i = 0; i != scheduler->list.size; ++i) {
        slot = scheduler->list.entries[i];
        if (slot->weight == weight) {
            ++slot->refcnt;
            return slot;
        } else if (slot->weight < weight) {
            break;
        }
    }
    /* not found, create new slot */
    slot = h2o_mem_alloc(sizeof(*slot));
    slot->weight = weight;
    h2o_linklist_init_anchor(&slot->active_streams);
    slot->refcnt = 1;
    h2o_vector_reserve(NULL, (h2o_vector_t *)&scheduler->list, sizeof(scheduler->list.entries[0]), scheduler->list.size + 1);
    memmove(scheduler->list.entries + i + 1, scheduler->list.entries + i,
            sizeof(scheduler->list.entries[0]) * (scheduler->list.size - i));
    scheduler->list.entries[i] = slot;
    ++scheduler->list.size;
    return slot;
}

void h2o_http2_scheduler_close(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_slot_t *slot)
{
    assert(slot->refcnt != 0);
    assert(scheduler->refcnt != 0);
    --slot->refcnt;
    --scheduler->refcnt;
}

void h2o_http2_scheduler_dispose(h2o_http2_scheduler_t *scheduler)
{
    assert(scheduler->refcnt == 0);
    if (scheduler->list.size != 0) {
        size_t i;
        for (i = 0; i != scheduler->list.size; ++i) {
            h2o_http2_scheduler_slot_t *slot = scheduler->list.entries[i];
            assert(slot->refcnt == 0);
            assert(h2o_linklist_is_empty(&slot->active_streams));
            free(slot);
        }
        free(scheduler->list.entries);
    }
}
