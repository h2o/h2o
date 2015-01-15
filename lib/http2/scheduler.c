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

void h2o_http2_scheduler_open(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_openref_t *ref, uint16_t weight)
{
    h2o_http2_scheduler_slot_t *slot;
    size_t i;

    /* locate the slot */
    for (i = 0; i != scheduler->_list.size; ++i) {
        slot = scheduler->_list.entries[i];
        if (slot->weight == weight) {
            ++slot->_refcnt;
            goto Exit;
        } else if (slot->weight < weight) {
            break;
        }
    }
    /* not found, create new slot */
    slot = h2o_mem_alloc(sizeof(*slot));
    slot->weight = weight;
    h2o_linklist_init_anchor(&slot->_active_streams);
    slot->_refcnt = 1;
    h2o_vector_reserve(NULL, (h2o_vector_t *)&scheduler->_list, sizeof(scheduler->_list.entries[0]), scheduler->_list.size + 1);
    memmove(scheduler->_list.entries + i + 1, scheduler->_list.entries + i,
            sizeof(scheduler->_list.entries[0]) * (scheduler->_list.size - i));
    scheduler->_list.entries[i] = slot;
    ++scheduler->_list.size;

Exit:
    ref->_slot = slot;
}

void h2o_http2_scheduler_close(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_openref_t *ref)
{
    assert(ref->_slot->_refcnt != 0);
    --ref->_slot->_refcnt;
    ref->_slot = NULL;
}

void h2o_http2_scheduler_dispose(h2o_http2_scheduler_t *scheduler)
{
    if (scheduler->_list.size != 0) {
        size_t i;
        for (i = 0; i != scheduler->_list.size; ++i) {
            h2o_http2_scheduler_slot_t *slot = scheduler->_list.entries[i];
            assert(slot->_refcnt == 0);
            assert(h2o_linklist_is_empty(&slot->_active_streams));
            free(slot);
        }
        free(scheduler->_list.entries);
    }
}
