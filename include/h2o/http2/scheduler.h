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
#ifndef h2o__http2__scheduler_h
#define h2o__http2__scheduler_h

#include <assert.h>
#include "h2o/linklist.h"
#include "h2o/memory.h"

typedef struct h2o_http2_scheduler_slot_t {
    uint16_t weight;
    h2o_linklist_t _all_refs; /* all openrefs */
    h2o_linklist_t _active_refs; /* openrefs that have data, that can be sent (incl. the dependents) */
} h2o_http2_scheduler_slot_t;

typedef struct st_h2o_http2_scheduler_node_t {
    struct st_h2o_http2_scheduler_node_t *_parent;
    h2o_http2_scheduler_slot_t *_slot;
    H2O_VECTOR(h2o_http2_scheduler_slot_t *) _list;
} h2o_http2_scheduler_node_t, h2o_http2_scheduler_t;

typedef struct st_h2o_http2_scheduler_openref_t {
    h2o_http2_scheduler_node_t super;
    h2o_linklist_t _all_link; /* linked to _all_refs */
    h2o_linklist_t _active_link; /* linked to _active_refs if is active */
    size_t _active_cnt; /* COUNT(active_streams_in_dependents) + _self_is_active */
    int _self_is_active;
} h2o_http2_scheduler_openref_t;

typedef int (*h2o_http2_scheduler_iterate_cb)(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg);

/* void h2o_http2_scheduler_init(h2o_http2_scheduler_t *scheduler); (zero-clear is sufficient for the time being) */
void h2o_http2_scheduler_dispose(h2o_http2_scheduler_t *scheduler);
void h2o_http2_scheduler_open(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_openref_t *ref, uint16_t weight);
void h2o_http2_scheduler_close(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_openref_t *ref);
void h2o_http2_scheduler_rebind(h2o_http2_scheduler_node_t *parent, h2o_http2_scheduler_openref_t *ref);
static int h2o_http2_scheduler_ref_is_open(h2o_http2_scheduler_openref_t *ref);
void h2o_http2_scheduler_set_active(h2o_http2_scheduler_openref_t *ref);
int h2o_http2_scheduler_iterate(h2o_http2_scheduler_t *scheduler, h2o_http2_scheduler_iterate_cb cb, void *cb_arg);

/* inline definitions */

inline int h2o_http2_scheduler_ref_is_open(h2o_http2_scheduler_openref_t *ref)
{
    return h2o_linklist_is_linked(&ref->_all_link);
}

#endif
