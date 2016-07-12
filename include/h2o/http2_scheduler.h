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

typedef struct st_h2o_http2_scheduler_queue_node_t {
    h2o_linklist_t _link;
    size_t _deficit;
} h2o_http2_scheduler_queue_node_t;

typedef struct st_h2o_http2_scheduler_queue_t h2o_http2_scheduler_queue_t;

/**
 * resembles a node in the dependency tree; i.e. assigned for each HTTP/2 stream (as a member of openref), or the root of the tree
 * associated to the connection
 */
typedef struct st_h2o_http2_scheduler_node_t {
    struct st_h2o_http2_scheduler_node_t *_parent; /* NULL if root */
    h2o_linklist_t _all_refs;                      /* list of nodes */
    h2o_http2_scheduler_queue_t *_queue;           /* priority list (NULL if _all_refs is empty) */
} h2o_http2_scheduler_node_t;

/**
 * the entry to be scheduled; is assigned for every HTTP/2 stream.
 */
typedef struct st_h2o_http2_scheduler_openref_t {
    h2o_http2_scheduler_node_t node;
    uint16_t weight;
    h2o_linklist_t _all_link; /* linked to _all_refs */
    size_t _active_cnt;       /* COUNT(active_streams_in_dependents) + _self_is_active */
    int _self_is_active;
    h2o_http2_scheduler_queue_node_t _queue_node;
} h2o_http2_scheduler_openref_t;

/**
 * callback called by h2o_http2_scheduler_run.
 * @param ref reference to an active stream that should consume resource
 * @param still_is_active [out] flag to indicate whether the ref should still be marked as active after returning from the function
 * @param cb_arg value of cb_arg passed to h2o_http2_scheduler_run
 * @return non-zero value to stop traversing through the tree, or 0 to continue
 */
typedef int (*h2o_http2_scheduler_run_cb)(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *cb_arg);

/**
 *
 */
void h2o_http2_scheduler_init(h2o_http2_scheduler_node_t *root);

/**
 * disposes of the scheduler.  All open references belonging to the node must be closed before calling this functions.
 */
void h2o_http2_scheduler_dispose(h2o_http2_scheduler_node_t *root);
/**
 * opens a reference with given parent as its dependency
 */
void h2o_http2_scheduler_open(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *parent, uint16_t weight,
                              int exclusive);
/**
 * closes a reference.  All the dependents are raised to become the dependents of the parent of the reference being closed.
 */
void h2o_http2_scheduler_close(h2o_http2_scheduler_openref_t *ref);
/**
 * reprioritizes the reference.
 */
void h2o_http2_scheduler_rebind(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *new_parent, uint16_t weight,
                                int exclusive);
/**
 * tests if the ref is open
 */
static int h2o_http2_scheduler_is_open(h2o_http2_scheduler_openref_t *ref);
/**
 * returns weight associated to the reference
 */
static uint16_t h2o_http2_scheduler_get_weight(h2o_http2_scheduler_openref_t *ref);
/**
 * returns the parent
 */
static h2o_http2_scheduler_node_t *h2o_http2_scheduler_get_parent(h2o_http2_scheduler_openref_t *ref);
/**
 * activates a reference so that it would be passed back as the argument to the callback of the h2o_http2_scheduler_run function
 * if any resource should be allocated
 */
void h2o_http2_scheduler_activate(h2o_http2_scheduler_openref_t *ref);
/**
 * calls the callback of the references linked to the dependency tree one by one, in the order defined by the dependency and the
 * weight.
 */
int h2o_http2_scheduler_run(h2o_http2_scheduler_node_t *root, h2o_http2_scheduler_run_cb cb, void *cb_arg);
/**
 * returns if there are any active entries nodes in the scheduler (may have false positives, but no false negatives)
 */
int h2o_http2_scheduler_is_active(h2o_http2_scheduler_node_t *root);

/* inline definitions */

inline int h2o_http2_scheduler_is_open(h2o_http2_scheduler_openref_t *ref)
{
    return h2o_linklist_is_linked(&ref->_all_link);
}

inline uint16_t h2o_http2_scheduler_get_weight(h2o_http2_scheduler_openref_t *ref)
{
    return ref->weight;
}

inline h2o_http2_scheduler_node_t *h2o_http2_scheduler_get_parent(h2o_http2_scheduler_openref_t *ref)
{
    return ref->node._parent;
}

#endif
