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
#include "h2o/http2_scheduler.h"

struct st_h2o_http2_scheduler_queue_t {
    uint64_t bits;
    size_t offset;
    h2o_linklist_t anchors[64];
    h2o_linklist_t anchor257;
};

static void queue_init(h2o_http2_scheduler_queue_t *queue)
{
    size_t i;
    queue->bits = 0;
    queue->offset = 0;
    for (i = 0; i != sizeof(queue->anchors) / sizeof(queue->anchors[0]); ++i)
        h2o_linklist_init_anchor(queue->anchors + i);
    h2o_linklist_init_anchor(&queue->anchor257);
}

static int queue_is_empty(h2o_http2_scheduler_queue_t *queue)
{
    return queue->bits == 0 && h2o_linklist_is_empty(&queue->anchor257);
}

static void queue_set(h2o_http2_scheduler_queue_t *queue, h2o_http2_scheduler_queue_node_t *node, uint16_t weight)
{
    /* holds 257 entries of offsets (multiplied by 65536) where nodes with weights between 1..257 should go into
     * each entry (expect for weight=256) is calculated as: round(N / weight), where N is adjusted so that the
     * value would become 63*65536 for weight=0.
     * weight=257 is used internally to send data before any of the streams being pulled, and therefore has the offset set to zero.
     */
    static const unsigned OFFSET_TABLE[] = {
        4128768, 2064384, 1376256, 1032192, 825754, 688128, 589824, 516096, 458752, 412877, 375343, 344064, 317598, 294912, 275251,
        258048,  242869,  229376,  217304,  206438, 196608, 187671, 179512, 172032, 165151, 158799, 152917, 147456, 142371, 137626,
        133186,  129024,  125114,  121434,  117965, 114688, 111588, 108652, 105866, 103219, 100702, 98304,  96018,  93836,  91750,
        89756,   87846,   86016,   84261,   82575,  80956,  79399,  77901,  76459,  75069,  73728,  72435,  71186,  69979,  68813,
        67685,   66593,   65536,   64512,   63520,  62557,  61623,  60717,  59837,  58982,  58152,  57344,  56558,  55794,  55050,
        54326,   53620,   52933,   52263,   51610,  50972,  50351,  49744,  49152,  48574,  48009,  47457,  46918,  46391,  45875,
        45371,   44878,   44395,   43923,   43461,  43008,  42565,  42130,  41705,  41288,  40879,  40478,  40085,  39700,  39322,
        38951,   38587,   38229,   37879,   37534,  37196,  36864,  36538,  36217,  35902,  35593,  35289,  34990,  34696,  34406,
        34122,   33842,   33567,   33297,   33030,  32768,  32510,  32256,  32006,  31760,  31517,  31279,  31043,  30812,  30583,
        30359,   30137,   29919,   29703,   29491,  29282,  29076,  28873,  28672,  28474,  28279,  28087,  27897,  27710,  27525,
        27343,   27163,   26985,   26810,   26637,  26466,  26298,  26131,  25967,  25805,  25645,  25486,  25330,  25175,  25023,
        24872,   24723,   24576,   24431,   24287,  24145,  24004,  23866,  23729,  23593,  23459,  23326,  23195,  23066,  22938,
        22811,   22686,   22562,   22439,   22318,  22198,  22079,  21962,  21845,  21730,  21617,  21504,  21393,  21282,  21173,
        21065,   20958,   20852,   20748,   20644,  20541,  20439,  20339,  20239,  20140,  20043,  19946,  19850,  19755,  19661,
        19568,   19475,   19384,   19293,   19204,  19115,  19027,  18939,  18853,  18767,  18682,  18598,  18515,  18432,  18350,
        18269,   18188,   18109,   18030,   17951,  17873,  17796,  17720,  17644,  17569,  17495,  17421,  17348,  17275,  17203,
        17132,   17061,   16991,   16921,   16852,  16784,  16716,  16648,  16581,  16515,  16449,  16384,  16319,  16255,  16191,
        16128,   0};

    assert(!h2o_linklist_is_linked(&node->_link));

    if (weight > 256) {

        h2o_linklist_insert(&queue->anchor257, &node->_link);

    } else {

        assert(1 <= weight);

        size_t offset = OFFSET_TABLE[weight - 1] + node->_deficit;
        node->_deficit = offset % 65536;
        offset = offset / 65536;

        queue->bits |= 1ULL << (sizeof(queue->bits) * 8 - 1 - offset);
        h2o_linklist_insert(queue->anchors + (queue->offset + offset) % (sizeof(queue->anchors) / sizeof(queue->anchors[0])),
                            &node->_link);
    }
}

static void queue_unset(h2o_http2_scheduler_queue_node_t *node)
{
    assert(h2o_linklist_is_linked(&node->_link));
    h2o_linklist_unlink(&node->_link);
}

static h2o_http2_scheduler_queue_node_t *queue_pop(h2o_http2_scheduler_queue_t *queue)
{
    if (!h2o_linklist_is_empty(&queue->anchor257)) {
        h2o_http2_scheduler_queue_node_t *node =
            H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_queue_node_t, _link, queue->anchor257.next);
        h2o_linklist_unlink(&node->_link);
        return node;
    }

    while (queue->bits != 0) {
        int zeroes = __builtin_clzll(queue->bits);
        queue->bits <<= zeroes;
        queue->offset = (queue->offset + zeroes) % (sizeof(queue->anchors) / sizeof(queue->anchors[0]));
        if (!h2o_linklist_is_empty(queue->anchors + queue->offset)) {
            h2o_http2_scheduler_queue_node_t *node =
                H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_queue_node_t, _link, queue->anchors[queue->offset].next);
            h2o_linklist_unlink(&node->_link);
            if (h2o_linklist_is_empty(queue->anchors + queue->offset))
                queue->bits &= (1ULL << (sizeof(queue->bits) * 8 - 1)) - 1;
            return node;
        }
        queue->bits &= (1ULL << (sizeof(queue->bits) * 8 - 1)) - 1;
    }
    return NULL;
}

static void init_node(h2o_http2_scheduler_node_t *node, h2o_http2_scheduler_node_t *parent)
{
    *node = (h2o_http2_scheduler_node_t){parent};
    h2o_linklist_init_anchor(&node->_all_refs);
}

static h2o_http2_scheduler_queue_t *get_queue(h2o_http2_scheduler_node_t *node)
{
    if (node->_queue == NULL) {
        node->_queue = h2o_mem_alloc(sizeof(*node->_queue));
        queue_init(node->_queue);
    }
    return node->_queue;
}

static void incr_active_cnt(h2o_http2_scheduler_node_t *node)
{
    h2o_http2_scheduler_openref_t *ref;

    /* do nothing if node is the root */
    if (node->_parent == NULL)
        return;

    ref = (h2o_http2_scheduler_openref_t *)node;
    if (++ref->_active_cnt != 1)
        return;
    /* just changed to active */
    queue_set(get_queue(ref->node._parent), &ref->_queue_node, ref->weight);
    /* delegate the change towards root */
    incr_active_cnt(ref->node._parent);
}

static void decr_active_cnt(h2o_http2_scheduler_node_t *node)
{
    h2o_http2_scheduler_openref_t *ref;

    /* do notnig if node is the root */
    if (node->_parent == NULL)
        return;

    ref = (h2o_http2_scheduler_openref_t *)node;
    if (--ref->_active_cnt != 0)
        return;
    /* just changed to inactive */
    queue_unset(&ref->_queue_node);
    /* delegate the change towards root */
    decr_active_cnt(ref->node._parent);
}

static void convert_to_exclusive(h2o_http2_scheduler_node_t *parent, h2o_http2_scheduler_openref_t *added)
{
    while (!h2o_linklist_is_empty(&parent->_all_refs)) {
        h2o_http2_scheduler_openref_t *child_ref =
            H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, parent->_all_refs.next);
        if (child_ref == added) {
            /* precond: the added node should exist as the last item within parent */
            assert(parent->_all_refs.prev == &added->_all_link);
            break;
        }
        h2o_http2_scheduler_rebind(child_ref, &added->node, h2o_http2_scheduler_get_weight(child_ref), 0);
    }
}

void h2o_http2_scheduler_open(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *parent, uint16_t weight,
                              int exclusive)
{
    init_node(&ref->node, parent);
    ref->weight = weight;
    ref->_all_link = (h2o_linklist_t){NULL};
    ref->_active_cnt = 0;
    ref->_self_is_active = 0;
    ref->_queue_node = (h2o_http2_scheduler_queue_node_t){{NULL}};

    h2o_linklist_insert(&parent->_all_refs, &ref->_all_link);

    if (exclusive)
        convert_to_exclusive(parent, ref);
}

void h2o_http2_scheduler_close(h2o_http2_scheduler_openref_t *ref)
{
    assert(h2o_http2_scheduler_is_open(ref));

    /* move dependents to parent */
    if (!h2o_linklist_is_empty(&ref->node._all_refs)) {
        /* proportionally distribute the weight to the children (draft-16 5.3.4) */
        uint32_t total_weight = 0, factor;
        h2o_linklist_t *link;
        for (link = ref->node._all_refs.next; link != &ref->node._all_refs; link = link->next) {
            h2o_http2_scheduler_openref_t *child_ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, link);
            total_weight += child_ref->weight;
        }
        assert(total_weight != 0);
        factor = ((uint32_t)ref->weight * 65536 + total_weight / 2) / total_weight;
        do {
            h2o_http2_scheduler_openref_t *child_ref =
                H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, ref->node._all_refs.next);
            uint16_t weight = (child_ref->weight * factor / 32768 + 1) / 2;
            if (weight < 1)
                weight = 1;
            else if (weight > 256)
                weight = 256;
            h2o_http2_scheduler_rebind(child_ref, ref->node._parent, weight, 0);
        } while (!h2o_linklist_is_empty(&ref->node._all_refs));
    }

    free(ref->node._queue);
    ref->node._queue = NULL;

    /* detach self */
    h2o_linklist_unlink(&ref->_all_link);
    if (ref->_self_is_active) {
        assert(ref->_active_cnt == 1);
        queue_unset(&ref->_queue_node);
        decr_active_cnt(ref->node._parent);
    } else {
        assert(ref->_active_cnt == 0);
    }
}

static void do_rebind(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *new_parent, int exclusive)
{
    /* rebind _all_link */
    h2o_linklist_unlink(&ref->_all_link);
    h2o_linklist_insert(&new_parent->_all_refs, &ref->_all_link);
    /* rebind to WRR (as well as adjust active_cnt) */
    if (ref->_active_cnt != 0) {
        queue_unset(&ref->_queue_node);
        queue_set(get_queue(new_parent), &ref->_queue_node, ref->weight);
        decr_active_cnt(ref->node._parent);
        incr_active_cnt(new_parent);
    }
    /* update the backlinks */
    ref->node._parent = new_parent;

    if (exclusive)
        convert_to_exclusive(new_parent, ref);
}

void h2o_http2_scheduler_rebind(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *new_parent, uint16_t weight,
                                int exclusive)
{
    assert(h2o_http2_scheduler_is_open(ref));
    assert(&ref->node != new_parent);
    assert(1 <= weight);
    assert(weight <= 257);

    /* do nothing if there'd be no change at all */
    if (ref->node._parent == new_parent && ref->weight == weight && !exclusive)
        return;

    ref->weight = weight;

    { /* if new_parent is dependent to ref, make new_parent a sibling of ref before applying the final transition (see draft-16
         5.3.3) */
        h2o_http2_scheduler_node_t *t;
        for (t = new_parent; t->_parent != NULL; t = t->_parent) {
            if (t->_parent == &ref->node) {
                /* quoting the spec: "The moved dependency retains its weight." */
                h2o_http2_scheduler_openref_t *new_parent_ref = (void *)new_parent;
                do_rebind(new_parent_ref, ref->node._parent, 0);
                break;
            }
        }
    }

    do_rebind(ref, new_parent, exclusive);
}

void h2o_http2_scheduler_init(h2o_http2_scheduler_node_t *root)
{
    init_node(root, NULL);
}

void h2o_http2_scheduler_dispose(h2o_http2_scheduler_node_t *root)
{
    free(root->_queue);
    root->_queue = NULL;
}

void h2o_http2_scheduler_activate(h2o_http2_scheduler_openref_t *ref)
{
    if (ref->_self_is_active)
        return;
    ref->_self_is_active = 1;
    incr_active_cnt(&ref->node);
}

static int proceed(h2o_http2_scheduler_node_t *node, h2o_http2_scheduler_run_cb cb, void *cb_arg)
{
Redo:
    if (node->_queue == NULL)
        return 0;

    h2o_http2_scheduler_queue_node_t *drr_node = queue_pop(node->_queue);
    if (drr_node == NULL)
        return 0;

    h2o_http2_scheduler_openref_t *ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _queue_node, drr_node);

    if (!ref->_self_is_active) {
        /* run the children (manually-unrolled tail recursion) */
        queue_set(node->_queue, &ref->_queue_node, ref->weight);
        node = &ref->node;
        goto Redo;
    }
    assert(ref->_active_cnt != 0);

    /* call the callbacks */
    int still_is_active, bail_out = cb(ref, &still_is_active, cb_arg);
    if (still_is_active) {
        queue_set(node->_queue, &ref->_queue_node, ref->weight);
    } else {
        ref->_self_is_active = 0;
        if (--ref->_active_cnt != 0) {
            queue_set(node->_queue, &ref->_queue_node, ref->weight);
        } else if (ref->node._parent != NULL) {
            decr_active_cnt(ref->node._parent);
        }
    }

    return bail_out;
}

int h2o_http2_scheduler_run(h2o_http2_scheduler_node_t *root, h2o_http2_scheduler_run_cb cb, void *cb_arg)
{
    if (root->_queue != NULL) {
        while (!queue_is_empty(root->_queue)) {
            int bail_out = proceed(root, cb, cb_arg);
            if (bail_out)
                return bail_out;
        }
    }
    return 0;
}

int h2o_http2_scheduler_is_active(h2o_http2_scheduler_node_t *root)
{
    return root->_queue != NULL && !queue_is_empty(root->_queue);
}
