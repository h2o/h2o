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

static void init_node(h2o_http2_scheduler_node_t *node, h2o_http2_scheduler_node_t *parent, h2o_http2_scheduler_slot_t *slot)
{
    *node = (h2o_http2_scheduler_node_t){
        parent,                                  /* _parent */
        slot,                                    /* _slot */
        {},                                      /* _list */
        {},                                      /* _run_refs */
        {0x536c6005dfa85e15, 0x8fa5832dd420e956} /* _rand_state */
    };
    h2o_linklist_init_anchor(&node->_run_refs);
}

static h2o_http2_scheduler_slot_t *get_or_create_slot(h2o_http2_scheduler_node_t *node, uint16_t weight)
{
    h2o_http2_scheduler_slot_t *slot;
    size_t i;

    /* locate the slot */
    for (i = 0; i != node->_list.size; ++i) {
        slot = node->_list.entries[i];
        if (slot->weight == weight) {
            goto Exit;
        } else if (slot->weight < weight) {
            break;
        }
    }
    /* not found, create new slot */
    slot = h2o_mem_alloc(sizeof(*slot));
    slot->weight = weight;
    h2o_linklist_init_anchor(&slot->_all_refs);
    h2o_linklist_init_anchor(&slot->_wait_refs);
    h2o_vector_reserve(NULL, (h2o_vector_t *)&node->_list, sizeof(node->_list.entries[0]), node->_list.size + 1);
    memmove(node->_list.entries + i + 1, node->_list.entries + i, sizeof(node->_list.entries[0]) * (node->_list.size - i));
    node->_list.entries[i] = slot;
    ++node->_list.size;

Exit:
    return slot;
}

static void incr_active_cnt(h2o_http2_scheduler_node_t *node, int is_immediate)
{
    h2o_http2_scheduler_openref_t *ref;

    /* do nothing if node is the root */
    if (node->_parent == NULL)
        return;

    ref = (h2o_http2_scheduler_openref_t *)node;
    if (++ref->_active_cnt != 1)
        return;
    /* now changing to active */
    assert(!h2o_linklist_is_linked(&ref->_active_link));
    h2o_linklist_insert(is_immediate ? &ref->node._parent->_run_refs : &ref->node._slot->_wait_refs, &ref->_active_link);
    /* delegate the change towards root */
    incr_active_cnt(ref->node._parent, 0 /* TODO delegate the flag */);
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
    assert(h2o_linklist_is_linked(&ref->_active_link));
    h2o_linklist_unlink(&ref->_active_link);
    /* delegate the change towards root */
    decr_active_cnt(ref->node._parent);
}

static void convert_to_exclusive(h2o_http2_scheduler_node_t *parent, h2o_http2_scheduler_openref_t *added)
{
    size_t slot_index;

    for (slot_index = 0; slot_index != parent->_list.size; ++slot_index) {
        h2o_http2_scheduler_slot_t *slot = parent->_list.entries[slot_index];
        while (!h2o_linklist_is_empty(&slot->_all_refs)) {
            h2o_http2_scheduler_openref_t *child_ref =
                H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, slot->_all_refs.next);
            if (child_ref == added) {
                /* precond: the added node should exist as the last item within the slot */
                assert(slot->_all_refs.prev == &added->_all_link);
                break;
            }
            h2o_http2_scheduler_rebind(child_ref, &added->node, h2o_http2_scheduler_get_weight(child_ref), 0);
        }
    }
}

void h2o_http2_scheduler_open(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *parent, uint16_t weight,
                              int exclusive)
{
    h2o_http2_scheduler_slot_t *slot = get_or_create_slot(parent, weight);

    init_node(&ref->node, parent, slot);
    ref->_all_link = (h2o_linklist_t){};
    ref->_active_link = (h2o_linklist_t){};
    ref->_active_cnt = 0;
    ref->_self_is_active = 0;

    h2o_linklist_insert(&slot->_all_refs, &ref->_all_link);

    if (exclusive)
        convert_to_exclusive(parent, ref);
}

void h2o_http2_scheduler_close(h2o_http2_scheduler_openref_t *ref)
{
    assert(h2o_http2_scheduler_is_open(ref));

    /* move dependents to parent */
    if (ref->node._list.size != 0) {
        size_t slot_index;
        for (slot_index = 0; slot_index != ref->node._list.size; ++slot_index) {
            h2o_http2_scheduler_slot_t *src_slot = ref->node._list.entries[slot_index];
            while (!h2o_linklist_is_empty(&src_slot->_all_refs)) {
                h2o_http2_scheduler_openref_t *child_ref =
                    H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, src_slot->_all_refs.next);
                /* TODO draft-16 5.3.4 says the weight of the closed parent should be distributed proportionally to the children */
                h2o_http2_scheduler_rebind(child_ref, ref->node._parent, h2o_http2_scheduler_get_weight(child_ref), 0);
            }
        }
    }

    /* detach self */
    h2o_linklist_unlink(&ref->_all_link);
    if (ref->_self_is_active) {
        assert(ref->_active_cnt == 1);
        assert(h2o_linklist_is_linked(&ref->_active_link));
        h2o_linklist_unlink(&ref->_active_link);
        decr_active_cnt(ref->node._parent);
    } else {
        assert(ref->_active_cnt == 0);
        assert(!h2o_linklist_is_linked(&ref->_active_link));
    }
}

static void do_rebind(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *new_parent, uint16_t weight, int exclusive)
{
    h2o_http2_scheduler_slot_t *new_slot = get_or_create_slot(new_parent, weight);

    /* rebind _all_link */
    h2o_linklist_unlink(&ref->_all_link);
    h2o_linklist_insert(&new_slot->_all_refs, &ref->_all_link);
    /* rebind _active_link (as well as adjust active_cnt) */
    if (h2o_linklist_is_linked(&ref->_active_link)) {
        h2o_linklist_unlink(&ref->_active_link);
        h2o_linklist_insert(&new_slot->_wait_refs, &ref->_active_link);
        decr_active_cnt(ref->node._parent);
        incr_active_cnt(new_parent, 0);
    }
    /* update the backlinks */
    ref->node._parent = new_parent;
    ref->node._slot = new_slot;

    if (exclusive)
        convert_to_exclusive(new_parent, ref);
}

void h2o_http2_scheduler_rebind(h2o_http2_scheduler_openref_t *ref, h2o_http2_scheduler_node_t *new_parent, uint16_t weight,
                                int exclusive)
{
    assert(h2o_http2_scheduler_is_open(ref));
    assert(&ref->node != new_parent);

    /* do nothing if there'd be no change at all */
    if (ref->node._parent == new_parent && h2o_http2_scheduler_get_weight(ref) == weight && !exclusive)
        return;

    { /* if new_parent is dependent to ref, make new_parent a sibling of ref before applying the final transition (see draft-16
         5.3.3) */
        h2o_http2_scheduler_node_t *t;
        for (t = new_parent; t->_parent != NULL; t = t->_parent) {
            if (t->_parent == &ref->node) {
                /* quoting the spec: "The moved dependency retains its weight." */
                h2o_http2_scheduler_openref_t *new_parent_ref = (void *)new_parent;
                do_rebind(new_parent_ref, ref->node._parent, h2o_http2_scheduler_get_weight(new_parent_ref), 0);
                break;
            }
        }
    }

    do_rebind(ref, new_parent, weight, exclusive);
}

void h2o_http2_scheduler_init(h2o_http2_scheduler_node_t *root)
{
    init_node(root, NULL, NULL);
}

void h2o_http2_scheduler_dispose(h2o_http2_scheduler_node_t *root)
{
    if (root->_list.size != 0) {
        size_t i;
        for (i = 0; i != root->_list.size; ++i) {
            h2o_http2_scheduler_slot_t *slot = root->_list.entries[i];
            assert(h2o_linklist_is_empty(&slot->_all_refs));
            free(slot);
        }
        free(root->_list.entries);
    }
}

void h2o_http2_scheduler_activate(h2o_http2_scheduler_openref_t *ref, int is_immediate)
{
    assert(!ref->_self_is_active);
    ref->_self_is_active = 1;
    incr_active_cnt(&ref->node, is_immediate);
}

static uint64_t xorshift128plus(uint64_t s[2])
{
    /*
    xorshift128+ (paper: http://arxiv.org/abs/1404.0390)
    copied from http://xorshift.di.unimi.it/xorshift128plus.c under the following license

    Written in 2014 by Sebastiano Vigna (vigna@acm.org)

    To the extent possible under law, the author has dedicated all copyright
    and related and neighboring rights to this software to the public domain
    worldwide. This software is distributed without any warranty.

    See <http://creativecommons.org/publicdomain/zero/1.0/>.
    */
	uint64_t s1 = s[0];
	const uint64_t s0 = s[ 1];
	s[ 0 ] = s0;
	s1 ^= s1 << 23; // a
	return ( s[ 1 ] = ( s1 ^ s0 ^ ( s1 >> 17 ) ^ ( s0 >> 26 ) ) ) + s0; // b, c
}

static int run_once(h2o_http2_scheduler_node_t *node, h2o_http2_scheduler_run_cb cb, void *cb_arg, size_t *num_touched)
{
    /* promote non-empty wait_refs of the heighest priority to the run_refs (if run_refs is empty) */
    if (h2o_linklist_is_empty(&node->_run_refs)) {
        h2o_http2_scheduler_slot_t *slot;
        size_t slot_index;
        uint16_t min_promote_weight;
        for (slot_index = 0; slot_index != node->_list.size; ++slot_index) {
            slot = node->_list.entries[slot_index];
            if (!h2o_linklist_is_empty(&slot->_wait_refs))
                goto FoundActiveSlot;
        }
        /* no active nodes */
        return 0;
    FoundActiveSlot:
        /* promote _wait_refs above a random value to _run_refs */
#ifdef H2O_UNITTEST
        min_promote_weight = slot->weight - 1;
#else
        min_promote_weight = xorshift128plus(node->_rand_state) % slot->weight;
#endif
        while (1) {
            h2o_linklist_insert_list(&node->_run_refs, &slot->_wait_refs);
            for (++slot_index; ; ++slot_index) {
                if (slot_index == node->_list.size)
                    goto EndPromote;
                slot = node->_list.entries[slot_index];
                if (slot->weight <= min_promote_weight)
                    goto EndPromote;
                if (!h2o_linklist_is_empty(&slot->_wait_refs))
                    break;
            }
        }
    EndPromote:
        ;
    }

    int bail_out = 0;

    /* execute the nodes in _run_refs */
    do {
        h2o_http2_scheduler_openref_t *ref =
            H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _active_link, node->_run_refs.next);
        h2o_linklist_unlink(&ref->_active_link);
        h2o_linklist_insert(&ref->node._slot->_wait_refs, &ref->_active_link);
        if (ref->_self_is_active) {
            /* call the callbacks */
            int still_is_active;
            assert(ref->_active_cnt != 0);
            bail_out = cb(ref, &still_is_active, cb_arg);
            ++*num_touched;
            /* adjust the state if it is going inactive */
            if (!still_is_active) {
                ref->_self_is_active = 0;
                decr_active_cnt(&ref->node);
            }
        } else {
            /* run the children */
            bail_out = run_once(&ref->node, cb, cb_arg, num_touched);
        }
    } while (!bail_out && !h2o_linklist_is_empty(&node->_run_refs));

    return bail_out;
}

int h2o_http2_scheduler_run(h2o_http2_scheduler_node_t *root, h2o_http2_scheduler_run_cb cb, void *cb_arg)
{
    int bail_out = 0;
    size_t num_touched;

    do {
        num_touched = 0;
        bail_out = run_once(root, cb, cb_arg, &num_touched);
    } while (!bail_out && num_touched != 0);

    return bail_out;
}
