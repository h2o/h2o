/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
#include <stdlib.h>
#include "../../test.h"
#include "../../../../lib/http3/server.c"

struct sched_node_t {
    struct st_h2o_http3_req_scheduler_node_t super;
    unsigned id;
};

static int compare_node(struct st_h2o_http3_req_scheduler_t *sched, const struct st_h2o_http3_req_scheduler_node_t *_x,
                        const struct st_h2o_http3_req_scheduler_node_t *_y)
{
    struct sched_node_t *x = (void *)_x, *y = (void *)_y;
    if (x->id < y->id) {
        return -1;
    } else if (x->id > y->id) {
        return 1;
    } else {
        return 0;
    }
}

static struct sched_node_t *get_top_node(struct st_h2o_http3_req_scheduler_t *sched)
{
    h2o_linklist_t *anchor = &sched->active.urgencies[sched->active.smallest_urgency].high;
    if (h2o_linklist_is_empty(anchor)) {
        anchor = &sched->active.urgencies[sched->active.smallest_urgency].low;
        assert(!h2o_linklist_is_empty(anchor));
    }
    return H2O_STRUCT_FROM_MEMBER(struct sched_node_t, super.link, anchor->next);
}

static void run_once(struct st_h2o_http3_req_scheduler_t *sched)
{
    struct sched_node_t *top = get_top_node(sched);
    ++top->super.call_cnt;
    req_scheduler_setup_for_next(sched, &top->super, compare_node);
}

static void test_scheduler(void)
{
    struct st_h2o_http3_req_scheduler_t sched;

    req_scheduler_init(&sched);
    ok(sched.active.smallest_urgency == H2O_ABSPRIO_NUM_URGENCY_LEVELS);

    /* add three nodes in non-sequential order, check that they are ordered in sequence */
    struct sched_node_t node1 = {.super = {.priority = {.urgency = 1}}, .id = 1};
    struct sched_node_t node4 = {.super = {.priority = {.urgency = 1}}, .id = 4};
    struct sched_node_t node5 = {.super = {.priority = {.urgency = 1}}, .id = 5};
    req_scheduler_activate(&sched, &node1.super, compare_node);
    req_scheduler_activate(&sched, &node5.super, compare_node);
    req_scheduler_activate(&sched, &node4.super, compare_node);
    ok(get_top_node(&sched) == &node1);
    ok(get_top_node(&sched)->super.link.next == &node4.super.link);
    ok(get_top_node(&sched)->super.link.next->next == &node5.super.link);
    ok(get_top_node(&sched)->super.link.next->next->next == &sched.active.urgencies[1].high);

    /* running the top node (which is non-sequential) does not change the order */
    run_once(&sched);
    ok(get_top_node(&sched) == &node1);

    /* retire the top node, check that the id=4 is promoted */
    req_scheduler_deactivate(&sched, &node1.super);
    ok(get_top_node(&sched) == &node4);
    ok(get_top_node(&sched)->super.link.next == &node5.super.link);
    ok(get_top_node(&sched)->super.link.next->next == &sched.active.urgencies[1].high);

    /* add node2, 3 that are incremental, their initial slots will be in "high", in sequential order */
    struct sched_node_t node2 = {.super = {.priority = {.urgency = 1, .incremental = 1}}, .id = 2};
    struct sched_node_t node3 = {.super = {.priority = {.urgency = 1, .incremental = 1}}, .id = 3};
    req_scheduler_activate(&sched, &node2.super, compare_node);
    req_scheduler_activate(&sched, &node3.super, compare_node);
    ok(get_top_node(&sched) == &node2);
    ok(get_top_node(&sched)->super.link.next == &node3.super.link);
    ok(get_top_node(&sched)->super.link.next->next == &node4.super.link);
    ok(get_top_node(&sched)->super.link.next->next->next == &node5.super.link);
    ok(get_top_node(&sched)->super.link.next->next->next->next == &sched.active.urgencies[1].high);

    /* run the top node multiple times; node2, node3 are moved to lower, but node4 stays at the top */
    run_once(&sched);
    ok(get_top_node(&sched) == &node3);
    run_once(&sched);
    ok(get_top_node(&sched) == &node4);
    for (int i = 0; i < 3; ++i) {
        run_once(&sched);
        ok(get_top_node(&sched) == &node4);
    }

    /* retire the non-incremental ones, check that the incremental ones are invoked one by one */
    req_scheduler_deactivate(&sched, &node4.super);
    req_scheduler_deactivate(&sched, &node5.super);
    for (int i = 0; i < 4; ++i) {
        ok(get_top_node(&sched) == &node2);
        run_once(&sched);
        ok(get_top_node(&sched) == &node3);
        run_once(&sched);
    }
    ok(get_top_node(&sched) == &node2);

    /* node at a higher urgency level cuts in */
    struct sched_node_t node6 = {.super = {.priority = {.urgency = 0}}, .id = 6};
    req_scheduler_activate(&sched, &node6.super, compare_node);
    ok(get_top_node(&sched) == &node6);
    run_once(&sched);
    ok(get_top_node(&sched) == &node6);

    /* retire all nodes */
    req_scheduler_deactivate(&sched, &node2.super);
    req_scheduler_deactivate(&sched, &node3.super);
    req_scheduler_deactivate(&sched, &node6.super);
    ok(sched.active.smallest_urgency == H2O_ABSPRIO_NUM_URGENCY_LEVELS);
}

static void test_wt_find_range_after(void)
{
    quicly_recvstate_t rs;
    const quicly_range_t *r;
    size_t n = 0;

    /* 300 ranges [2k, 2k + 1) for k = 1..300, being more than QUICLY_BPLUS_RANGES_FANOUT^2 so that the tree has three levels */
    int all_added = 1;
    quicly_recvstate_init(&rs);
    for (uint64_t k = 300; k != 0; --k) {
        uint64_t off = 2 * k;
        size_t len = 1;
        if (quicly_recvstate_update(&rs, &off, &len, 0, UINT64_MAX) != 0)
            all_added = 0;
    }
    ok(all_added);
    ok(rs.received.height >= 3);

    /* walking from the start yields every range in order, the empty one at zero excluded */
    for (uint64_t next = 0; (r = wt_find_range_after(rs.received.root, rs.received.height, next)) != NULL; next = r->end) {
        ++n;
        if (r->start != 2 * n || r->end != 2 * n + 1)
            break;
    }
    ok(n == 300);

    /* lookups from any offset find the first range that ends above it */
    int all_found = 1;
    for (uint64_t off = 0; off <= 601; ++off) {
        uint64_t k = off < 2 ? 1 : off / 2 + off % 2;
        r = wt_find_range_after(rs.received.root, rs.received.height, off);
        if (k > 300 ? r != NULL : r == NULL || r->start != 2 * k)
            all_found = 0;
    }
    ok(all_found);

    quicly_recvstate_dispose(&rs);
}

static void test_wt_mirror_reset_after_fin(void)
{
    /* The peer sends a WebTransport stream with a 2-byte header: [0,5), a zero-length FIN at 52 beyond a gap, [22,27), then
     * RESET_STREAM. The FIN is mirrored once the bytes after the gap arrive; the reset has to use the final size it fixed. */
    quicly_stream_t qs = {NULL};
    struct st_h2o_http3_server_wt_stream_t ws = {{NULL}};
    uint64_t off, missing;
    size_t len;

    ws.quic = &qs;
    ws.recv.base = 2;
    quicly_recvstate_init(&qs.recvstate);
    quicly_recvstate_init(&ws.super.recvstate);

    /* the QUIC stream */
    off = 0, len = 5;
    ok(quicly_recvstate_update(&qs.recvstate, &off, &len, 0, UINT64_MAX) == 0);
    off = 52, len = 0;
    ok(quicly_recvstate_update(&qs.recvstate, &off, &len, 1, UINT64_MAX) == 0);
    off = 22, len = 5;
    ok(quicly_recvstate_update(&qs.recvstate, &off, &len, 0, UINT64_MAX) == 0);
    /* its mirror, the offsets excluding the header */
    wt_mirror_update(&ws, 0, 3, 0);
    wt_mirror_update(&ws, 20, 5, 0);
    wt_mirror_eos(&ws);
    ok(ws.super.recvstate.eos == 50);

    ok(quicly_recvstate_reset(&qs.recvstate, 52, 0, 11, &missing) == 0);
    wt_mirror_reset(&ws);
    ok(quicly_recvstate_transfer_complete(&ws.super.recvstate));
    ok(ws.super.recvstate.app_error_code == 11);

    quicly_recvstate_dispose(&ws.super.recvstate);
    quicly_recvstate_dispose(&qs.recvstate);
}

void test_lib__http3_server(void)
{
    subtest("scheduler", test_scheduler);
    subtest("webtransport: walk the received ranges", test_wt_find_range_after);
    subtest("webtransport: reset after a FIN beyond a gap", test_wt_mirror_reset_after_fin);
}
