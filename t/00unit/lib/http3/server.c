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

void test_lib__http3_server(void)
{
    subtest("scheduler", test_scheduler);
}
