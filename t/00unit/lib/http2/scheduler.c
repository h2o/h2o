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
#include <string.h>
#include "../../test.h"
#include "../../../../lib/http2/scheduler.c"

typedef struct {
    h2o_http2_scheduler_openref_t ref;
    const char *name;
    int still_is_active;
    int bail_out;
} node_t;

static char output[1024];
static size_t max_cnt;

static int iterate_cb(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *_unused)
{
    node_t *node = (void*)ref;

    if (output[0] != '\0')
        strcat(output, ",");
    strcat(output, node->name);
    *still_is_active = node->still_is_active;

    if (--max_cnt == 0)
        return 1;
    return node->bail_out;
}

static void test_round_robin(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 12, 0);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 12, 0);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12, 0);

    /* none are active */
    output[0] = '\0';
    max_cnt = 4;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "") == 0);

    /* set A to active */
    h2o_http2_scheduler_set_active(&nodeA.ref);
    output[0] = '\0';
    max_cnt = 4;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,A,A,A") == 0);

    /* A should change to inactive */
    nodeA.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 4;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A") == 0);

    /* set all to active */
    h2o_http2_scheduler_set_active(&nodeA.ref);
    nodeA.still_is_active = 1;
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_set_active(&nodeC.ref);
    output[0] = '\0';
    max_cnt = 7;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B,C,A,B,C,A") == 0);

    /* change them to inactive */
    nodeA.still_is_active = 0;
    nodeB.still_is_active = 0;
    nodeC.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 4;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "B,C,A") == 0);

    /* close C */
    h2o_http2_scheduler_close(&nodeC.ref);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    output[0] = '\0';
    max_cnt = 4;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B") == 0);

    h2o_http2_scheduler_close(&nodeA.ref);
    h2o_http2_scheduler_close(&nodeB.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_priority(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 32, 0);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 32, 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12, 0);
    h2o_http2_scheduler_set_active(&nodeC.ref);

    /* should only get the higher ones */
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B,A,B,A") == 0);

    /* eventually disactivate A */
    nodeA.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "B,A,B,B,B") == 0);

    /* should start serving C as B gets disactivated */
    nodeB.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "B,C,C,C,C") == 0);

    h2o_http2_scheduler_close(&nodeA.ref);
    h2o_http2_scheduler_close(&nodeB.ref);
    h2o_http2_scheduler_close(&nodeC.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_dependency(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };
    node_t nodeD = { {}, "D", 1, 0 };

    /*
     * root
     *  /|\
     * A B C
     * |
     * D
     */

    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 32, 0);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 32, 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12, 0);
    h2o_http2_scheduler_set_active(&nodeC.ref);
    h2o_http2_scheduler_open(&nodeA.ref.super, &nodeD.ref, 24, 0);
    h2o_http2_scheduler_set_active(&nodeD.ref);

    /* should only get A and B */
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B,A,B,A") == 0);

    /* eventually disactivate A, should get C and B */
    nodeA.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 7;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "B,A,B,D,B,D,B") == 0);

    /* eventually disactivate B, should get D only */
    nodeB.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "D,B,D,D,D") == 0);

    /* closing A raises D, and the priority becomes B -> D -> C */
    h2o_http2_scheduler_close(&nodeA.ref);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    nodeB.still_is_active = 0;
    nodeD.still_is_active = 0;
    nodeC.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "B,D,C") == 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);

    h2o_http2_scheduler_close(&nodeB.ref);
    h2o_http2_scheduler_close(&nodeC.ref);
    h2o_http2_scheduler_close(&nodeD.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_exclusive(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    /*
     * root      root
     *  /\        |
     * A  B  =>   C
     *            |\
     *            A B
     */

    /* open A & B */
    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 32, 0);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 32, 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);

    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B,A,B,A") == 0);

    /* add C as an exclusive */
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12, 1);

    /* should get A & B since C is inactive */
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B,A,B,A") == 0); /* under current impl, moving the deps causes them to be ordered using _all_ref */

    /* should see C once it is activated */
    h2o_http2_scheduler_set_active(&nodeC.ref);
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "C,C,C,C,C") == 0);

    /* eventually disabling C should show A and B */
    nodeC.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "C,B,A,B,A") == 0);

    h2o_http2_scheduler_close(&nodeA.ref);
    h2o_http2_scheduler_close(&nodeB.ref);
    h2o_http2_scheduler_close(&nodeC.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_firefox(void)
{
    /*
     * firefox sends something like below
     *
     * PRIORITY: id:3, dependency:0, weight: 201
     * PRIORITY: id:5, dependency:0, weight: 101
     * PRIORITY: id:7, dependency:0, weight: 1
     * PRIORITY: id:9, dependency:7, weight: 1
     * PRIORITY: id:11, dependency:3, weight: 1
     * HEADERS: id:13, dependency:11, weight: 22
     * HEADERS: id:15, dependency:3, weight: 22
     * HEADERS: id:17, dependency:3, weight: 22
     */
    h2o_http2_scheduler_t scheduler = {};
    node_t g1 = { {}, "g1", 0, 0 };
    node_t g2 = { {}, "g2", 0, 0 };
    node_t g3 = { {}, "g3", 0, 0 };
    node_t g4 = { {}, "g4", 0, 0 };
    node_t g5 = { {}, "g5", 0, 0 };
    node_t r1 = { {}, "r1", 1, 0 };
    node_t r2 = { {}, "r2", 1, 0 };
    node_t r3 = { {}, "r3", 1, 0 };

    /* setup the proirity groups */
    h2o_http2_scheduler_open(&scheduler, &g1.ref, 201, 0);
    h2o_http2_scheduler_open(&scheduler, &g2.ref, 101, 0);
    h2o_http2_scheduler_open(&scheduler, &g3.ref, 1, 0);
    h2o_http2_scheduler_open(&g3.ref.super, &g4.ref, 1, 0);
    h2o_http2_scheduler_open(&g1.ref.super, &g5.ref, 1, 0);

    /* open r1 and set serving */
    h2o_http2_scheduler_open(&g5.ref.super, &r1.ref, 22, 0);
    h2o_http2_scheduler_set_active(&r1.ref);
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "r1,r1,r1,r1,r1") == 0);

    /* open r2,r3 and serve */
    h2o_http2_scheduler_open(&g1.ref.super, &r2.ref, 22, 0);
    h2o_http2_scheduler_set_active(&r2.ref);
    h2o_http2_scheduler_open(&g1.ref.super, &r3.ref, 22, 0);
    h2o_http2_scheduler_set_active(&r3.ref);
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "r2,r3,r2,r3,r2") == 0);

    /* eventually disactive r2,r3 */
    r2.still_is_active = 0;
    r3.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "r3,r2,r1,r1,r1") == 0);

    /* close r2,r3 */
    h2o_http2_scheduler_close(&r2.ref);
    h2o_http2_scheduler_close(&r3.ref);
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "r1,r1,r1,r1,r1") == 0);

    h2o_http2_scheduler_close(&r1.ref);

    h2o_http2_scheduler_close(&g1.ref);
    h2o_http2_scheduler_close(&g2.ref);
    h2o_http2_scheduler_close(&g3.ref);
    h2o_http2_scheduler_close(&g4.ref);
    h2o_http2_scheduler_close(&g5.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void dump_tree(h2o_http2_scheduler_node_t *node)
{
    if (node->_parent != NULL) {
        strcat(output, ((node_t*)node)->name);
    }

    if (node->_list.size != 0) {
        size_t slot_index;
        int found_any = 0;
        for (slot_index = 0; slot_index != node->_list.size; ++slot_index) {
            h2o_http2_scheduler_slot_t *slot = node->_list.entries[slot_index];
            h2o_linklist_t *link;
            for (link = slot->_all_refs.next; link != &slot->_all_refs; link = link->next) {
                h2o_http2_scheduler_openref_t *ref = H2O_STRUCT_FROM_MEMBER(h2o_http2_scheduler_openref_t, _all_link, link);
                if (! found_any) {
                    found_any = 1;
                    strcat(output, "(");
                }
                dump_tree(&ref->super);
            }
        }
        if (found_any)
            strcat(output, ")");
    }
}

static int test_reprioritize_exclusive;

static void test_reprioritize(void)
{
    /* from 5.3.3 of HTTP-2 draft 16
     *    ?                ?                ?                 ?
     *    |               / \               |                 |
     *    A              D   A              D                 D
     *   / \            /   / \            / \                |
     *  B   C     ==>  F   B   C   ==>    F   A       OR      A
     *     / \                 |             / \             /|\
     *    D   E                E            B   C           B C F
     *    |                                     |             |
     *    F                                     E             E
     *               (intermediate)   (non-exclusive)    (exclusive)
     */
    h2o_http2_scheduler_t scheduler = {};
    node_t a = { {}, "A" };
    node_t b = { {}, "B" };
    node_t c = { {}, "C" };
    node_t d = { {}, "D" };
    node_t e = { {}, "E" };
    node_t f = { {}, "F" };

    h2o_http2_scheduler_open(&scheduler, &a.ref, 16, 0);
    h2o_http2_scheduler_open(&a.ref.super, &b.ref, 16, 0);
    h2o_http2_scheduler_open(&a.ref.super, &c.ref, 16, 0);
    h2o_http2_scheduler_open(&c.ref.super, &d.ref, 16, 0);
    h2o_http2_scheduler_open(&c.ref.super, &e.ref, 16, 0);
    h2o_http2_scheduler_open(&d.ref.super, &f.ref, 16, 0);

    output[0] = '\0';
    dump_tree(&scheduler);
    ok(strcmp(output, "(A(BC(D(F)E)))") == 0);

    h2o_http2_scheduler_rebind(&a.ref, &d.ref.super, 16, test_reprioritize_exclusive);
    output[0] = '\0';
    dump_tree(&scheduler);
    if (!test_reprioritize_exclusive) {
        ok(strcmp(output, "(D(FA(BC(E))))") == 0);
    } else {
        ok(strcmp(output, "(D(A(BC(E)F)))") == 0);
    }

    h2o_http2_scheduler_close(&a.ref);
    h2o_http2_scheduler_close(&b.ref);
    h2o_http2_scheduler_close(&c.ref);
    h2o_http2_scheduler_close(&d.ref);
    h2o_http2_scheduler_close(&e.ref);
    h2o_http2_scheduler_close(&f.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_change_weight(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    /* open them all with priority=16 */
    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 16, 0);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 16, 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 16, 0);
    h2o_http2_scheduler_set_active(&nodeC.ref);

    /* check the output */
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "A,B,C,A,B") == 0);

    /* nodeA.priority = 1 */
    h2o_http2_scheduler_rebind(&nodeA.ref, &scheduler, 1, 0);
    output[0] = '\0';
    dump_tree(&scheduler);
    ok(strcmp(output, "(BCA)") == 0);
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "C,B,C,B,C") == 0);

    /* eventually disactivate B,C */
    nodeB.still_is_active = 0;
    nodeC.still_is_active = 0;
    output[0] = '\0';
    max_cnt = 5;
    h2o_http2_scheduler_run(&scheduler, iterate_cb, NULL);
    ok(strcmp(output, "B,C,A,A,A") == 0);

    h2o_http2_scheduler_close(&nodeA.ref);
    h2o_http2_scheduler_close(&nodeB.ref);
    h2o_http2_scheduler_close(&nodeC.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_exclusive_at_current_pos(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    /* open them all with priority=16 */
    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 16, 0);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 16, 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 16, 0);
    h2o_http2_scheduler_set_active(&nodeC.ref);

    output[0] = '\0';
    dump_tree(&scheduler);
    ok(strcmp(output, "(ABC)") == 0);

    h2o_http2_scheduler_rebind(&nodeB.ref, &scheduler, 1, 1);

    output[0] = '\0';
    dump_tree(&scheduler);
    ok(strcmp(output, "(B(AC))") == 0);

    h2o_http2_scheduler_close(&nodeA.ref);
    h2o_http2_scheduler_close(&nodeB.ref);
    h2o_http2_scheduler_close(&nodeC.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

void test_lib__http2__scheduler(void)
{
    subtest("round-robin", test_round_robin);
    subtest("priority", test_priority);
    subtest("dependency", test_dependency);
    subtest("exclusive", test_exclusive);
    subtest("firefox", test_firefox);
    test_reprioritize_exclusive = 0;
    subtest("repriortize-nonexclusive", test_reprioritize);
    test_reprioritize_exclusive = 1;
    subtest("repriortize-exclusive", test_reprioritize);
    subtest("change-weight", test_change_weight);
    subtest("exclusive-at-current-pos", test_exclusive_at_current_pos);
}
