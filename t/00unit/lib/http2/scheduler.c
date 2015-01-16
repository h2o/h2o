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

static char iterate_out[1024];
static size_t iterate_max;

static int iterate_cb(h2o_http2_scheduler_openref_t *ref, int *still_is_active, void *_unused)
{
    node_t *node = (void*)ref;

    if (iterate_out[0] != '\0')
        strcat(iterate_out, ",");
    strcat(iterate_out, node->name);
    *still_is_active = node->still_is_active;

    if (--iterate_max == 0)
        return 1;
    return node->bail_out;
}

static void test_round_robin(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 12);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 12);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12);

    /* none are active */
    iterate_out[0] = '\0';
    iterate_max = 4;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "") == 0);

    /* set A to active */
    h2o_http2_scheduler_set_active(&nodeA.ref);
    iterate_out[0] = '\0';
    iterate_max = 4;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "A,A,A,A") == 0);

    /* A should change to inactive */
    nodeA.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 4;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "A") == 0);

    /* set all to active */
    h2o_http2_scheduler_set_active(&nodeA.ref);
    nodeA.still_is_active = 1;
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_set_active(&nodeC.ref);
    iterate_out[0] = '\0';
    iterate_max = 7;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "A,B,C,A,B,C,A") == 0);

    /* change them to inactive */
    nodeA.still_is_active = 0;
    nodeB.still_is_active = 0;
    nodeC.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 4;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "B,C,A") == 0);

    /* close C */
    h2o_http2_scheduler_close(&scheduler, &nodeC.ref);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    iterate_out[0] = '\0';
    iterate_max = 4;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "A,B") == 0);

    h2o_http2_scheduler_close(&scheduler, &nodeA.ref);
    h2o_http2_scheduler_close(&scheduler, &nodeB.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

static void test_priority(void)
{
    h2o_http2_scheduler_t scheduler = {};
    node_t nodeA = { {}, "A", 1, 0 };
    node_t nodeB = { {}, "B", 1, 0 };
    node_t nodeC = { {}, "C", 1, 0 };

    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 32);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 32);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12);
    h2o_http2_scheduler_set_active(&nodeC.ref);

    /* should only get the higher ones */
    iterate_out[0] = '\0';
    iterate_max = 5;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "A,B,A,B,A") == 0);

    /* eventually disactivate A */
    nodeA.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 5;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "B,A,B,B,B") == 0);

    /* should start serving C as B gets disactivated */
    nodeB.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 5;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "B,C,C,C,C") == 0);

    h2o_http2_scheduler_close(&scheduler, &nodeA.ref);
    h2o_http2_scheduler_close(&scheduler, &nodeB.ref);
    h2o_http2_scheduler_close(&scheduler, &nodeC.ref);
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

    h2o_http2_scheduler_open(&scheduler, &nodeA.ref, 32);
    h2o_http2_scheduler_set_active(&nodeA.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeB.ref, 32);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    h2o_http2_scheduler_open(&scheduler, &nodeC.ref, 12);
    h2o_http2_scheduler_set_active(&nodeC.ref);
    h2o_http2_scheduler_open(&nodeA.ref.super, &nodeD.ref, 24);
    h2o_http2_scheduler_set_active(&nodeD.ref);

    /* should only get A and B */
    iterate_out[0] = '\0';
    iterate_max = 5;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "A,B,A,B,A") == 0);

    /* eventually disactivate A, should get C and B */
    nodeA.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 7;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "B,A,B,D,B,D,B") == 0);

    /* eventually disactivate B, should get D only */
    nodeB.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 5;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "D,B,D,D,D") == 0);

    /* closing A raises D, and the priority becomes B -> D -> C */
    h2o_http2_scheduler_close(&scheduler, &nodeA.ref);
    h2o_http2_scheduler_set_active(&nodeB.ref);
    nodeB.still_is_active = 0;
    nodeD.still_is_active = 0;
    nodeC.still_is_active = 0;
    iterate_out[0] = '\0';
    iterate_max = 5;
    h2o_http2_scheduler_iterate(&scheduler, iterate_cb, NULL);
    ok(strcmp(iterate_out, "B,D,C") == 0);
    h2o_http2_scheduler_set_active(&nodeB.ref);

    h2o_http2_scheduler_close(&scheduler, &nodeB.ref);
    h2o_http2_scheduler_close(&scheduler, &nodeC.ref);
    h2o_http2_scheduler_close(&scheduler, &nodeD.ref);
    h2o_http2_scheduler_dispose(&scheduler);
}

void test_lib__http2__scheduler(void)
{
    subtest("round-robin", test_round_robin);
    subtest("priority", test_priority);
    subtest("dependency", test_dependency);
}
