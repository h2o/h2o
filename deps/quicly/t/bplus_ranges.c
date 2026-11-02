/*
 * Copyright (c) 2026 Fastly, Kazuho Oku
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
#include <stdio.h>
#include <stdlib.h>
#include "quicly/bplus_ranges.h"
#include "test.h"

#define FANOUT QUICLY_BPLUS_RANGES_FANOUT
#define NO_LIMIT ((uint64_t)1 << 62)

struct st_collected_t {
    quicly_range_t *ranges;
    size_t num_ranges, capacity;
    const quicly_range_t *last_seen;
};

static int fail(const char *what)
{
    fprintf(stderr, "bplus_ranges invariant violated: %s\n", what);
    return 0;
}

/**
 * Walks the subtree, appending ranges to `out` and checking invariants. Returns the smallest start in the subtree via `min_start`.
 */
static int walk(quicly_bplus_ranges_t *ranges, quicly_bplus_ranges_node_t *node, size_t level, int is_first,
                struct st_collected_t *out, uint64_t *min_start)
{
    int is_root = level == 0;

    if (level == ranges->height - 1) {
        /* leaf */
        if (is_first && node != &ranges->first)
            return fail("first leaf is not `first`");
        size_t n = 0;
        while (n < FANOUT && node->ranges[n].start != UINT64_MAX)
            ++n;
        for (size_t i = n; i < FANOUT; ++i)
            if (node->ranges[i].start != UINT64_MAX)
                return fail("leaf entries are not packed");
        if (!is_root && n < FANOUT / 2)
            return fail("leaf underflow");
        if (n == 0 && !is_root)
            return fail("empty non-root leaf");
        for (size_t i = 0; i < n; ++i) {
            if (out->num_ranges == out->capacity) {
                out->capacity = out->capacity == 0 ? 64 : out->capacity * 2;
                out->ranges = realloc(out->ranges, out->capacity * sizeof(out->ranges[0]));
            }
            out->ranges[out->num_ranges++] = node->ranges[i];
            out->last_seen = node->ranges + i;
        }
        *min_start = n != 0 ? node->ranges[0].start : UINT64_MAX;
        return 1;
    }

    /* non-leaf */
    size_t num_children = 1;
    while (num_children < FANOUT && node->keys[num_children] != UINT64_MAX)
        ++num_children;
    for (size_t i = num_children; i < FANOUT; ++i)
        if (node->keys[i] != UINT64_MAX)
            return fail("keys are not packed");
    if (is_root ? num_children < 2 : num_children < FANOUT / 2)
        return fail("non-leaf underflow");
    for (size_t i = 0; i < num_children; ++i) {
        uint64_t child_min;
        if (node->children[i] == NULL)
            return fail("missing child");
        if (!walk(ranges, node->children[i], level + 1, is_first && i == 0, out, &child_min))
            return 0;
        if (i == 0) {
            *min_start = child_min;
        } else if (node->keys[i] != child_min) {
            return fail("separator is not the smallest start of the child");
        }
    }
    return 1;
}

static int check(quicly_bplus_ranges_t *ranges, quicly_ranges_t *expected)
{
    struct st_collected_t collected = {NULL};
    uint64_t min_start;
    int success = 0;

    if (!walk(ranges, ranges->root, 0, 1, &collected, &min_start))
        goto Exit;
    if (collected.num_ranges != ranges->num_ranges) {
        fail("num_ranges mismatch");
        goto Exit;
    }
    if (ranges->last != collected.last_seen) {
        fail("`last` does not point to the last range");
        goto Exit;
    }
    if (expected != NULL) {
        if (collected.num_ranges != expected->num_ranges) {
            fail("number of ranges differs from quicly_ranges_t");
            goto Exit;
        }
        for (size_t i = 0; i < collected.num_ranges; ++i) {
            if (collected.ranges[i].start != expected->ranges[i].start || collected.ranges[i].end != expected->ranges[i].end) {
                fail("ranges differ from quicly_ranges_t");
                goto Exit;
            }
        }
    }
    success = 1;

Exit:
    free(collected.ranges);
    return success;
}

static void test_basic(void)
{
    quicly_bplus_ranges_t ranges;

    quicly_bplus_ranges_init(&ranges);
    ok(ranges.num_ranges == 1);
    ok(ranges.first.ranges[0].start == 0 && ranges.first.ranges[0].end == 0);
    ok(ranges.last == ranges.first.ranges);

    ok(quicly_bplus_ranges_add(&ranges, 0, 10, NO_LIMIT) == 0);
    ok(ranges.num_ranges == 1);
    ok(ranges.first.ranges[0].end == 10);

    ok(quicly_bplus_ranges_add(&ranges, 20, 30, NO_LIMIT) == 0);
    ok(quicly_bplus_ranges_add(&ranges, 40, 50, NO_LIMIT) == 0);
    ok(ranges.num_ranges == 3);
    ok(ranges.last->start == 40);

    /* touching merges */
    ok(quicly_bplus_ranges_add(&ranges, 10, 20, NO_LIMIT) == 0);
    ok(ranges.num_ranges == 2);
    ok(ranges.first.ranges[0].end == 30);

    /* covering everything */
    ok(quicly_bplus_ranges_add(&ranges, 5, 100, NO_LIMIT) == 0);
    ok(ranges.num_ranges == 1);
    ok(ranges.first.ranges[0].start == 0 && ranges.first.ranges[0].end == 100);
    ok(check(&ranges, NULL));

    /* empty range is ignored */
    ok(quicly_bplus_ranges_add(&ranges, 200, 200, NO_LIMIT) == 0);
    ok(ranges.num_ranges == 1);

    quicly_bplus_ranges_dispose(&ranges);
}

static void test_limit(void)
{
    quicly_bplus_ranges_t ranges;
    quicly_ranges_t expected;

    quicly_bplus_ranges_init(&ranges);
    quicly_ranges_init_with_range(&expected, 0, 0);

    /* the span is small, therefore the minimum of 63 applies */
    for (uint64_t i = 1; i < 63; ++i) {
        ok(quicly_bplus_ranges_add(&ranges, i * 2, i * 2 + 1, 1000) == 0);
        quicly_ranges_add(&expected, i * 2, i * 2 + 1);
    }
    ok(ranges.num_ranges == 63);
    ok(quicly_bplus_ranges_add(&ranges, 200, 201, 1000) == QUICLY_ERROR_STATE_EXHAUSTION);
    ok(check(&ranges, &expected));

    /* merges and extensions are permitted */
    ok(quicly_bplus_ranges_add(&ranges, 3, 4, 1000) == 0);
    quicly_ranges_add(&expected, 3, 4);
    ok(quicly_bplus_ranges_add(&ranges, 124, 130, 1000) == 0);
    quicly_ranges_add(&expected, 124, 130);
    ok(ranges.num_ranges == 62);
    ok(check(&ranges, &expected));

    /* now that one gap has been filled, a new range can be added */
    ok(quicly_bplus_ranges_add(&ranges, 200, 201, 1000) == 0);
    quicly_ranges_add(&expected, 200, 201);
    ok(quicly_bplus_ranges_add(&ranges, 300, 301, 1000) == QUICLY_ERROR_STATE_EXHAUSTION);
    ok(check(&ranges, &expected));

    /* the span determines the limit: one range per 1024 bytes beyond `first.end`, plus the first range */
    ok(quicly_bplus_ranges_add(&ranges, 300, 301, 1024 * 99) == 0);
    quicly_ranges_add(&expected, 300, 301);
    for (uint64_t i = 0; ranges.num_ranges < 100; ++i) {
        ok(quicly_bplus_ranges_add(&ranges, 1000 + i * 2, 1001 + i * 2, 1024 * 99) == 0);
        quicly_ranges_add(&expected, 1000 + i * 2, 1001 + i * 2);
    }
    ok(quicly_bplus_ranges_add(&ranges, 5000, 5001, 1024 * 99) == QUICLY_ERROR_STATE_EXHAUSTION);
    ok(check(&ranges, &expected));

    quicly_bplus_ranges_dispose(&ranges);
    quicly_ranges_clear(&expected);
}

static int add_both(quicly_bplus_ranges_t *ranges, quicly_ranges_t *expected, uint64_t start, uint64_t end)
{
    if (quicly_bplus_ranges_add(ranges, start, end, NO_LIMIT) != 0)
        return fail("add failed");
    if (quicly_ranges_add(expected, start, end) != 0)
        return fail("quicly_ranges_add failed");
    return 1;
}

/**
 * builds many disjoint ranges, then fills the gaps in a pseudo-random order, exercising splits and every kind of rebalancing
 */
static void test_fill_gaps(void)
{
    quicly_bplus_ranges_t ranges;
    quicly_ranges_t expected;
    size_t num_gaps = 5000, *order = malloc(num_gaps * sizeof(*order));
    int success = 1;

    quicly_bplus_ranges_init(&ranges);
    quicly_ranges_init_with_range(&expected, 0, 0);

    for (size_t i = 0; success && i < num_gaps; ++i) {
        success = add_both(&ranges, &expected, i * 2 + 1, i * 2 + 2);
        if (success && i % 97 == 0)
            success = check(&ranges, &expected);
    }
    ok(success);
    ok(ranges.num_ranges == num_gaps + 1);
    ok(ranges.height >= 3);
    ok(check(&ranges, &expected));

    for (size_t i = 0; i < num_gaps; ++i)
        order[i] = i;
    srand(1);
    for (size_t i = num_gaps - 1; i > 0; --i) {
        size_t j = (size_t)rand() % (i + 1), t = order[i];
        order[i] = order[j];
        order[j] = t;
    }
    for (size_t i = 0; success && i < num_gaps; ++i) {
        success = add_both(&ranges, &expected, order[i] * 2, order[i] * 2 + 1);
        if (success && i % 53 == 0)
            success = check(&ranges, &expected);
    }
    ok(success);
    ok(ranges.num_ranges == 1);
    ok(ranges.height == 1);
    ok(check(&ranges, &expected));

    free(order);
    quicly_bplus_ranges_dispose(&ranges);
    quicly_ranges_clear(&expected);
}

/**
 * adds ranges that swallow runs of various lengths, within a leaf and across leaves, starting at various offsets
 */
static void test_swallow(void)
{
    static const uint64_t lengths[] = {3, 5, 17, 33, 100, 300, 1000};
    int success = 1;

    for (size_t li = 0; success && li < PTLS_ELEMENTSOF(lengths); ++li) {
        for (uint64_t offset = 0; success && offset < 40; offset += 3) {
            quicly_bplus_ranges_t ranges;
            quicly_ranges_t expected;
            quicly_bplus_ranges_init(&ranges);
            quicly_ranges_init_with_range(&expected, 0, 0);
            for (uint64_t i = 1; success && i < 2000; ++i)
                success = add_both(&ranges, &expected, i * 4, i * 4 + 2);
            /* swallow a run, then swallow the merged range together with its neighbors */
            uint64_t start = 1000 + offset * 4 + 1, end = start + lengths[li] * 4;
            if (success)
                success = add_both(&ranges, &expected, start, end) && check(&ranges, &expected);
            if (success)
                success = add_both(&ranges, &expected, start - 9, end + 9) && check(&ranges, &expected);
            quicly_bplus_ranges_dispose(&ranges);
            quicly_ranges_clear(&expected);
        }
    }
    ok(success);
}

/**
 * Builds a fragmented tree by adding isolated ranges in ascending (`order == 0`), descending (1), or shuffled (2) order, then
 * interleaves adding isolated ranges into gaps, extending ranges, filling gaps, and adding ranges that span multiple ranges,
 * comparing against quicly_ranges_t after every addition. Unlike the ascending order, the descending and shuffled orders split
 * nodes other than those on the rightmost path.
 */
static int test_fragmented_order(int order)
{
    enum { NUM_RANGES = 4000, NUM_OPS = 6000, STRIDE = 8 };
    quicly_bplus_ranges_t ranges;
    quicly_ranges_t expected;
    uint64_t *indices = malloc(NUM_RANGES * sizeof(*indices));
    int success = 1;

    quicly_bplus_ranges_init(&ranges);
    quicly_ranges_init_with_range(&expected, 0, 0);
    srand(3 + order);

    /* build; ranges are at STRIDE * index + 4, leaving gaps of STRIDE - 1 bytes */
    for (size_t i = 0; i < NUM_RANGES; ++i)
        indices[i] = order == 1 ? NUM_RANGES - 1 - i : i;
    if (order == 2) {
        for (size_t i = NUM_RANGES - 1; i > 0; --i) {
            size_t j = (size_t)rand() % (i + 1);
            uint64_t t = indices[i];
            indices[i] = indices[j];
            indices[j] = t;
        }
    }
    for (size_t i = 0; success && i < NUM_RANGES; ++i) {
        uint64_t off = indices[i] * STRIDE + 4;
        success = add_both(&ranges, &expected, off, off + 1) && check(&ranges, &expected);
    }

    /* interleave additions of various kinds at random positions */
    for (size_t i = 0; success && i < NUM_OPS; ++i) {
        uint64_t base = (uint64_t)(rand() % (NUM_RANGES - 1)) * STRIDE, start, end;
        switch (rand() % 8) {
        case 0:
        case 1:
        case 2: /* isolated range in the middle of a gap */
            start = base + 8;
            end = start + 1;
            break;
        case 3:
        case 4: /* extend a range */
            start = base + 5;
            end = start + 1;
            break;
        case 5:
        case 6: /* fill a gap, merging the neighbors */
            start = base + 5;
            end = base + 12;
            break;
        default: /* span multiple ranges */
            start = base + (uint64_t)rand() % STRIDE;
            end = start + 1 + (uint64_t)rand() % (16 * STRIDE);
            break;
        }
        success = add_both(&ranges, &expected, start, end) && check(&ranges, &expected);
    }

    free(indices);
    quicly_bplus_ranges_dispose(&ranges);
    quicly_ranges_clear(&expected);
    return success;
}

static void test_fragmented(void)
{
    ok(test_fragmented_order(0));
    ok(test_fragmented_order(1));
    ok(test_fragmented_order(2));
}

void test_bplus_ranges(void)
{
    subtest("basic", test_basic);
    subtest("limit", test_limit);
    subtest("fill-gaps", test_fill_gaps);
    subtest("swallow", test_swallow);
    subtest("fragmented", test_fragmented);
}
