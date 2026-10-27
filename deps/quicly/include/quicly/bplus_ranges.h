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
#ifndef quicly_bplus_ranges_h
#define quicly_bplus_ranges_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "quicly/constants.h"
#include "quicly/ranges.h"

#define QUICLY_BPLUS_RANGES_FANOUT_BITS 4
#define QUICLY_BPLUS_RANGES_FANOUT (1 << QUICLY_BPLUS_RANGES_FANOUT_BITS)

/**
 * A node of the B+ tree. Entries are packed at the front; unused slots hold UINT64_MAX as the start of the range (leaf) or as the
 * key (non-leaf). `children[i]` (`i > 0`) exists if `keys[i]` is in use; the content of unused child slots is undefined.
 */
typedef union un_quicly_bplus_ranges_node_t {
    /**
     * leaf
     */
    quicly_range_t ranges[QUICLY_BPLUS_RANGES_FANOUT];
    /**
     * non-leaf; keys[i] is the start of the first range under children[i]; keys[0] is unused, as children[0] always exists
     */
    struct {
        uint64_t keys[QUICLY_BPLUS_RANGES_FANOUT];
        union un_quicly_bplus_ranges_node_t *children[QUICLY_BPLUS_RANGES_FANOUT];
    };
} quicly_bplus_ranges_node_t;

/**
 * A set of non-overlapping, non-adjacent ranges of a stream being received, backed by a B+ tree. Ranges are only added; existing
 * ranges are removed only by being merged into the added one.
 */
typedef struct st_quicly_bplus_ranges_t {
    /**
     * number of ranges contained
     */
    size_t num_ranges;
    /**
     * number of levels including the leaves; 1 means `root` is a leaf
     */
    uint8_t height;
    /**
     * the root node; points to `quicly_bplus_ranges_t::first` if `root` is a leaf
     */
    quicly_bplus_ranges_node_t *root;
    /**
     * last range
     */
    quicly_range_t *last;
    /**
     * first leaf; it always remains the first, so no memory is allocated until the number of ranges exceeds
     * QUICLY_BPLUS_RANGES_FANOUT
     */
    quicly_bplus_ranges_node_t first;
} quicly_bplus_ranges_t;

/**
 * initializes the structure, registering [0, 0)
 */
static void quicly_bplus_ranges_init(quicly_bplus_ranges_t *ranges);
/**
 * frees all memory
 */
void quicly_bplus_ranges_dispose(quicly_bplus_ranges_t *ranges);
/**
 * Adds given range, merging it with the ranges it overlaps or touches. `max_committed` is the maximum offset that the peer is
 * permitted to send. A range disjoint from all existing ones is rejected with QUICLY_ERROR_STATE_EXHAUSTION if `num_ranges` has
 * reached max(63, (max_committed - first.end) / 1024 + 1), up to 2^22. The structure is left unmodified when an error is returned.
 */
quicly_error_t quicly_bplus_ranges_add(quicly_bplus_ranges_t *ranges, uint64_t start, uint64_t end, uint64_t max_committed);

/* inline functions */

inline void quicly_bplus_ranges_init(quicly_bplus_ranges_t *ranges)
{
    ranges->first.ranges[0] = (quicly_range_t){0, 0};
    for (size_t i = 1; i < QUICLY_BPLUS_RANGES_FANOUT; ++i) {
        ranges->first.ranges[i].start = UINT64_MAX;
        ranges->first.ranges[i].end = UINT64_MAX;
    }
    ranges->num_ranges = 1;
    ranges->height = 1;
    ranges->root = &ranges->first;
    ranges->last = ranges->first.ranges;
}

#ifdef __cplusplus
}
#endif

#endif
