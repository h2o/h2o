/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"
#include "quicly/constants.h"
#include "quicly/ranges.h"

#define COPY(dst, src, n)                                                                                                          \
    do {                                                                                                                           \
        size_t _n = (n);                                                                                                           \
        if (_n != 0)                                                                                                               \
            memcpy((dst), (src), sizeof(quicly_range_t) * _n);                                                                     \
    } while (0)
#define MOVE(dst, src, n)                                                                                                          \
    do {                                                                                                                           \
        size_t _n = (n);                                                                                                           \
        if (_n != 0)                                                                                                               \
            memmove((dst), (src), sizeof(quicly_range_t) * _n);                                                                    \
    } while (0)

static int insert_at(quicly_ranges_t *ranges, uint64_t start, uint64_t end, size_t slot)
{
    if (ranges->num_ranges == ranges->capacity) {
        if (ranges->num_ranges == QUICLY_MAX_RANGES)
            return QUICLY_ERROR_STATE_EXHAUSTION;
        size_t new_capacity = ranges->capacity < 4 ? 4 : ranges->capacity * 2;
        if (new_capacity > QUICLY_MAX_RANGES)
            new_capacity = QUICLY_MAX_RANGES;
        quicly_range_t *new_ranges = malloc(new_capacity * sizeof(*new_ranges));
        if (new_ranges == NULL)
            return PTLS_ERROR_NO_MEMORY;
        COPY(new_ranges, ranges->ranges, slot);
        COPY(new_ranges + slot + 1, ranges->ranges + slot, ranges->num_ranges - slot);
        if (ranges->ranges != &ranges->_initial)
            free(ranges->ranges);
        ranges->ranges = new_ranges;
        ranges->capacity = new_capacity;
    } else {
        MOVE(ranges->ranges + slot + 1, ranges->ranges + slot, ranges->num_ranges - slot);
    }
    ranges->ranges[slot] = (quicly_range_t){start, end};
    ++ranges->num_ranges;
    return 0;
}

static void shrink_ranges(quicly_ranges_t *ranges, size_t begin_range_index, size_t end_range_index)
{
    assert(begin_range_index < end_range_index);

    MOVE(ranges->ranges + begin_range_index, ranges->ranges + end_range_index, ranges->num_ranges - end_range_index);
    ranges->num_ranges -= end_range_index - begin_range_index;
    if (ranges->capacity > 4 && ranges->num_ranges * 3 <= ranges->capacity) {
        size_t new_capacity = ranges->capacity / 2;
        quicly_range_t *new_ranges = realloc(ranges->ranges, new_capacity * sizeof(*new_ranges));
        if (new_ranges != NULL) {
            ranges->ranges = new_ranges;
            ranges->capacity = new_capacity;
        }
    }
}

static inline int merge_update(quicly_ranges_t *ranges, uint64_t start, uint64_t end, size_t slot, size_t end_slot)
{
    if (start < ranges->ranges[slot].start)
        ranges->ranges[slot].start = start;
    ranges->ranges[slot].end = end < ranges->ranges[end_slot].end ? ranges->ranges[end_slot].end : end;

    if (slot != end_slot)
        shrink_ranges(ranges, slot + 1, end_slot + 1);

    return 0;
}

int quicly_ranges_init_with_range(quicly_ranges_t *ranges, uint64_t start, uint64_t end)
{
    quicly_ranges_init(ranges);
    return insert_at(ranges, start, end, 0);
}

int quicly_ranges_add(quicly_ranges_t *ranges, uint64_t start, uint64_t end)
{
    size_t slot, end_slot;

    assert(start <= end);

    if (start == end)
        return 0;

    if (ranges->num_ranges == 0) {
        return insert_at(ranges, start, end, 0);
    } else if (ranges->ranges[ranges->num_ranges - 1].end < start) {
        return insert_at(ranges, start, end, ranges->num_ranges);
    }

    /* find the slot that should contain `end` */
    for (slot = ranges->num_ranges - 1;; --slot) {
        if (ranges->ranges[slot].start <= end)
            break;
        if (slot == 0)
            return insert_at(ranges, start, end, 0);
    }
    end_slot = slot;

    /* find the slot that should contain `start` */
    do {
        if (ranges->ranges[slot].end == start) {
            return merge_update(ranges, start, end, slot, end_slot);
        } else if (ranges->ranges[slot].end < start) {
            if (slot++ == end_slot) {
                return insert_at(ranges, start, end, slot);
            } else {
                return merge_update(ranges, start, end, slot, end_slot);
            }
        }
    } while (slot-- != 0);

    return merge_update(ranges, start, end, 0, end_slot);
}

int quicly_ranges_subtract(quicly_ranges_t *ranges, uint64_t start, uint64_t end)
{
    size_t shrink_from, slot;

    assert(start <= end);

    if (start == end)
        return 0;

    if (ranges->num_ranges == 0) {
        return 0;
    } else if (end <= ranges->ranges[0].start) {
        return 0;
    } else if (ranges->ranges[ranges->num_ranges - 1].end <= start) {
        return 0;
    }

    /* find the first overlapping slot */
    for (slot = 0; ranges->ranges[slot].end < start; ++slot)
        ;

    if (end <= ranges->ranges[slot].end) {
        /* first overlapping slot is the only slot that we will ever modify */
        if (end <= ranges->ranges[slot].start)
            return 0;
        if (start <= ranges->ranges[slot].start) {
            ranges->ranges[slot].start = end;
        } else if (end == ranges->ranges[slot].end) {
            ranges->ranges[slot].end = start;
        } else {
            /* split */
            int ret;
            if ((ret = insert_at(ranges, end, ranges->ranges[slot].end, slot + 1)) != 0)
                return ret;
            ranges->ranges[slot].end = start;
            return 0;
        }
        /* remove the slot if the range has become empty */
        if (ranges->ranges[slot].start == ranges->ranges[slot].end)
            shrink_ranges(ranges, slot, slot + 1);
        return 0;
    }

    /* specified region covers multiple slots */
    if (start <= ranges->ranges[slot].start) {
        shrink_from = slot;
    } else {
        ranges->ranges[slot].end = start;
        shrink_from = slot + 1;
    }

    /* find the last overlapping slot */
    for (++slot; slot != ranges->num_ranges; ++slot) {
        if (end <= ranges->ranges[slot].start)
            break;
        if (end < ranges->ranges[slot].end) {
            ranges->ranges[slot].start = end;
            break;
        }
    }

    /* remove shrink_from..slot */
    if (shrink_from != slot)
        shrink_ranges(ranges, shrink_from, slot);

    return 0;
}

void quicly_ranges_drop_smallest_range(quicly_ranges_t *ranges)
{
    assert(ranges->num_ranges != 0);
    shrink_ranges(ranges, 0, 1);
}
