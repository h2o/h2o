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
#ifndef quicly_ranges_h
#define quicly_ranges_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct st_quicly_range_t {
    uint64_t start;
    uint64_t end; /* non-inclusive */
} quicly_range_t;

typedef struct st_quicly_ranges_t {
    quicly_range_t *ranges;
    size_t num_ranges, capacity;
    quicly_range_t _initial;
} quicly_ranges_t;

/**
 * initializes the structure
 */
static void quicly_ranges_init(quicly_ranges_t *ranges);
/**
 * initializes the structure, registering given range
 */
int quicly_ranges_init_with_range(quicly_ranges_t *ranges, uint64_t start, uint64_t end);
/**
 * clears the structure
 */
static void quicly_ranges_clear(quicly_ranges_t *ranges);
/**
 * adds given range, returns 0 if successful
 */
int quicly_ranges_add(quicly_ranges_t *ranges, uint64_t start, uint64_t end);
/**
 * subtracts given range, returns 0 if sucessful
 */
int quicly_ranges_subtract(quicly_ranges_t *ranges, uint64_t start, uint64_t end);
/**
 * removes ranges->ranges[I] where begin_index <= I && I < end_index
 */
void quicly_ranges_drop_by_range_indices(quicly_ranges_t *ranges, size_t begin_index, size_t end_index);

/* inline functions */

inline void quicly_ranges_init(quicly_ranges_t *ranges)
{
    ranges->ranges = &ranges->_initial;
    ranges->num_ranges = 0;
    ranges->capacity = 1;
}

inline void quicly_ranges_clear(quicly_ranges_t *ranges)
{
    if (ranges->ranges != &ranges->_initial) {
        free(ranges->ranges);
        ranges->ranges = &ranges->_initial;
    }
    ranges->num_ranges = 0;
    ranges->capacity = 1;
}

#ifdef __cplusplus
}
#endif

#endif
