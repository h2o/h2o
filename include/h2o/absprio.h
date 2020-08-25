/*
 * Copyright (c) 2019 Fastly
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
#ifndef h2o__absprio_h
#define h2o__absprio_h

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define H2O_ABSPRIO_DEFAULT_URGENCY 3
#define H2O_ABSPRIO_NUM_URGENCY_LEVELS 8

typedef struct h2o_absprio_t {
    uint8_t urgency : 3;
    uint8_t incremental : 1;
} h2o_absprio_t;

extern h2o_absprio_t h2o_absprio_default;

void h2o_absprio_parse_priority(const char *s, size_t len, h2o_absprio_t *prio);
/**
 * Convert urgency value in absolute priority header to HTTP2 weight, having Chromium as a client in mind.
 */
static uint16_t h2o_absprio_urgency_to_chromium_weight(uint8_t urgency);

/* inline functions */

inline uint16_t h2o_absprio_urgency_to_chromium_weight(uint8_t urgency)
{
    uint16_t weight;
    assert(urgency < H2O_ABSPRIO_NUM_URGENCY_LEVELS);
    weight = (H2O_ABSPRIO_NUM_URGENCY_LEVELS - urgency) * 32;
    return weight;
}

#endif
