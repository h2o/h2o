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

typedef enum en_h2o_absprio_urgency_type_t {
    H2O_ABSPRIO_URGENCY_PREREQUISITE = 0,
    H2O_ABSPRIO_URGENCY_DEFAULT = 1,
    H2O_ABSPRIO_URGENCY_SUPPLEMENTARY_0 = 2,
    H2O_ABSPRIO_URGENCY_SUPPLEMENTARY_1 = 3,
    H2O_ABSPRIO_URGENCY_SUPPLEMENTARY_2 = 4,
    H2O_ABSPRIO_URGENCY_SUPPLEMENTARY_3 = 5,
    H2O_ABSPRIO_URGENCY_SUPPLEMENTARY_4 = 6,
    H2O_ABSPRIO_URGENCY_BACKGROUND = 7,
} h2o_absprio_urgency_type_t;

void h2o_absprio_parse_priority(const h2o_iovec_t *header_value, uint8_t *urgency, int *incremental);
#endif
