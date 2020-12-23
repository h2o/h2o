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

#include "../../test.h"
#include "../../../../lib/common/absprio.c"

static void test_parser(void)
{
    h2o_absprio_t p;

    p.urgency = 0;
    p.incremental = 1;
    h2o_absprio_parse_priority(H2O_STRLIT("u=1, i=?0"), &p);
    ok(p.urgency == 1);
    ok(p.incremental == 0);

    p.urgency = 0;
    p.incremental = 0;
    h2o_absprio_parse_priority(H2O_STRLIT("i=?1, u=7"), &p);
    ok(p.urgency == 7);
    ok(p.incremental == 1);

    /* Omitted value for "i" means "?1", u is preserved */
    p.urgency = 0;
    p.incremental = 0;
    h2o_absprio_parse_priority(H2O_STRLIT("i"), &p);
    ok(p.urgency == 0);
    ok(p.incremental == 1);

    p.urgency = 0;
    p.incremental = 1;
    h2o_absprio_parse_priority(H2O_STRLIT("u=3"), &p);
    ok(p.urgency == 3);
    ok(p.incremental == 1);

    /* Invalid values */
    p.urgency = 0;
    p.incremental = 1;
    h2o_absprio_parse_priority(H2O_STRLIT("i=?10, u=77"), &p);
    ok(p.urgency == 0);
    ok(p.incremental == 1);

    p.urgency = 0;
    p.incremental = 1;
    h2o_absprio_parse_priority(H2O_STRLIT("invalid"), &p);
    ok(p.urgency == 0);
    ok(p.incremental == 1);
}

void test_urgency_to_weight(void)
{
    ok(h2o_absprio_urgency_to_chromium_weight(0) == 256);
    ok(h2o_absprio_urgency_to_chromium_weight(1) == 220);
    ok(h2o_absprio_urgency_to_chromium_weight(2) == 183);
    ok(h2o_absprio_urgency_to_chromium_weight(3) == 147);
    ok(h2o_absprio_urgency_to_chromium_weight(4) == 110);
    ok(h2o_absprio_urgency_to_chromium_weight(5) == 74);
    ok(h2o_absprio_urgency_to_chromium_weight(6) == 37);
    ok(h2o_absprio_urgency_to_chromium_weight(7) == 1);
}

void test_lib__common__absprio_c(void)
{
    subtest("parser", test_parser);
    subtest("urgency_to_weight", test_urgency_to_weight);
}
