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
    h2o_iovec_t value;
    uint8_t urgency = 255;
    int incremental = -1;

    value = (h2o_iovec_t){H2O_STRLIT("u=1, i=?0")};
    h2o_absprio_parse_priority(&value, &urgency, &incremental);
    ok(urgency == 1);
    ok(incremental == 0);

    urgency = 255;
    incremental = -1;
    value = (h2o_iovec_t){H2O_STRLIT("i=?1, u=7")};
    h2o_absprio_parse_priority(&value, &urgency, &incremental);
    ok(urgency == 7);
    ok(incremental == 1);

    /* Omitted value for "i" means "?1" */
    urgency = 255;
    incremental = -1;
    value = (h2o_iovec_t){H2O_STRLIT("i")};
    h2o_absprio_parse_priority(&value, &urgency, &incremental);
    ok(urgency == 255);
    ok(incremental == 1);

    urgency = 255;
    incremental = -1;
    value = (h2o_iovec_t){H2O_STRLIT("u=3")};
    h2o_absprio_parse_priority(&value, &urgency, &incremental);
    ok(urgency == 3);
    ok(incremental == -1);

    /* Invalid values */
    urgency = 255;
    incremental = -1;
    value = (h2o_iovec_t){H2O_STRLIT("i=?10, u=77")};
    h2o_absprio_parse_priority(&value, &urgency, &incremental);
    ok(urgency == 255);
    ok(incremental == -1);

    urgency = 255;
    incremental = -1;
    value = (h2o_iovec_t){H2O_STRLIT("invalid")};
    h2o_absprio_parse_priority(&value, &urgency, &incremental);
    ok(urgency == 255);
    ok(incremental == -1);
}

void test_lib__common__absprio_c(void)
{
    subtest("parser", test_parser);
}
