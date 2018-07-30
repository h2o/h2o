/*
 * Copyright (c) 2018 Ichito Nagata, Fastly, Inc
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
#include "../../../../lib/common/httpclient.c"

static void test_should_use_h2(void)
{
    int8_t counter = -1;
    int i;
    for (i = 0; i != 110; ++i) {
        int use_h2 = should_use_h2(5, &counter);
        switch (counter) {
            case 0:
            case 20:
            case 40:
            case 60:
            case 80:
                ok(use_h2 == 1);
                break;
            default:
                ok(use_h2 == 0);
                break;
        }
    }

    counter = 0;
    for (i = 0; i != 110; ++i) {
        int use_h2 = should_use_h2(7, &counter);
        switch (counter) {
            case 0:
            case 15:
            case 29:
            case 43:
            case 58:
            case 72:
            case 86:
                ok(use_h2 == 1);
                break;
            default:
                ok(use_h2 == 0);
                break;
        }
    }

    counter = 0;
    for (i = 0; i != 110; ++i) {
        int use_h2 = should_use_h2(93, &counter);
        switch (counter) {
            case 1:
            case 15:
            case 29:
            case 43:
            case 58:
            case 72:
            case 86:
                ok(use_h2 == 0);
                break;
            default:
                ok(use_h2 == 1);
                break;
        }
    }

    counter = 0;
    for (i = 0; i != 110; ++i) {
        int use_h2 = should_use_h2(0, &counter);
        ok(use_h2 == 0);
    }

    counter = 0;
    for (i = 0; i != 110; ++i) {
        int use_h2 = should_use_h2(100, &counter);
        ok(use_h2 == 1);
    }
}

void test_lib__common__httpclient_c(void)
{
    subtest("should_use_h2", test_should_use_h2);
}
