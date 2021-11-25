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
    struct st_h2o_httpclient_protocol_selector_t selector = {.ratio = {.http2 = 5}};

    for (int i = 0; i != 110; ++i) {
        size_t selected = select_protocol(&selector);
        switch (i) {
        case 10:
        case 30:
        case 50:
        case 70:
        case 90:
            ok(selected == PROTOCOL_SELECTOR_H2);
            break;
        default:
            ok(selected == PROTOCOL_SELECTOR_H1);
            break;
        }
    }

    selector = (struct st_h2o_httpclient_protocol_selector_t){.ratio = {.http2 = 7}};
    for (int i = 0; i != 110; ++i) {
        size_t selected = select_protocol(&selector);
        switch (i) {
        case 7:
        case 21:
        case 35:
        case 50:
        case 64:
        case 78:
        case 92:
        case 107:
            ok(selected == PROTOCOL_SELECTOR_H2);
            break;
        default:
            ok(selected == PROTOCOL_SELECTOR_H1);
            break;
        }
    }

    selector = (struct st_h2o_httpclient_protocol_selector_t){.ratio = {.http2 = 93}};
    for (int i = 0; i != 110; ++i) {
        size_t selected = select_protocol(&selector);
        switch (i) {
        case 7:
        case 21:
        case 35:
        case 49:
        case 64:
        case 78:
        case 92:
        case 107:
            ok(selected == PROTOCOL_SELECTOR_H1);
            break;
        default:
            ok(selected == PROTOCOL_SELECTOR_H2);
            break;
        }
    }

    selector = (struct st_h2o_httpclient_protocol_selector_t){.ratio = {.http2 = 0}};
    for (int i = 0; i != 110; ++i) {
        size_t selected = select_protocol(&selector);
        ok(selected == PROTOCOL_SELECTOR_H1);
    }

    selector = (struct st_h2o_httpclient_protocol_selector_t){.ratio = {.http2 = 100}};
    for (int i = 0; i != 110; ++i) {
        size_t selected = select_protocol(&selector);
        ok(selected == PROTOCOL_SELECTOR_H2);
    }
}

void test_lib__common__httpclient_c(void)
{
    subtest("should_use_h2", test_should_use_h2);
}
