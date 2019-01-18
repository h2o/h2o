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
#include "quicly/maxsender.h"
#include "test.h"

static void test_basic(void)
{
    quicly_maxsender_t m;
    quicly_maxsender_sent_t ackargs;

    quicly_maxsender_init(&m, 100);

    /* basic checks */
    ok(!quicly_maxsender_should_update(&m, 0, 100, 512));
    ok(quicly_maxsender_should_update(&m, 0, 100, 1024));
    ok(!quicly_maxsender_should_update(&m, 99, 100, 0));
    ok(quicly_maxsender_should_update(&m, 100, 100, 0));

    /* scenario */
    ok(!quicly_maxsender_should_update(&m, 24, 100, 768));
    ok(quicly_maxsender_should_update(&m, 25, 100, 768));
    quicly_maxsender_record(&m, 125, &ackargs);
    ok(!quicly_maxsender_should_update(&m, 49, 100, 768));
    ok(quicly_maxsender_should_update(&m, 50, 100, 768));
    quicly_maxsender_acked(&m, &ackargs);
    ok(!quicly_maxsender_should_update(&m, 49, 100, 768));
    ok(quicly_maxsender_should_update(&m, 50, 100, 768));
    quicly_maxsender_record(&m, 150, &ackargs);
    ok(!quicly_maxsender_should_update(&m, 74, 100, 768));
    quicly_maxsender_lost(&m, &ackargs);
    ok(quicly_maxsender_should_update(&m, 74, 100, 768));
}

void test_maxsender(void)
{
    subtest("basic", test_basic);
}
