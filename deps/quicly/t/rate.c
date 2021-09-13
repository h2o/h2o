/*
 * Copyright (c) 2021 Fastly, Kazuho Oku
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

#include "quicly/rate.h"
#include "test.h"

#define CHECK_REPORT(el, es, ev)                                                                                                   \
    do {                                                                                                                           \
        quicly_rate_t rate;                                                                                                        \
        quicly_ratemeter_report(&meter, &rate);                                                                                    \
        ok(rate.latest == el);                                                                                                     \
        ok(rate.smoothed == es);                                                                                                   \
        ok(rate.stdev == ev);                                                                                                      \
    } while (0)

static void test_basic(void)
{
    quicly_ratemeter_t meter;

    quicly_ratemeter_init(&meter);
    CHECK_REPORT(0, 0, 0);

    uint64_t pn = 0, bytes_acked = 0;
    int64_t now = 1000;

    /* send 1KB packet every 20ms, in CWND-limited state */
    for (; pn < 100; ++pn) {
        quicly_ratemeter_in_cwnd_limited(&meter, pn);
        bytes_acked += 1000;
        now += 20;
        quicly_ratemeter_on_ack(&meter, now, bytes_acked, pn);
    }
    CHECK_REPORT(50000, 50000, 0);

    /* send at a slow rate, in application-limited state */
    for (; pn < 200; ++pn) {
        quicly_ratemeter_not_cwnd_limited(&meter, pn);
        bytes_acked += 10;
        now += 20;
        quicly_ratemeter_on_ack(&meter, now, bytes_acked, pn);
    }
    CHECK_REPORT(50000, 50000, 0);

    /* send 2KB packet every 20ms, in CWND-limited state */
    for (; pn < 300; ++pn) {
        quicly_ratemeter_in_cwnd_limited(&meter, pn);
        bytes_acked += 2000;
        now += 20;
        quicly_ratemeter_on_ack(&meter, now, bytes_acked, pn);
    }
    CHECK_REPORT(100000, 100000, 0);
}

static void test_burst(void)
{
    quicly_ratemeter_t meter;

    quicly_ratemeter_init(&meter);
    CHECK_REPORT(0, 0, 0);

    /* send 10 packet burst (pn=1 to 10) */
    quicly_ratemeter_in_cwnd_limited(&meter, 1);
    quicly_ratemeter_not_cwnd_limited(&meter, 11);

    /* ack every 2 packets up to pn=9, every 20ms */
    uint64_t pn = 0, bytes_acked = 0;
    int64_t now = 1000;
    while (1) {
        pn += 2;
        bytes_acked += 2000;
        now += 20;
        quicly_ratemeter_on_ack(&meter, now, bytes_acked, pn);
        if (pn == 10)
            break;
    }
    CHECK_REPORT(100000, 100000, 0);

    ok(meter.current.sample.elapsed != 0); /* we have an active sample ... */

    pn += 1;
    bytes_acked += 50;
    now += 20;
    quicly_ratemeter_on_ack(&meter, now, bytes_acked, pn);

    ok(meter.current.sample.elapsed == 0); /* that gets committed by the next pn out of the window */

    CHECK_REPORT(100000, 100000, 0);
}

void test_rate(void)
{
    subtest("basic", test_basic);
    subtest("burst", test_burst);
}
