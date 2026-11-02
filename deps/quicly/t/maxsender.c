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
    ok(!quicly_maxsender_should_send_max(&m, 0, 0, 100, 512));
    ok(quicly_maxsender_should_send_max(&m, 0, 0, 100, 1024));
    ok(!quicly_maxsender_should_send_max(&m, 49, 49, 100, 0));
    ok(quicly_maxsender_should_send_max(&m, 50, 50, 100, 0));

    /* scenario */
    ok(!quicly_maxsender_should_send_max(&m, 24, 24, 100, 768));
    ok(quicly_maxsender_should_send_max(&m, 25, 25, 100, 768));
    quicly_maxsender_record(&m, 125, &ackargs);
    ok(!quicly_maxsender_should_send_max(&m, 49, 49, 100, 768));
    ok(quicly_maxsender_should_send_max(&m, 50, 50, 100, 768));
    ok(!quicly_maxsender_on_ack(&m, &ackargs, 1));
    ok(!quicly_maxsender_should_send_max(&m, 49, 49, 100, 768));
    ok(quicly_maxsender_should_send_max(&m, 50, 50, 100, 768));
    quicly_maxsender_record(&m, 150, &ackargs);
    ok(!quicly_maxsender_should_send_max(&m, 74, 74, 100, 768));
    ok(quicly_maxsender_on_ack(&m, &ackargs, 0));
    ok(quicly_maxsender_should_send_max(&m, 74, 74, 100, 768));
}

static void test_credit_growth(void)
{
    quicly_maxsender_t m;
    quicly_maxsender_sent_t sent;
    static const int64_t updates[] = {1, 2, 4, 8, 16, 32, 48, 64};
    size_t next_update = 0;

    /* With all credit used, advertise exponentially growing room until the quarter-window batching rule takes over. */
    quicly_maxsender_init(&m, 64);
    for (int64_t released = 0; released <= 64; ++released) {
        int should_send = quicly_maxsender_should_send_max(&m, released, 64, 64, 768);
        ok(should_send == (next_update < PTLS_ELEMENTSOF(updates) && released == updates[next_update]));
        if (should_send) {
            quicly_maxsender_record(&m, 64 + released, &sent);
            ++next_update;
        }
    }
    ok(next_update == PTLS_ELEMENTSOF(updates));

    /* Using more credit lowers the threshold, even if no additional room has been freed in the meantime. */
    quicly_maxsender_init(&m, 100);
    quicly_maxsender_record(&m, 108, &sent);
    ok(!quicly_maxsender_should_send_max(&m, 9, 100, 100, 768));
    ok(quicly_maxsender_should_send_max(&m, 9, 107, 100, 768));
    quicly_maxsender_record(&m, 109, &sent);
    ok(!quicly_maxsender_should_send_max(&m, 9, 109, 100, 768));
    ok(quicly_maxsender_should_send_max(&m, 10, 109, 100, 768));

    /* A smaller receive window must not turn exhaustion into repeated announcements of the same or a lower limit. */
    ok(!quicly_maxsender_should_send_max(&m, 10, 109, 50, 768));
    ok(quicly_maxsender_on_ack(&m, &sent, 0));
    ok(quicly_maxsender_should_send_max(&m, 10, 109, 50, 768));
}

static void test_known_delivery(void)
{
    quicly_maxsender_t m;
    quicly_maxsender_sent_t sent1, sent2;

    /* Once a late ACK confirms that `committed` has reached the peer, losing the resent copy does not trigger another resend. */
    quicly_maxsender_init(&m, 100);
    quicly_maxsender_record(&m, 150, &sent1);
    ok(quicly_maxsender_on_ack(&m, &sent1, 0));
    ok(quicly_maxsender_should_send_max(&m, 74, 74, 100, 768));
    quicly_maxsender_record(&m, 150, &sent2);
    ok(!quicly_maxsender_should_send_max(&m, 74, 74, 100, 768));
    ok(!quicly_maxsender_on_ack(&m, &sent1, 1));
    ok(m.acked == 150);
    ok(!quicly_maxsender_on_ack(&m, &sent2, 0));
    ok(!quicly_maxsender_should_send_max(&m, 74, 74, 100, 768));

    /* A late ACK arriving before the resend cancels it. */
    quicly_maxsender_init(&m, 100);
    quicly_maxsender_record(&m, 150, &sent1);
    ok(quicly_maxsender_on_ack(&m, &sent1, 0));
    ok(!quicly_maxsender_on_ack(&m, &sent1, 1));
    ok(!quicly_maxsender_should_send_max(&m, 74, 74, 100, 768));

    /* The peer reporting being blocked at `committed` proves delivery, hence a subsequent loss does not trigger a resend, while the
     * next greater value is sent as soon as it becomes available. */
    quicly_maxsender_init(&m, 100);
    quicly_maxsender_record(&m, 150, &sent1);
    quicly_maxsender_blocked(&m, 150);
    ok(m.acked == 150);
    ok(!quicly_maxsender_on_ack(&m, &sent1, 0));
    ok(!quicly_maxsender_should_send_max(&m, 50, 100, 100, 768));
    ok(quicly_maxsender_should_send_max(&m, 51, 100, 100, 768));

    /* A report of being blocked at an older value does not prove delivery of `committed`. */
    quicly_maxsender_init(&m, 100);
    quicly_maxsender_record(&m, 150, &sent1);
    quicly_maxsender_blocked(&m, 100);
    ok(m.acked == 100);
    ok(quicly_maxsender_on_ack(&m, &sent1, 0));
}

void test_maxsender(void)
{
    subtest("basic", test_basic);
    subtest("credit-growth", test_credit_growth);
    subtest("known-delivery", test_known_delivery);
}
