/*
 * Copyright (c) 2017-2024 Fastly, Kazuho Oku
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
#include "test.h"

struct test_jumpstart_action {
    enum { TEST_JUMPSTART_ACTION_END, TEST_JUMPSTART_ACTION_SEND, TEST_JUMPSTART_ACTION_ACKED, TEST_JUMPSTART_ACTION_LOST } action;
    int64_t now;
    uint32_t packets;
};

static void test_jumpstart_pattern(quicly_init_cc_t *init, const struct test_jumpstart_action *actions, uint32_t final_cwnd)
{
    static const uint32_t mtu = 1200;
    quicly_loss_t loss = {.rtt = {.latest = 100, .smoothed = 100, .minimum = 100, .variance = 0}};
    quicly_cc_t cc;
    int64_t now = 1;
    uint64_t next_pn = 0;
    uint32_t packets_acked = 0, packets_inflight = 0;
    size_t ackcnt = 0;

    init->cb(init, &cc, 10 * mtu, now);
    ok(cc.cwnd == 10 * mtu);
    ok(cc.num_loss_episodes == 0);

    for (const struct test_jumpstart_action *action = actions; action->action != TEST_JUMPSTART_ACTION_END; ++action) {
        switch (action->action) {
        case TEST_JUMPSTART_ACTION_SEND:
            cc.type->cc_on_sent(&cc, &loss, action->packets * mtu, action->now);
            packets_inflight += action->packets;
            next_pn += action->packets;
            break;
        case TEST_JUMPSTART_ACTION_ACKED:
            cc.type->cc_on_acked(&cc, &loss, action->packets * mtu, packets_acked + action->packets - 1, packets_inflight * mtu, 1,
                                 next_pn, action->now, mtu);
            packets_inflight -= action->packets;
            packets_acked += action->packets;
            ++ackcnt;
            /* enter jumpstart upon receiving the first ack */
            if (ackcnt == 1 && cc.num_loss_episodes == 0) {
                cc.type->cc_jumpstart(&cc, 20 * mtu, next_pn);
                ok(cc.cwnd == 20 * mtu);
            }
            break;
        case TEST_JUMPSTART_ACTION_LOST:
            cc.type->cc_on_lost(&cc, &loss, action->packets * mtu, packets_acked + action->packets - 1, next_pn, action->now, mtu);
            packets_inflight -= action->packets;
            packets_acked += action->packets;
            ok(!quicly_cc_in_jumpstart(&cc));
            ok(cc.ssthresh < UINT32_MAX);
            break;
        default:
            assert(!"FIXME");
        }
    }

    ok(!quicly_cc_in_jumpstart(&cc));
    ok(cc.cwnd == final_cwnd * mtu);
}

static void do_test_jumpstart(quicly_init_cc_t *init)
{
    /* if all packets sent in the unvalidated phase are acked, final CWND is 2x jumpstart cwnd */
    subtest("simple", test_jumpstart_pattern, init,
            (struct test_jumpstart_action[]){
                {TEST_JUMPSTART_ACTION_SEND, 1000, 2},   /* send 2 packets */
                {TEST_JUMPSTART_ACTION_ACKED, 1100, 2},  /* 2 packet acked, entering jumpstart */
                {TEST_JUMPSTART_ACTION_SEND, 1100, 20},  /* use full jumpstart window */
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 20}, /* receive acks for all packets send in jumpstart */
                {TEST_JUMPSTART_ACTION_END},
            },
            40);

    /* if a packet is lost in the reconnaisance phase, jumpstart is not entered */
    subtest("loss-inreconnaisance", test_jumpstart_pattern, init,
            (struct test_jumpstart_action[]){
                {TEST_JUMPSTART_ACTION_SEND, 1000, 2},  /* send 2 packets */
                {TEST_JUMPSTART_ACTION_LOST, 1100, 1},  /* 1st packet lost */
                {TEST_JUMPSTART_ACTION_ACKED, 1100, 1}, /* 2nd packet acked */
                {TEST_JUMPSTART_ACTION_END},
            },
            5);

    /* if 25% of packets sent in the unvalidated phase are lost, final CWND is 75% the jumpstart cwnd */
    subtest("proportional rate reduction", test_jumpstart_pattern, init,
            (struct test_jumpstart_action[]){
                {TEST_JUMPSTART_ACTION_SEND, 1000, 2},  /* send 2 packets */
                {TEST_JUMPSTART_ACTION_ACKED, 1100, 2}, /* 2 packet acked, entering jumpstart */
                {TEST_JUMPSTART_ACTION_SEND, 1100, 20}, /* use full jumpstart window */
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 8},
                {TEST_JUMPSTART_ACTION_LOST, 1200, 2},
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 7},
                {TEST_JUMPSTART_ACTION_LOST, 1200, 3},
                {TEST_JUMPSTART_ACTION_END},
            },
            15);

    /* regardless of how much we lose, we never go down below 1/2 IW */
    subtest("lower bound", test_jumpstart_pattern, init,
            (struct test_jumpstart_action[]){
                {TEST_JUMPSTART_ACTION_SEND, 1000, 2},  /* send 2 packets */
                {TEST_JUMPSTART_ACTION_ACKED, 1100, 2}, /* 2 packet acked, entering jumpstart */
                {TEST_JUMPSTART_ACTION_SEND, 1100, 20}, /* use full jumpstart window */
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 1},
                {TEST_JUMPSTART_ACTION_LOST, 1200, 9},
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 2},
                {TEST_JUMPSTART_ACTION_LOST, 1200, 8},
                {TEST_JUMPSTART_ACTION_END},
            },
            5);

    /* When receiving ACK early in the reconnaisance phase before sending entire batch, CWND doubles per each RT from bytes_inflight
     * (of 10 packets, in the test case below). */
    subtest("simple", test_jumpstart_pattern, init,
            (struct test_jumpstart_action[]){
                {TEST_JUMPSTART_ACTION_SEND, 1000, 2},  /* send 2 packets */
                {TEST_JUMPSTART_ACTION_ACKED, 1100, 2}, /* 2 packet acked, entering jumpstart */
                {TEST_JUMPSTART_ACTION_SEND, 1100, 10}, /* use full jumpstart window */
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 2}, /* receive acks for all packets send in jumpstart */
                {TEST_JUMPSTART_ACTION_SEND, 1200, 4},  /* use full jumpstart window */
                {TEST_JUMPSTART_ACTION_ACKED, 1200, 8}, /* receive acks for all packets send in jumpstart */
                {TEST_JUMPSTART_ACTION_END},
            },
            20);
}

void test_jumpstart(void)
{
    subtest("reno", do_test_jumpstart, &quicly_cc_reno_init);
    subtest("pico", do_test_jumpstart, &quicly_cc_pico_init);
    subtest("cubic", do_test_jumpstart, &quicly_cc_cubic_init);
}
