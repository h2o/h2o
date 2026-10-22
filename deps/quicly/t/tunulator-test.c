/*
 * Copyright (c) 2026 Kazuho Oku
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

#define main tunulator_main
#include "tunulator.c"
#undef main
#include "picotest.h"

static void add_packets(struct queue *q, uint64_t at, size_t len, unsigned count)
{
    for (unsigned i = 0; i < count; ++i) {
        struct packet *p = calloc(1, sizeof(*p) + len);
        assert(p != NULL);
        p->at = at;
        p->len = len;
        enqueue(q, p);
    }
}

static void clear_queue(struct queue *q)
{
    while (q->head != NULL)
        free(dequeue(q));
}

static void test_controller(void)
{
    struct queue q;
    struct codel c = codel_defaults;
    init_queue(&q);
    add_packets(&q, 0, 1500, 30);

    codel_prepare(&c, &q, 1500, c.target - 1);
    ok(c.first_above_time == 0);
    codel_prepare(&c, &q, 1500, c.target);
    ok(c.first_above_time == 105 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 105 * NS_PER_MS - 1);
    ok(q.bytes == 30 * 1500 && !c.dropping);
    codel_prepare(&c, &q, 1500, 105 * NS_PER_MS);
    ok(q.bytes == 29 * 1500 && c.dropping && c.count == 1);
    ok(c.drop_next == 205 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 205 * NS_PER_MS);
    ok(q.bytes == 28 * 1500 && c.count == 2);
    ok(c.drop_next == 275710678);
    /* A late transmission opportunity catches up with every due drop. */
    codel_prepare(&c, &q, 1500, 400 * NS_PER_MS);
    ok(q.bytes == 25 * 1500 && c.count == 5);
    ok(c.drop_next == 428167063);

    clear_queue(&q);
    codel_prepare(&c, &q, 1500, 401 * NS_PER_MS);
    ok(!c.dropping && c.first_above_time == 0);
    add_packets(&q, 400 * NS_PER_MS, 1500, 30);
    codel_prepare(&c, &q, 1500, 405 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 505 * NS_PER_MS);
    ok(c.dropping && c.count == 4 && c.lastcount == 4);
    ok(c.drop_next == 555 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 800 * NS_PER_MS);
    ok(c.count - c.lastcount > 1);

    clear_queue(&q);
    codel_prepare(&c, &q, 1500, 3000 * NS_PER_MS);
    add_packets(&q, 3000 * NS_PER_MS, 1500, 30);
    codel_prepare(&c, &q, 1500, 3005 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 3105 * NS_PER_MS);
    ok(c.dropping && c.count == 1 && c.lastcount == 1);
    clear_queue(&q);
}

static void test_recovery(void)
{
    struct queue q;
    struct codel c = codel_defaults;
    init_queue(&q);
    add_packets(&q, 0, 500, 5);
    codel_prepare(&c, &q, 1500, 5 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 105 * NS_PER_MS);
    ok(q.bytes == 2000 && c.first_above_time == 0);
    codel_prepare(&c, &q, 1500, 1000 * NS_PER_MS);
    ok(q.bytes == 2000 && !c.dropping); /* Exactly one MTU behind the head is protected. */
    clear_queue(&q);

    add_packets(&q, 1000 * NS_PER_MS, 1500, 20);
    codel_prepare(&c, &q, 1500, 1005 * NS_PER_MS);
    /* Seeing a fresh packet restarts the full interval, even if the backlog is large. */
    clear_queue(&q);
    add_packets(&q, 1050 * NS_PER_MS, 1500, 20);
    codel_prepare(&c, &q, 1500, 1050 * NS_PER_MS);
    ok(c.first_above_time == 0);
    codel_prepare(&c, &q, 1500, 1055 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 1105 * NS_PER_MS);
    ok(!c.dropping && q.bytes == 30000);
    codel_prepare(&c, &q, 1500, 1155 * NS_PER_MS);
    ok(c.dropping && q.bytes == 28500);
    clear_queue(&q);
    add_packets(&q, 1156 * NS_PER_MS, 1500, 20);
    codel_prepare(&c, &q, 1500, 1156 * NS_PER_MS);
    ok(!c.dropping && c.first_above_time == 0 && q.bytes == 30000);
    clear_queue(&q);
}

static struct tunulator *new_tunulator(void)
{
    struct tunulator *t = calloc(1, sizeof(*t));
    assert(t != NULL);
    t->mtu = 1500;
    t->fd = open("/dev/null", O_WRONLY);
    assert(t->fd >= 0);
    t->stats.next_at = UINT64_MAX;
    for (unsigned i = 0; i < 2; ++i) {
        init_queue(&t->dirs[i].delay);
        init_queue(&t->dirs[i].bottleneck);
        init_queue(&t->dirs[i].device);
        t->dirs[i].capacity = 100000;
        t->dirs[i].rate = 15000;
        t->dirs[i].codel = codel_defaults;
    }
    return t;
}

static void free_tunulator(struct tunulator *t)
{
    for (unsigned i = 0; i < 2; ++i) {
        clear_queue(&t->dirs[i].delay);
        clear_queue(&t->dirs[i].bottleneck);
        clear_queue(&t->dirs[i].device);
    }
    close(t->fd);
    free(t);
}

static void test_fixed_rate(void)
{
    struct tunulator *t = new_tunulator();
    struct direction *d = &t->dirs[1];
    d->discipline = DISCIPLINE_CODEL;
    /* These timestamps represent arrival after a one-second propagation delay. */
    add_packets(&d->delay, NS_PER_SEC, 1500, 20);
    for (unsigned i = 0; i < 20; ++i)
        run_event(t, 1, next_event(d));
    run_event(t, 1, next_event(d));
    ok(d->codel.first_above_time == 0 && d->bottleneck.bytes == 19 * 1500);
    ok(d->next_send == 1100 * NS_PER_MS);
    run_event(t, 1, next_event(d));
    ok(d->codel.first_above_time == 1200 * NS_PER_MS);
    run_event(t, 1, next_event(d));
    ok(d->codel.dropping && d->bottleneck.bytes == 16 * 1500);
    ok(t->stats.bytes[0][3] == 4500 && d->next_send == 1300 * NS_PER_MS);

    /* The other direction defaults to FIFO and has independent state. */
    add_packets(&t->dirs[0].bottleneck, 0, 1500, 20);
    for (unsigned i = 0; i < 4; ++i)
        run_event(t, 0, next_event(&t->dirs[0]));
    ok(t->dirs[0].bottleneck.bytes == 16 * 1500 && t->stats.bytes[0][1] == 6000);
    ok(!t->dirs[0].codel.dropping);
    free_tunulator(t);
}

static void test_trace(void)
{
    struct tunulator *t = new_tunulator();
    struct direction *d = &t->dirs[1];
    uint64_t slots[] = {5 * NS_PER_MS, 105 * NS_PER_MS, 205 * NS_PER_MS, 305 * NS_PER_MS};
    d->trace.at = slots;
    d->trace.count = sizeof(slots) / sizeof(slots[0]);
    d->trace.period = 400 * NS_PER_MS;
    d->discipline = DISCIPLINE_CODEL;
    t->mtu = 2000;
    add_packets(&d->bottleneck, 0, 2000, 20);
    struct packet *first = d->bottleneck.head;
    run_event(t, 1, next_event(d));
    ok(d->trace.remaining == 500 && d->bottleneck.head == first);
    ok(d->codel.first_above_time == 105 * NS_PER_MS);
    run_event(t, 1, next_event(d));
    /* Complete the first packet, drop the second, then spend the remaining 1000 bytes on the third. */
    ok(t->stats.bytes[0][3] == 2000 && d->trace.remaining == 1000);
    ok(d->codel.count == 1 && d->bottleneck.bytes == 18 * 2000);
    run_event(t, 1, next_event(d));
    ok(t->stats.bytes[0][3] == 4000 && d->trace.remaining == 1500);
    ok(d->codel.count == 2 && d->bottleneck.bytes == 16 * 2000);
    run_event(t, 1, next_event(d));
    ok(t->stats.bytes[0][3] == 6000 && d->trace.remaining == 0);
    ok(d->codel.count == 2); /* No CoDel check on the packet already being transmitted. */
    free_tunulator(t);
}

static uint16_t ip_checksum(const uint8_t *bytes)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < (bytes[0] & 15) * 4; i += 2)
        sum += read16(bytes + i);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return ~sum;
}

static void set_ecn(struct packet *p, unsigned ecn)
{
    p->bytes[0] = 0x46; /* Include IPv4 options in the checksum test. */
    p->bytes[1] = 0xb8 | ecn;
    write16(p->bytes + 2, p->len);
    p->bytes[8] = 63;
    p->bytes[9] = IPPROTO_UDP;
    p->bytes[20] = 1;
    write16(p->bytes + 10, 0);
    write16(p->bytes + 10, ip_checksum(p->bytes));
}

static void test_ecn(void)
{
    struct queue q;
    init_queue(&q);
    add_packets(&q, 0, 1500, 20);
    for (unsigned ecn = 0; ecn < 4; ++ecn) {
        set_ecn(q.head, ecn);
        uint8_t original[1500];
        memcpy(original, q.head->bytes, sizeof(original));
        ok(mark_ce(q.head) == (ecn != 0));
        ok(q.head->bytes[1] == (0xb8 | (ecn != 0 ? 3 : 0)));
        ok(ip_checksum(q.head->bytes) == 0);
        original[1] = q.head->bytes[1];
        memcpy(original + 10, q.head->bytes + 10, 2);
        ok(memcmp(original, q.head->bytes, sizeof(original)) == 0);
    }
    for (struct packet *p = q.head; p != NULL; p = p->next)
        set_ecn(p, 2);
    struct codel c = codel_defaults;
    codel_prepare(&c, &q, 1500, 5 * NS_PER_MS);
    ok((q.head->bytes[1] & 3) == 2);
    codel_prepare(&c, &q, 1500, 105 * NS_PER_MS);
    ok(c.count == 1 && c.dropping && q.bytes == 30000);
    ok((q.head->bytes[1] & 3) == 3 && ip_checksum(q.head->bytes) == 0);
    free(dequeue(&q));
    set_ecn(q.head, 0);
    /* Catch up by dropping a non-ECT packet, then marking and returning the next ECT packet exactly once. */
    codel_prepare(&c, &q, 1500, 1000 * NS_PER_MS);
    ok(c.count == 3 && q.bytes == 27000);
    ok((q.head->bytes[1] & 3) == 3 && c.drop_next == 333445704);
    clear_queue(&q);

    c = codel_defaults;
    c.ecn = 0;
    add_packets(&q, 0, 1500, 20);
    set_ecn(q.head, 2);
    codel_prepare(&c, &q, 1500, 5 * NS_PER_MS);
    codel_prepare(&c, &q, 1500, 105 * NS_PER_MS);
    ok(c.count == 1 && q.bytes == 28500);
    clear_queue(&q);
}

static void test_configuration(void)
{
    struct direction d = {0};
    init_queue(&d.bottleneck);
    ok(parse_queue_discipline(&d, "codel"));
    ok(d.discipline == DISCIPLINE_CODEL && d.codel.target == 5 * NS_PER_MS && d.codel.interval == 100 * NS_PER_MS && d.codel.ecn);
    ok(parse_queue_discipline(&d, "codel/noecn") && !d.codel.ecn);
    ok(d.codel.target == 5 * NS_PER_MS && d.codel.interval == 100 * NS_PER_MS);
    ok(parse_queue_discipline(&d, "codel/noecn:5:100") && !d.codel.ecn);
    ok(parse_queue_discipline(&d, "codel:10:200") && d.codel.ecn);
    ok(d.codel.target == 10 * NS_PER_MS && d.codel.interval == 200 * NS_PER_MS);
    add_packets(&d.bottleneck, 0, 1500, 20);
    codel_prepare(&d.codel, &d.bottleneck, 1500, 5 * NS_PER_MS);
    ok(d.codel.first_above_time == 0);
    codel_prepare(&d.codel, &d.bottleneck, 1500, 10 * NS_PER_MS);
    ok(d.codel.first_above_time == 210 * NS_PER_MS);
    codel_prepare(&d.codel, &d.bottleneck, 1500, 210 * NS_PER_MS);
    ok(d.bottleneck.bytes == 28500 && d.codel.drop_next == 410 * NS_PER_MS);
    clear_queue(&d.bottleneck);
    ok(parse_queue_discipline(&d, "fifo") && d.discipline == DISCIPLINE_FIFO);
    ok(parse_queue_discipline(&d, "dualpi2") && d.discipline == DISCIPLINE_DUALPI2 && d.device_limit == 0);
    ok(parse_queue_discipline(&d, "dualpi2:10") && d.discipline == DISCIPLINE_DUALPI2 && d.device_limit == 10);
    ok(parse_queue_discipline(&d, "codel") && d.codel.ecn);
    ok(d.codel.target == 5 * NS_PER_MS && d.codel.interval == 100 * NS_PER_MS && !d.codel.dropping);
    const char *invalid[] = {"",
                             "fq-codel",
                             "fifo:5:100",
                             "codel:",
                             "codel:5",
                             "codel:0:100",
                             "codel:5:0",
                             "codel:100:5",
                             "codel:5:5",
                             "codel:-5:100",
                             "codel:5:-100",
                             "codel:5:100x",
                             "codel:5:100:",
                             "codel:5:100:foo",
                             "codel:5:100:ecn:noecn",
                             "codel/noecnfoo",
                             "codel/noecn:",
                             "codel/noecn:5",
                             "codel:5:4294967296",
                             "codel:5:99999999999999999999999999",
                             "codel:5: 100",
                             "codel:5.5:100",
                             "dualpi2:",
                             "dualpi2:0",
                             "dualpi2:1001",
                             "dualpi2:1x",
                             "dualpi2x"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        ok(!parse_queue_discipline(&d, invalid[i]));
}

static void test_ecn_bandwidth(void)
{
    for (unsigned trace = 0; trace < 2; ++trace) {
        struct tunulator *t = new_tunulator();
        struct direction *d = &t->dirs[1];
        ok(parse_queue_discipline(d, "codel:5:100"));
        uint64_t slots[] = {105 * NS_PER_MS};
        if (trace) {
            d->trace.at = slots;
            d->trace.count = 1;
            d->trace.period = 200 * NS_PER_MS;
        } else {
            d->next_send = slots[0];
        }
        add_packets(&d->bottleneck, 0, 1500, 20);
        set_ecn(d->bottleneck.head, 2);
        codel_prepare(&d->codel, &d->bottleneck, t->mtu, 5 * NS_PER_MS);
        run_event(t, 1, next_event(d));
        ok(d->codel.count == 1 && d->bottleneck.bytes == 28500);
        ok(t->stats.bytes[0][3] == 1500);
        ok(next_event(d) == (trace ? 305 : 205) * NS_PER_MS);
        free_tunulator(t);
    }
}

static void test_dualpi2_step(void)
{
    struct dualpi2 s = {0};
    struct queue q;
    init_queue(&q);
    add_packets(&q, 0, 1500, 2);
    set_ecn(q.head, 1);
    set_ecn(q.head->next, 2);
    /* An L4S packet is marked once its sojourn time exceeds 1 ms. */
    dualpi2_prepare(&s, &q, 1500, NS_PER_MS);
    ok((q.head->bytes[1] & 3) == 1);
    dualpi2_prepare(&s, &q, 1500, NS_PER_MS + 1);
    ok((q.head->bytes[1] & 3) == 3 && ip_checksum(q.head->bytes) == 0);
    /* A classic packet is not. */
    free(dequeue(&q));
    dualpi2_prepare(&s, &q, 1500, 100 * NS_PER_MS);
    ok((q.head->bytes[1] & 3) == 2);
    clear_queue(&q);
}

static void test_dualpi2_pi(void)
{
    struct dualpi2 s = {0};
    struct queue q;
    init_queue(&q);

    /* Every 16 ms, the probability changes by alpha * (qdelay - target) + beta * (qdelay - last_qdelay), bounded below by 0. */
    dualpi2_update(&s, &q, 0);
    add_packets(&q, 0, 1500, 5);
    dualpi2_update(&s, &q, 16 * NS_PER_MS);
    ok(fabs(s.prob - (41. / 256 * 0.001 + 819. / 256 * 0.016)) < 1e-12);
    clear_queue(&q);
    dualpi2_update(&s, &q, 32 * NS_PER_MS);
    ok(s.prob == 0 && s.last_qdelay == 0);

    /* With at least 2 MTUs behind the head, L4S packets are marked at twice the probability. */
    add_packets(&q, 0, 1500, 3);
    for (struct packet *p = q.head; p != NULL; p = p->next)
        set_ecn(p, 1);
    s.prob = 0.5;
    dualpi2_prepare(&s, &q, 1500, 0);
    ok((q.head->bytes[1] & 3) == 3);
    free(dequeue(&q));
    dualpi2_prepare(&s, &q, 1500, 0);
    ok((q.head->bytes[1] & 3) == 1);
    clear_queue(&q);

    /* When twice the probability exceeds 1 (i.e., overload), they are dropped at the squared probability, while at least 2 MTUs
     * remain behind the head. */
    add_packets(&q, 0, 1500, 5);
    for (struct packet *p = q.head; p != NULL; p = p->next)
        set_ecn(p, 1);
    s.prob = 1;
    dualpi2_prepare(&s, &q, 1500, 0);
    ok(q.bytes == 3000);
    clear_queue(&q);

    /* The probability is updated at the events of the direction. */
    struct tunulator *t = new_tunulator();
    struct direction *d = &t->dirs[1];
    d->discipline = DISCIPLINE_DUALPI2;
    add_packets(&d->bottleneck, 0, 1500, 5);
    run_event(t, 1, next_event(d));
    run_event(t, 1, next_event(d));
    ok(d->dualpi2.prob > 0);
    free_tunulator(t);
}

static void test_dualpi2_device(void)
{
    struct tunulator *t = new_tunulator();
    struct direction *d = &t->dirs[1];
    uint64_t slots[] = {0, 21 * NS_PER_MS};
    d->trace.at = slots;
    d->trace.count = 2;
    d->trace.period = 100 * NS_PER_MS;
    ok(parse_queue_discipline(d, "dualpi2:1"));
    add_packets(&d->delay, NS_PER_MS, 1500, 2);
    for (struct packet *p = d->delay.head; p != NULL; p = p->next)
        set_ecn(p, 1);

    /* An L4S packet arriving while the device buffer has room moves there unmarked; the next one waits in DualPI2. */
    run_event(t, 1, next_event(d));
    run_event(t, 1, next_event(d));
    ok(d->device_packets == 1 && (d->device.head->bytes[1] & 3) == 1 && d->bottleneck.head != NULL);

    /* Once the link sends the first one at 21ms, the second moves to the device buffer, marked as it waited 20ms in DualPI2. */
    run_event(t, 1, next_event(d));
    ok(t->stats.bytes[0][3] == 1500 && d->device_packets == 1 && d->bottleneck.head == NULL);
    ok((d->device.head->bytes[1] & 3) == 3);
    free_tunulator(t);
}

int main(void)
{
    subtest("codel-controller", test_controller);
    subtest("codel-recovery", test_recovery);
    subtest("fixed-rate", test_fixed_rate);
    subtest("trace", test_trace);
    subtest("ecn", test_ecn);
    subtest("configuration", test_configuration);
    subtest("ecn-bandwidth", test_ecn_bandwidth);
    subtest("dualpi2-step", test_dualpi2_step);
    subtest("dualpi2-pi", test_dualpi2_pi);
    subtest("dualpi2-device", test_dualpi2_device);
    return done_testing();
}
