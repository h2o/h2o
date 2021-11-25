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
#include "quicly/sentmap.h"
#include "test.h"

static int on_acked_callcnt, on_acked_ackcnt;

static int on_acked(quicly_sentmap_t *map, const quicly_sent_packet_t *packet, int acked, quicly_sent_t *sent)
{
    ++on_acked_callcnt;
    if (acked)
        ++on_acked_ackcnt;
    return 0;
}

static size_t num_blocks(quicly_sentmap_t *map)
{
    struct st_quicly_sent_block_t *block;
    size_t n = 0;

    for (block = map->head; block != NULL; block = block->next)
        ++n;

    return n;
}

static void test_basic(void)
{
    quicly_sentmap_t map;
    uint64_t at;
    size_t i;
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;

    quicly_sentmap_init(&map);

    /* save 50 packets, with 2 frames each */
    for (at = 0; at < 10; ++at) {
        for (i = 1; i <= 5; ++i) {
            quicly_sentmap_prepare(&map, at * 5 + i, at, QUICLY_EPOCH_INITIAL);
            quicly_sentmap_allocate(&map, on_acked);
            quicly_sentmap_allocate(&map, on_acked);
            quicly_sentmap_commit(&map, 1);
        }
    }

    /* check all acks */
    quicly_sentmap_init_iter(&map, &iter);
    for (at = 0; at < 10; ++at) {
        for (i = 1; i <= 5; ++i) {
            const quicly_sent_packet_t *sent = quicly_sentmap_get(&iter);
            ok(sent->packet_number == at * 5 + i);
            ok(sent->sent_at == at);
            ok(sent->ack_epoch == QUICLY_EPOCH_INITIAL);
            ok(sent->cc_bytes_in_flight == 1);
            quicly_sentmap_skip(&iter);
        }
    }
    ok(quicly_sentmap_get(&iter)->packet_number == UINT64_MAX);
    ok(num_blocks(&map) == 150 / 16 + 1);

    /* pop acks between 11 <= packet_number <= 40 */
    quicly_sentmap_init_iter(&map, &iter);
    while (quicly_sentmap_get(&iter)->packet_number <= 10)
        quicly_sentmap_skip(&iter);
    assert(quicly_sentmap_get(&iter)->packet_number == 11);
    while (quicly_sentmap_get(&iter)->packet_number <= 40)
        quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_EXPIRED);
    ok(on_acked_callcnt == 30 * 2);
    ok(on_acked_ackcnt == 0);

    size_t cnt = 0;
    for (quicly_sentmap_init_iter(&map, &iter); (sent = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX;
         quicly_sentmap_skip(&iter)) {
        ok(sent->cc_bytes_in_flight != 0);
        ok(sent->packet_number <= 10 || 40 < sent->packet_number);
        ++cnt;
    }
    ok(cnt == 20);
    ok(num_blocks(&map) == 30 / 16 + 1 + 1 + 30 / 16 + 1);

    quicly_sentmap_dispose(&map);
}

static void test_late_ack(void)
{
    quicly_sentmap_t map;
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;

    on_acked_callcnt = 0;
    on_acked_ackcnt = 0;

    quicly_sentmap_init(&map);

    /* commit pn 1, 2 */
    quicly_sentmap_prepare(&map, 1, 0, QUICLY_EPOCH_INITIAL);
    quicly_sentmap_allocate(&map, on_acked);
    quicly_sentmap_commit(&map, 10);
    quicly_sentmap_prepare(&map, 2, 0, QUICLY_EPOCH_INITIAL);
    quicly_sentmap_allocate(&map, on_acked);
    quicly_sentmap_commit(&map, 20);
    ok(map.bytes_in_flight == 30);

    /* mark pn 1 as lost */
    quicly_sentmap_init_iter(&map, &iter);
    sent = quicly_sentmap_get(&iter);
    assert(sent->packet_number == 1);
    ok(quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_LOST) == 0);
    ok(on_acked_callcnt == 1);
    ok(on_acked_ackcnt == 0);
    ok(map.bytes_in_flight == 20);

    /* mark pn 1, 2 as acked */
    quicly_sentmap_init_iter(&map, &iter);
    sent = quicly_sentmap_get(&iter);
    assert(sent->packet_number == 1);
    ok(quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
    sent = quicly_sentmap_get(&iter);
    assert(sent->packet_number == 2);
    ok(quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
    ok(on_acked_callcnt == 3);
    ok(on_acked_ackcnt == 2);
    ok(map.bytes_in_flight == 0);

    quicly_sentmap_dispose(&map);
}

static void test_pto(void)
{
    quicly_sentmap_t map;
    quicly_sentmap_iter_t iter;
    const quicly_sent_packet_t *sent;

    on_acked_callcnt = 0;
    on_acked_ackcnt = 0;

    quicly_sentmap_init(&map);

    /* commit pn 1, 2 */
    quicly_sentmap_prepare(&map, 1, 0, QUICLY_EPOCH_INITIAL);
    quicly_sentmap_allocate(&map, on_acked);
    quicly_sentmap_commit(&map, 10);
    quicly_sentmap_prepare(&map, 2, 0, QUICLY_EPOCH_INITIAL);
    quicly_sentmap_allocate(&map, on_acked);
    quicly_sentmap_commit(&map, 20);
    ok(map.bytes_in_flight == 30);

    /* mark pn 1 for PTO */
    quicly_sentmap_init_iter(&map, &iter);
    sent = quicly_sentmap_get(&iter);
    assert(sent->packet_number == 1);
    ok(quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_PTO) == 0);
    ok(on_acked_callcnt == 1);
    ok(on_acked_ackcnt == 0);
    ok(map.bytes_in_flight == 30);

    /* mark pn 1, 2 as acked */
    quicly_sentmap_init_iter(&map, &iter);
    sent = quicly_sentmap_get(&iter);
    assert(sent->packet_number == 1);
    ok(quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
    sent = quicly_sentmap_get(&iter);
    assert(sent->packet_number == 2);
    ok(quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_ACKED) == 0);
    ok(on_acked_callcnt == 3);
    ok(on_acked_ackcnt == 2);
    ok(map.bytes_in_flight == 0);

    quicly_sentmap_dispose(&map);
}

void test_sentmap(void)
{
    subtest("basic", test_basic);
    subtest("late-ack", test_late_ack);
    subtest("pto", test_pto);
}
