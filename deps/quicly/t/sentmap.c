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

static int on_acked(struct st_quicly_conn_t *conn, const quicly_sent_packet_t *packet, quicly_sent_t *sent,
                    quicly_sentmap_event_t event)
{
    ++on_acked_callcnt;
    if (event == QUICLY_SENTMAP_EVENT_ACKED)
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

void test_sentmap(void)
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
            quicly_sentmap_prepare(&map, at * 5 + i, at, 0);
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
            ok(sent->ack_epoch == 0);
            ok(sent->bytes_in_flight == 1);
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
        quicly_sentmap_update(&map, &iter, QUICLY_SENTMAP_EVENT_EXPIRED, NULL);
    ok(on_acked_callcnt == 30 * 4);
    ok(on_acked_ackcnt == 0);

    size_t cnt = 0;
    for (quicly_sentmap_init_iter(&map, &iter); (sent = quicly_sentmap_get(&iter))->packet_number != UINT64_MAX;
         quicly_sentmap_skip(&iter)) {
        ok(sent->bytes_in_flight != 0);
        ok(sent->packet_number <= 10 || 40 < sent->packet_number);
        ++cnt;
    }
    ok(cnt == 20);
    ok(num_blocks(&map) == 30 / 16 + 1 + 1 + 30 / 16 + 1);

    quicly_sentmap_dispose(&map);
}
