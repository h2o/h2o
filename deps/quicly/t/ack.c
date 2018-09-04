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
#include "quicly/ack.h"
#include "test.h"

static int on_acked(struct st_quicly_conn_t *conn, int is_ack, quicly_ack_t *ack)
{
    return 0;
}

static size_t num_blocks(quicly_acks_t *acks)
{
    struct st_quicly_ack_block_t *block;
    size_t n = 0;

    for (block = acks->head; block != NULL; block = block->next)
        ++n;

    return n;
}

void test_ack(void)
{
    quicly_acks_t acks;
    quicly_ack_t *ack;
    uint64_t at;
    size_t i, j;

    quicly_acks_init(&acks);

    /* save 150 acks, packet number from 1 to 50 */
    for (at = 0; at < 10; ++at)
        for (i = 1; i <= 5; ++i)
            for (j = 0; j < 3; ++j)
                quicly_acks_allocate(&acks, at * 5 + i, at, on_acked);

    /* check all acks */
    quicly_acks_iter_t iter;
    quicly_acks_init_iter(&acks, &iter);
    for (at = 0; at < 10; ++at) {
        for (i = 1; i <= 5; ++i) {
            for (j = 0; j < 3; ++j) {
                quicly_ack_t *ack = quicly_acks_get(&iter);
                ok(ack->packet_number != UINT64_MAX);
                ok(ack->packet_number == at * 5 + i);
                ok(ack->sent_at == at);
                ok(ack->acked == on_acked);
                quicly_acks_next(&iter);
            }
        }
    }
    ok(quicly_acks_get(&iter)->packet_number == UINT64_MAX);
    ok(num_blocks(&acks) == 150 / 16 + 1);

    /* pop acks between 11 <= packet_number <= 40 */
    quicly_acks_init_iter(&acks, &iter);
    while (quicly_acks_get(&iter)->packet_number <= 10) {
        quicly_acks_next(&iter);
        ok(quicly_acks_get(&iter)->packet_number != UINT64_MAX);
    }
    while ((ack = quicly_acks_get(&iter))->packet_number <= 40) {
        quicly_acks_on_ack(&acks, 0, ack, NULL);
        quicly_acks_release(&acks, &iter);
        quicly_acks_next(&iter);
        ok(quicly_acks_get(&iter)->packet_number != UINT64_MAX);
    }

    quicly_acks_init_iter(&acks, &iter);
    size_t cnt = 0;
    for (; quicly_acks_get(&iter)->packet_number != UINT64_MAX; quicly_acks_next(&iter)) {
        quicly_ack_t *ack = quicly_acks_get(&iter);
        ok(ack->acked != NULL);
        ok(ack->packet_number <= 10 || 40 < ack->packet_number);
        ++cnt;
    }
    ok(cnt == 60);
    ok(num_blocks(&acks) == 30 / 16 + 1 + 1 + 30 / 16 + 1);

    quicly_acks_dispose(&acks);
}
