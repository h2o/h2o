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
#include <assert.h>
#include <stdlib.h>
#include "quicly/ack.h"

const quicly_ack_t quicly_acks__end_iter = {UINT64_MAX, INT64_MAX};

void quicly_acks_dispose(quicly_acks_t *acks)
{
    struct st_quicly_ack_block_t *block;

    while ((block = acks->head) != NULL) {
        acks->head = block->next;
        free(block);
    }
}

struct st_quicly_ack_block_t *quicly_acks__new_block(quicly_acks_t *acks)
{
    struct st_quicly_ack_block_t *block;

    if ((block = malloc(sizeof(*block))) == NULL)
        return NULL;

    block->next = NULL;
    block->total = 0;
    block->active = 0;
    if (acks->tail != NULL) {
        acks->tail->next = block;
        acks->tail = block;
    } else {
        acks->head = acks->tail = block;
    }

    return block;
}

struct st_quicly_ack_block_t **quicly_acks__release_block(quicly_acks_t *acks, struct st_quicly_ack_block_t **ref)
{
    static const struct st_quicly_ack_block_t dummy = {NULL};
    static const struct st_quicly_ack_block_t *const dummy_ref = &dummy;
    struct st_quicly_ack_block_t *block = *ref;

    if (block->next != NULL) {
        *ref = block->next;
        assert((*ref)->active != 0);
    } else {
        assert(block == acks->tail);
        if (ref == &acks->head) {
            acks->head = NULL;
            acks->tail = NULL;
        } else {
            acks->tail = (void *)((char *)ref - offsetof(struct st_quicly_ack_block_t, next));
            acks->tail->next = NULL;
        }
        ref = (struct st_quicly_ack_block_t **)&dummy_ref;
    }

    free(block);
    return ref;
}
