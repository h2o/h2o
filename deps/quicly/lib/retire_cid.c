/*
 * Copyright (c) 2020 Fastly, Inc.
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

#include "quicly/retire_cid.h"

void quicly_retire_cid_init(quicly_retire_cid_set_t *set)
{
    set->_num_pending = 0;
}

void quicly_retire_cid_push(quicly_retire_cid_set_t *set, uint64_t sequence)
{
    if (set->_num_pending == PTLS_ELEMENTSOF(set->sequences)) {
        /* in case we don't find an empty slot, we'll just drop this sequence (never send RETIRE_CONNECTION_ID frame) */
        return;
    }

    for (size_t i = 0; i < set->_num_pending; i++) {
        if (set->sequences[i] == sequence) {
            /* already scheduled */
            return;
        }
    }

    set->sequences[set->_num_pending] = sequence;
    set->_num_pending++;
}

void quicly_retire_cid_shift(quicly_retire_cid_set_t *set, size_t num_shift)
{
    assert(num_shift <= PTLS_ELEMENTSOF(set->sequences));
    assert(num_shift <= set->_num_pending);
    /* move the remaining pending sequence numbers to the front */
    memmove(set->sequences, set->sequences + num_shift, sizeof(set->sequences[0]) * (set->_num_pending - num_shift));
    set->_num_pending -= num_shift;
}
