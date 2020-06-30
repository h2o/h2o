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
#ifndef quicly_retire_cid_h
#define quicly_retire_cid_h

#include "quicly/cid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * up to how many RETIRE_CONNECTION_IDs to keep for retransmission
 */
#define QUICLY_RETIRE_CONNECTION_ID_LIMIT (QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT * 2)

typedef struct st_quicly_retire_cid_set_t quicly_retire_cid_set_t;

struct st_quicly_retire_cid_set_t {
    /**
     * sequence numbers to ask for retirement
     * Valid entries are packed in the front of the array with FIFO manner.
     */
    uint64_t sequences[QUICLY_RETIRE_CONNECTION_ID_LIMIT];
    /**
     * number of pending sequence numbers
     */
    size_t _num_pending;
};

void quicly_retire_cid_init(quicly_retire_cid_set_t *set);
void quicly_retire_cid_push(quicly_retire_cid_set_t *set, uint64_t sequence);
void quicly_retire_cid_shift(quicly_retire_cid_set_t *set, size_t num_shift);
static size_t quicly_retire_cid_get_num_pending(const quicly_retire_cid_set_t *set);

inline size_t quicly_retire_cid_get_num_pending(const quicly_retire_cid_set_t *set)
{
    return set->_num_pending;
}

#ifdef __cplusplus
}
#endif

#endif
