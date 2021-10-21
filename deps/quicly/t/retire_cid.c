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

#include "test.h"
#include "picotls.h"
#include "quicly/retire_cid.h"

/**
 * verifies that expected sequence numbers are in that order at the front of the array.
 * Returns zero on success.
 */
static int verify(const quicly_retire_cid_set_t *set, const uint64_t expected_seqs[], size_t num_seqs)
{
    size_t i;

    if (set->_num_pending != num_seqs)
        return 1;

    for (i = 0; i < num_seqs && i < PTLS_ELEMENTSOF(set->sequences); i++) {
        if (set->sequences[i] != expected_seqs[i])
            return 1;
    }

    return 0;
}

void test_retire_cid(void)
{
    uint64_t sequence = 0;

    quicly_retire_cid_set_t set;
    quicly_retire_cid_init(&set);

    /* should be empty */
    ok(verify(&set, NULL, 0) == 0);

    /* push one sequence number */
    quicly_retire_cid_push(&set, sequence);
    {
        uint64_t seqs[] = {sequence};
        ok(verify(&set, seqs, PTLS_ELEMENTSOF(seqs)) == 0);
    }

    sequence++;

    /* shift one -- back to empty */
    quicly_retire_cid_shift(&set, 1);
    ok(verify(&set, NULL, 0) == 0);

    {
        /* make the array full */
        uint64_t seqs[PTLS_ELEMENTSOF(set.sequences)];
        for (size_t i = 0; i < PTLS_ELEMENTSOF(set.sequences); i++) {
            seqs[i] = sequence;
            quicly_retire_cid_push(&set, sequence);
            sequence++;
        }
        ok(verify(&set, seqs, PTLS_ELEMENTSOF(seqs)) == 0);
        /* make sure duplicated push is ignored */
        quicly_retire_cid_push(&set, seqs[0]);
        ok(verify(&set, seqs, PTLS_ELEMENTSOF(seqs)) == 0);
        /* make sure push is ignored when the array is already full */
        quicly_retire_cid_push(&set, sequence + 1);
        ok(verify(&set, seqs, PTLS_ELEMENTSOF(seqs)) == 0);
        /* zero shift from a full array */
        quicly_retire_cid_shift(&set, 0);
        /* test partial removal */
        size_t num_shift = PTLS_ELEMENTSOF(seqs) / 2;
        quicly_retire_cid_shift(&set, num_shift);
        ok(verify(&set, seqs + num_shift, PTLS_ELEMENTSOF(seqs) - num_shift) == 0);
        /* test zero shift */
        quicly_retire_cid_shift(&set, 0);
        ok(verify(&set, seqs + num_shift, PTLS_ELEMENTSOF(seqs) - num_shift) == 0);
        /* remove remaining sequence numbers */
        quicly_retire_cid_shift(&set, PTLS_ELEMENTSOF(seqs) - num_shift);
        ok(verify(&set, NULL, 0) == 0);
    }
}
