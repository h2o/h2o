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
#include "quicly/remote_cid.h"

#define CID_LEN 8

/* clang-format off */
static uint8_t cids[][CID_LEN] = {
	{0, 1, 2, 3, 4, 5, 6, 7}, /* 0 */
	{1, 2, 3, 4, 5, 6, 7, 0},
	{2, 3, 4, 5, 6, 7, 0, 1},
	{3, 4, 5, 6, 7, 0, 1, 2},
	{4, 5, 6, 7, 0, 1, 2, 3},
	{5, 6, 7, 0, 1, 2, 3, 4},
	{6, 7, 0, 1, 2, 3, 4, 5},
	{7, 0, 1, 2, 3, 4, 5, 6},
	{8, 9, 10, 11, 12, 13, 14, 15}, /* 8 */
};

static uint8_t srts[][QUICLY_STATELESS_RESET_TOKEN_LEN] = {
	{0},
	{1},
	{2},
	{3},
	{4},
	{5},
	{6},
	{7},
	{8},
};
/* clang-format on */

void test_received_cid(void)
{
    quicly_remote_cid_set_t set;
    uint64_t unregistered_seqs[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
    size_t num_unregistered;

    quicly_remote_cid_init_set(&set, NULL, quic_ctx.tls->random_bytes);
    /* fill CIDs */
    for (int i = 1; i < 4; i++) {
        ok(quicly_remote_cid_register(&set, i, cids[i], CID_LEN, srts[i], 0, unregistered_seqs, &num_unregistered) == 0);
        ok(num_unregistered == 0);
    }
    /* active CIDs = {*0, 1, 2, 3} (*0 is the current one) */

    /* dup */
    ok(quicly_remote_cid_register(&set, 1, cids[1], CID_LEN, srts[1], 0, unregistered_seqs, &num_unregistered) == 0);
    ok(num_unregistered == 0);
    /* same CID with different sequence number */
    ok(quicly_remote_cid_register(&set, 0, cids[1], CID_LEN, srts[1], 0, unregistered_seqs, &num_unregistered) != 0);
    ok(num_unregistered == 0);
    /* already full */
    ok(quicly_remote_cid_register(&set, 4, cids[4], CID_LEN, srts[4], 0, unregistered_seqs, &num_unregistered) ==
       QUICLY_TRANSPORT_ERROR_CONNECTION_ID_LIMIT);
    ok(set.cids[0].is_active && "we have CID to send error");

    /* try to unregister something doesn't exist */
    ok(quicly_remote_cid_unregister(&set, 255) != 0);
    /* retire seq=0 */
    ok(quicly_remote_cid_unregister(&set, 0) == 0);
    /* active CIDs = {*1, 2, 3} */
    ok(set.cids[0].is_active);
    ok(set.cids[0].sequence == 1);
    ok(memcmp(set.cids[0].cid.cid, cids[1], CID_LEN) == 0);
    ok(memcmp(set.cids[0].stateless_reset_token, srts[1], QUICLY_STATELESS_RESET_TOKEN_LEN) == 0);
    /* try to unregister sequence which is already unregistered */
    ok(quicly_remote_cid_unregister(&set, 0) != 0);
    /* sequence number out of current acceptable window */
    ok(quicly_remote_cid_register(&set, 255, cids[4], CID_LEN, srts[4], 0, unregistered_seqs, &num_unregistered) ==
       QUICLY_TRANSPORT_ERROR_CONNECTION_ID_LIMIT);
    ok(set.cids[0].is_active && "we have CID to send error");

    /* ignore already retired CID */
    ok(quicly_remote_cid_register(&set, 0, cids[0], CID_LEN, srts[0], 0, unregistered_seqs, &num_unregistered) == 0);
    ok(num_unregistered == 0);

    /* register 5th CID */
    ok(quicly_remote_cid_register(&set, 4, cids[4], CID_LEN, srts[4], 0, unregistered_seqs, &num_unregistered) == 0);
    ok(num_unregistered == 0);
    /* active CIDs = {*1, 2, 3, 4} */

    /* unregister seq=2 */
    ok(quicly_remote_cid_unregister(&set, 2) == 0);
    /* active CIDs = {*1, 3, 4} */
    ok(set.cids[0].is_active);
    ok(set.cids[0].sequence == 1);

    /* register 5, unregister prior to 5 -- seq=1,3,4 should be unregistered at this moment */
    ok(quicly_remote_cid_register(&set, 5, cids[5], CID_LEN, srts[5], 5, unregistered_seqs, &num_unregistered) == 0);
    /* active CIDs = {} */
    ok(num_unregistered == 3);
    {
        /* order in unregistered_seqs is not defined, so use a set to determine equivalence */
        char expected[5] = {0, 1, 0, 1, 1}; /* expect seq=1,3,4 */
        char seqset[5] = {0};
        for (size_t i = 0; i < num_unregistered; i++) {
            if (unregistered_seqs[i] < sizeof(seqset))
                seqset[unregistered_seqs[i]] = 1;
        }
        ok(memcmp(seqset, expected, sizeof(seqset)) == 0);
    }
    /* active CIDs = {*5} */
    ok(set.cids[0].is_active);
    ok(set.cids[0].sequence == 5);
    ok(memcmp(set.cids[0].cid.cid, cids[5], CID_LEN) == 0);
    ok(memcmp(set.cids[0].stateless_reset_token, srts[5], QUICLY_STATELESS_RESET_TOKEN_LEN) == 0);

    /* install CID with out-of-order sequence */
    ok(quicly_remote_cid_register(&set, 8, cids[8], CID_LEN, srts[8], 5, unregistered_seqs, &num_unregistered) == 0);
    ok(num_unregistered == 0);
    /* active CIDs = {*5, 8} */
    ok(quicly_remote_cid_register(&set, 7, cids[7], CID_LEN, srts[7], 5, unregistered_seqs, &num_unregistered) == 0);
    /* active CIDs = {*5, 7, 8} */
    ok(set.cids[0].is_active);
    ok(set.cids[0].sequence == 5);

    /* unregister prior to 8 -- seq=5,7 should be unregistered at this moment */
    ok(quicly_remote_cid_register(&set, 8, cids[8], CID_LEN, srts[8], 8, unregistered_seqs, &num_unregistered) == 0);
    /* active CIDs = {*8} */
    ok(num_unregistered == 2);
    {
        /* order in unregistered_seqs is not defined, so use a set to determine equivalence */
        char expected[8] = {0, 0, 0, 0, 0, 1, 0, 1}; /* expect seq=5,7 */
        char seqset[8] = {0};
        for (size_t i = 0; i < num_unregistered; i++) {
            if (unregistered_seqs[i] < sizeof(seqset))
                seqset[unregistered_seqs[i]] = 1;
        }
        ok(memcmp(seqset, expected, sizeof(seqset)) == 0);
    }
    ok(set.cids[0].is_active);
    ok(set.cids[0].sequence == 8);
}
