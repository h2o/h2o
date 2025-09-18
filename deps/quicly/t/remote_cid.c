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
    {9, 10, 11, 12, 13, 14, 15, 16},
    {10, 11, 12, 13, 14, 15, 16, 17},
    {11, 12, 13, 14, 15, 16, 17, 18},
    {12, 13, 14, 15, 16, 17, 18, 19},
    {13, 14, 15, 16, 17, 18, 19, 20},
    {14, 15, 16, 17, 18, 19, 20, 21},
    {15, 16, 17, 18, 19, 20, 21, 22},
    {16, 17, 18, 19, 20, 21, 22, 23},
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
    {9},
    {10},
    {11},
    {12},
    {13},
    {14},
    {15},
    {16},
};
/* clang-format on */

void test_received_cid(void)
{
    quicly_remote_cid_set_t set;

#define TEST_SET(largest_expected, ...)                                                                                            \
    do {                                                                                                                           \
        ok(set._largest_sequence_expected == largest_expected);                                                                    \
        static const struct {                                                                                                      \
            uint64_t seq;                                                                                                          \
            quicly_remote_cid_state_t state;                                                                                       \
        } expected[] = {__VA_ARGS__};                                                                                              \
        PTLS_BUILD_ASSERT(PTLS_ELEMENTSOF(expected) == QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT);                                   \
        for (size_t i = 0; i < PTLS_ELEMENTSOF(expected); ++i) {                                                                   \
            ok(set.cids[i].state == expected[i].state);                                                                            \
            ok(set.cids[i].sequence == expected[i].seq);                                                                           \
            if (expected[i].state != QUICLY_REMOTE_CID_UNAVAILABLE) {                                                              \
                ok(set.cids[i].cid.len == CID_LEN);                                                                                \
                ok(expected[i].seq == 0 /* cid is random for seq 0 */ ||                                                           \
                   memcmp(set.cids[i].cid.cid, cids[expected[i].seq], CID_LEN) == 0);                                              \
                ok(expected[i].seq == 0 /* so is srt */ ||                                                                         \
                   memcmp(set.cids[i].stateless_reset_token, srts[expected[i].seq], QUICLY_STATELESS_RESET_TOKEN_LEN) == 0);       \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)
#define TEST_RETIRED(...)                                                                                                          \
    do {                                                                                                                           \
        static uint64_t expected[] = {__VA_ARGS__};                                                                                \
        ok(set.retired.count == PTLS_ELEMENTSOF(expected));                                                                        \
        for (size_t i = 0; i < PTLS_ELEMENTSOF(expected); ++i)                                                                     \
            ok(set.retired.cids[i] == expected[i]);                                                                                \
    } while (0)

    quicly_remote_cid_init_set(&set, NULL, quic_ctx.tls->random_bytes);

    /* fill CIDs */
    for (int i = 1; i < 4; i++) {
        ok(quicly_remote_cid_register(&set, i, cids[i], CID_LEN, srts[i], 0) == 0);
    }
    /* CIDs = {0, 1, 2, 3} */
    ok(set.retired.count == 0);

    /* dup */
    ok(quicly_remote_cid_register(&set, 1, cids[1], CID_LEN, srts[1], 0) == 0);
    ok(set.retired.count == 0);
    /* same CID with different sequence number */
    ok(quicly_remote_cid_register(&set, 0, cids[1], CID_LEN, srts[1], 0) != 0);
    ok(set.retired.count == 0);
    /* already full */
    ok(quicly_remote_cid_register(&set, 4, cids[4], CID_LEN, srts[4], 0) == QUICLY_TRANSPORT_ERROR_CONNECTION_ID_LIMIT);
    TEST_SET(3, {0, QUICLY_REMOTE_CID_IN_USE}, /* we have CID to send error */
             {1, QUICLY_REMOTE_CID_AVAILABLE}, {2, QUICLY_REMOTE_CID_AVAILABLE}, {3, QUICLY_REMOTE_CID_AVAILABLE});

    /* retire seq=0 */
    quicly_remote_cid_unregister(&set, 0);
    TEST_RETIRED(0);

    /* CIDs = {(4), 1, 2, 3} */
    TEST_SET(4, {4, QUICLY_REMOTE_CID_UNAVAILABLE}, {1, QUICLY_REMOTE_CID_AVAILABLE}, {2, QUICLY_REMOTE_CID_AVAILABLE},
             {3, QUICLY_REMOTE_CID_AVAILABLE});
    /* sequence number out of current acceptable window */
    ok(quicly_remote_cid_register(&set, 255, cids[4], CID_LEN, srts[4], 0) == QUICLY_TRANSPORT_ERROR_CONNECTION_ID_LIMIT);
    ok(set.cids[1].state == QUICLY_REMOTE_CID_AVAILABLE && "we have CID to send error");

    /* ignore already retired CID */
    ok(quicly_remote_cid_register(&set, 0, cids[0], CID_LEN, srts[0], 0) == 0);
    TEST_RETIRED(0);

    /* register 5th CID */
    ok(quicly_remote_cid_register(&set, 4, cids[4], CID_LEN, srts[4], 0) == 0);
    /* active CIDs = {4, 1, 2, 3} */
    TEST_SET(4, {4, QUICLY_REMOTE_CID_AVAILABLE}, {1, QUICLY_REMOTE_CID_AVAILABLE}, {2, QUICLY_REMOTE_CID_AVAILABLE},
             {3, QUICLY_REMOTE_CID_AVAILABLE});
    TEST_RETIRED(0);

    /* unregister seq=2 */
    quicly_remote_cid_unregister(&set, 2);
    /* active CIDs = {4, 1, (5), 3} */
    TEST_SET(5, {4, QUICLY_REMOTE_CID_AVAILABLE}, {1, QUICLY_REMOTE_CID_AVAILABLE}, {5, QUICLY_REMOTE_CID_UNAVAILABLE},
             {3, QUICLY_REMOTE_CID_AVAILABLE});
    TEST_RETIRED(0, 2);

    /* register 5, unregister prior to 5 -- seq=1,3,4 should be unregistered at this moment */
    ok(quicly_remote_cid_register(&set, 5, cids[5], CID_LEN, srts[5], 5) == 0);
    /* active CIDs = {(6), (7), 5, (8)} */
    TEST_SET(8, {6, QUICLY_REMOTE_CID_UNAVAILABLE}, {7, QUICLY_REMOTE_CID_UNAVAILABLE}, {5, QUICLY_REMOTE_CID_AVAILABLE},
             {8, QUICLY_REMOTE_CID_UNAVAILABLE});
    TEST_RETIRED(0, 2, 4, 1, 3);

    /* install CID with out-of-order sequence */
    ok(quicly_remote_cid_register(&set, 8, cids[8], CID_LEN, srts[8], 5) == 0);
    /* active CIDs = {(6), (7), 5, 8} */
    TEST_SET(8, {6, QUICLY_REMOTE_CID_UNAVAILABLE}, {7, QUICLY_REMOTE_CID_UNAVAILABLE}, {5, QUICLY_REMOTE_CID_AVAILABLE},
             {8, QUICLY_REMOTE_CID_AVAILABLE});
    TEST_RETIRED(0, 2, 4, 1, 3);
    ok(quicly_remote_cid_register(&set, 7, cids[7], CID_LEN, srts[7], 5) == 0);
    /* active CIDs = {(6), 7, 5, 8} */
    TEST_SET(8, {6, QUICLY_REMOTE_CID_UNAVAILABLE}, {7, QUICLY_REMOTE_CID_AVAILABLE}, {5, QUICLY_REMOTE_CID_AVAILABLE},
             {8, QUICLY_REMOTE_CID_AVAILABLE});
    TEST_RETIRED(0, 2, 4, 1, 3);

    /* unregister prior to 8 -- seq=5-7 should be unregistered at this moment */
    ok(quicly_remote_cid_register(&set, 8, cids[8], CID_LEN, srts[8], 8) == 0);
    /* active CIDs = {(9), (10), (11), 8} */
    TEST_SET(11, {9, QUICLY_REMOTE_CID_UNAVAILABLE}, {10, QUICLY_REMOTE_CID_UNAVAILABLE}, {11, QUICLY_REMOTE_CID_UNAVAILABLE},
             {8, QUICLY_REMOTE_CID_AVAILABLE});

    /* register 11 */
    ok(quicly_remote_cid_register(&set, 11, cids[11], CID_LEN, srts[11], 8) == 0);
    /* active CIDs = {(9), (10), (11), 8} */
    TEST_SET(11, {9, QUICLY_REMOTE_CID_UNAVAILABLE}, {10, QUICLY_REMOTE_CID_UNAVAILABLE}, {11, QUICLY_REMOTE_CID_AVAILABLE},
             {8, QUICLY_REMOTE_CID_AVAILABLE});
    TEST_RETIRED(0, 2, 4, 1, 3, 6, 7, 5);

    /* too many outstanding CIDs in retire queue */
    ok(quicly_remote_cid_register(&set, 11, cids[11], CID_LEN, srts[11], 9) == QUICLY_ERROR_STATE_EXHAUSTION);

    /* pretend as if RCID frames carrying the retired ones were sent and that all have been acked */
    set.retired.count = 0;

    /* retire more than ACTIVE_CID_LIMITs at once */
    ok(quicly_remote_cid_register(&set, 16, cids[16], CID_LEN, srts[16], 16) == 0);
    /* active CIDs = {16, (17), (18), (19)} */
    TEST_SET(19, {16, QUICLY_REMOTE_CID_AVAILABLE}, {17, QUICLY_REMOTE_CID_UNAVAILABLE}, {18, QUICLY_REMOTE_CID_UNAVAILABLE},
             {19, QUICLY_REMOTE_CID_UNAVAILABLE});
    TEST_RETIRED(9, 12, 13, 14, 15, 10, 11, 8);
}
