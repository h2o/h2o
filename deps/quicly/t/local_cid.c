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
#include "quicly/local_cid.h"

#define NUM_CIDS 4

static void encrypt_cid(struct st_quicly_cid_encryptor_t *self, quicly_cid_t *encrypted, void *stateless_reset_token,
                        const quicly_cid_plaintext_t *plaintext)
{
    encrypted->cid[0] = plaintext->path_id;
    encrypted->len = 1;
}

static size_t decrypt_cid(struct st_quicly_cid_encryptor_t *self, quicly_cid_plaintext_t *plaintext, const void *encrypted,
                          size_t len)
{
    plaintext->path_id = ((const uint8_t *)encrypted)[0];
    return 1;
}

static quicly_cid_encryptor_t test_encryptor = {
    .encrypt_cid = encrypt_cid,
    .decrypt_cid = decrypt_cid,
};

/**
 * checks if the values within given CID are correct
 *
 * @return zero if okay
 */
static int verify_cid(const quicly_local_cid_t *cid, quicly_cid_encryptor_t *encryptor)
{
    quicly_cid_plaintext_t plaintext;
    if (cid->state == QUICLY_LOCAL_CID_STATE_IDLE)
        return 0;
    if (encryptor == NULL)
        return 0;

    encryptor->decrypt_cid(encryptor, &plaintext, cid->cid.cid, cid->cid.len);
    return !(cid->sequence == plaintext.path_id);
}

/**
 * checks two properties
 * 1. PENDING CIDs are in front of the array
 * 2. each CID's values are not corrupted
 *
 * @return zero if okay
 */
static int verify_array(const quicly_local_cid_set_t *set)
{
    int allow_pending = 1;
    for (size_t i = 0; i < set->_size; i++) {
        if (allow_pending) {
            if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_PENDING)
                allow_pending = 0;
        } else if (set->cids[i].state == QUICLY_LOCAL_CID_STATE_PENDING) {
            return 1;
        }
        if (verify_cid(&set->cids[i], set->_encryptor) != 0)
            return 1;
    }

    return 0;
}

static size_t count_by_state(const quicly_local_cid_set_t *set, enum en_quicly_local_cid_state_t state)
{
    size_t num = 0;
    for (size_t i = 0; i < PTLS_ELEMENTSOF(set->cids); i++) {
        if (set->cids[i].state == state)
            num++;
    }
    return num;
}

/**
 * verifies that specified sequence with the specified state appears only once in the array
 */
static int exists_once(const quicly_local_cid_set_t *set, uint64_t sequence, enum en_quicly_local_cid_state_t state)
{
    size_t occurrence = 0;
    for (size_t i = 0; i < set->_size; i++) {
        if (set->cids[i].sequence == sequence) {
            if (set->cids[i].state != state)
                return 0;
            if (occurrence > 0)
                return 0;
            occurrence++;
        }
    }

    return occurrence == 1;
}

void test_local_cid(void)
{
    PTLS_BUILD_ASSERT(QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT >= NUM_CIDS);
    quicly_local_cid_set_t set;
    static const quicly_cid_plaintext_t cid_plaintext = {0};

    /* initialize */
    quicly_local_cid_init_set(&set, &test_encryptor, &cid_plaintext);
    ok(verify_array(&set) == 0);
    ok(count_by_state(&set, QUICLY_LOCAL_CID_STATE_PENDING) == 0);
    ok(exists_once(&set, 0, QUICLY_LOCAL_CID_STATE_DELIVERED));

    ok(quicly_local_cid_set_size(&set, NUM_CIDS) != 0);
    ok(verify_array(&set) == 0);
    ok(count_by_state(&set, QUICLY_LOCAL_CID_STATE_PENDING) == NUM_CIDS - 1);
    ok(exists_once(&set, 0, QUICLY_LOCAL_CID_STATE_DELIVERED));
    ok(exists_once(&set, 1, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(exists_once(&set, 2, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(exists_once(&set, 3, QUICLY_LOCAL_CID_STATE_PENDING));

    /* send three PENDING CIDs */
    quicly_local_cid_on_sent(&set, NUM_CIDS - 1);
    ok(verify_array(&set) == 0);
    ok(exists_once(&set, 1, QUICLY_LOCAL_CID_STATE_INFLIGHT));
    ok(exists_once(&set, 2, QUICLY_LOCAL_CID_STATE_INFLIGHT));
    ok(exists_once(&set, 3, QUICLY_LOCAL_CID_STATE_INFLIGHT));

    quicly_local_cid_on_acked(&set, 1);
    quicly_local_cid_on_acked(&set, 3);
    ok(quicly_local_cid_on_lost(&set, 2) != 0); /* simulate a packet loss */
    ok(verify_array(&set) == 0);
    ok(count_by_state(&set, QUICLY_LOCAL_CID_STATE_PENDING) == 1);
    ok(exists_once(&set, 1, QUICLY_LOCAL_CID_STATE_DELIVERED));
    ok(exists_once(&set, 2, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(exists_once(&set, 3, QUICLY_LOCAL_CID_STATE_DELIVERED));

    /* retransmit sequence=2 */
    quicly_local_cid_on_sent(&set, 1);
    ok(count_by_state(&set, QUICLY_LOCAL_CID_STATE_PENDING) == 0);

    /* retire everything */
    int has_pending;
    ok(quicly_local_cid_retire(&set, 0, &has_pending) == 0);
    ok(has_pending);
    ok(quicly_local_cid_retire(&set, 1, &has_pending) == 0);
    ok(has_pending);
    ok(quicly_local_cid_retire(&set, 2, &has_pending) == 0);
    ok(has_pending);
    ok(quicly_local_cid_retire(&set, 3, &has_pending) == 0);
    ok(has_pending);
    ok(count_by_state(&set, QUICLY_LOCAL_CID_STATE_PENDING) == 4);
    /* partial send */
    quicly_local_cid_on_sent(&set, 1);
    ok(verify_array(&set) == 0);
    ok(count_by_state(&set, QUICLY_LOCAL_CID_STATE_PENDING) == 3);
    ok(exists_once(&set, 4, QUICLY_LOCAL_CID_STATE_INFLIGHT));
    ok(exists_once(&set, 5, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(exists_once(&set, 6, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(exists_once(&set, 7, QUICLY_LOCAL_CID_STATE_PENDING));

    /* retire one in the middle of PENDING CIDs */
    ok(quicly_local_cid_retire(&set, 6, &has_pending) == 0);
    ok(has_pending);
    ok(verify_array(&set) == 0);

    quicly_local_cid_on_sent(&set, 2); /* send 4,5 */
    ok(quicly_local_cid_on_lost(&set, 4) != 0);
    quicly_local_cid_on_acked(&set, 4); /* simulate late ack */
    quicly_local_cid_on_acked(&set, 5);
    quicly_local_cid_on_acked(&set, 5); /* simulate duplicate ack */
    ok(exists_once(&set, 4, QUICLY_LOCAL_CID_STATE_DELIVERED));
    ok(exists_once(&set, 5, QUICLY_LOCAL_CID_STATE_DELIVERED));
    ok(exists_once(&set, 8, QUICLY_LOCAL_CID_STATE_PENDING));

    /* at this moment sequence=0,1,2,3,6 have been retired */
    ok(quicly_local_cid_retire(&set, 4, &has_pending) == 0);
    ok(has_pending);
    ok(quicly_local_cid_retire(&set, 5, &has_pending) == 0);
    ok(has_pending);
    /* sequence=0-6 have been retired */

    /* try to exhaust CID */
    size_t num_retired = 7;
    uint64_t seq_to_retire = 7;
    while (num_retired < QUICLY_MAX_PATH_ID) {
        if (seq_to_retire == QUICLY_MAX_PATH_ID - 1) {
            /* this is the maximum CID we can generate -- after retiring it, there should be no CID to send */
            ok(quicly_local_cid_retire(&set, seq_to_retire, &has_pending) == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
        } else {
            ok(quicly_local_cid_retire(&set, seq_to_retire, &has_pending) == 0);
            ok(has_pending);
        }
        num_retired++;
        seq_to_retire++;
    }

    /* create a set with a NULL CID encryptor */
    quicly_local_cid_set_t empty_set;
    quicly_local_cid_init_set(&empty_set, NULL, NULL);
    ok(quicly_local_cid_set_size(&empty_set, NUM_CIDS) == 0);
    ok(count_by_state(&empty_set, QUICLY_LOCAL_CID_STATE_DELIVERED) == 1);
    ok(count_by_state(&empty_set, QUICLY_LOCAL_CID_STATE_IDLE) == PTLS_ELEMENTSOF(empty_set.cids) - 1);

    /* create a set with a size smaller than QUICLY_LOCAL_ACTIVE_CONNECTION_LIMIT */
    PTLS_BUILD_ASSERT(NUM_CIDS >= 2);
    quicly_cid_plaintext_t cid_plaintext2 = {0};
    quicly_local_cid_set_t small_set;
    quicly_local_cid_init_set(&small_set, &test_encryptor, &cid_plaintext2);
    ok(quicly_local_cid_set_size(&small_set, NUM_CIDS - 1) != 0);
    ok(verify_array(&small_set) == 0);
    ok(count_by_state(&small_set, QUICLY_LOCAL_CID_STATE_PENDING) == NUM_CIDS - 2);
    ok(exists_once(&small_set, 0, QUICLY_LOCAL_CID_STATE_DELIVERED));
    ok(exists_once(&small_set, 1, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(exists_once(&small_set, 2, QUICLY_LOCAL_CID_STATE_PENDING));
    ok(!exists_once(&small_set, 3, QUICLY_LOCAL_CID_STATE_PENDING)); /* seq=3 should not exist yet */
    ok(quicly_local_cid_retire(&small_set, 0, &has_pending) == 0);
    ok(has_pending);
    ok(exists_once(&small_set, 3, QUICLY_LOCAL_CID_STATE_PENDING));
}
