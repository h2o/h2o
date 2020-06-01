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
#include "quicly/local_cid.h"

static int has_pending(quicly_local_cid_set_t *set)
{
    return set->cids[0].state == QUICLY_LOCAL_CID_STATE_PENDING;
}

/**
 * generates a new CID and increments path_id. returns true if successfully generated.
 */
static int generate_cid(quicly_local_cid_set_t *set, size_t idx)
{
    if (set->_encryptor == NULL || set->plaintext.path_id >= QUICLY_MAX_PATH_ID)
        return 0;

    set->_encryptor->encrypt_cid(set->_encryptor, &set->cids[idx].cid, set->cids[idx].stateless_reset_token, &set->plaintext);
    set->cids[idx].sequence = set->plaintext.path_id++;

    return 1;
}

static void swap_cids(quicly_local_cid_t *a, quicly_local_cid_t *b)
{
    quicly_local_cid_t tmp = *b;
    *b = *a;
    *a = tmp;
}

/**
 * change the state of a CID to PENDING, and move it forward so CIDs in pending state form FIFO
 */
static void do_mark_pending(quicly_local_cid_set_t *set, size_t idx)
{
    set->cids[idx].state = QUICLY_LOCAL_CID_STATE_PENDING;
    for (size_t j = 0; j < idx; j++) {
        if (set->cids[j].state != QUICLY_LOCAL_CID_STATE_PENDING) {
            swap_cids(&set->cids[idx], &set->cids[j]);
            break;
        }
    }
}

static void do_mark_delivered(quicly_local_cid_set_t *set, size_t idx)
{
    if (set->cids[idx].state == QUICLY_LOCAL_CID_STATE_PENDING) {
        /* if transitioning from PENDING, move it backward so the remaining PENDING CIDs come first */
        while (idx + 1 < set->_size && set->cids[idx + 1].state == QUICLY_LOCAL_CID_STATE_PENDING) {
            swap_cids(&set->cids[idx], &set->cids[idx + 1]);
            idx++;
        }
    }
    set->cids[idx].state = QUICLY_LOCAL_CID_STATE_DELIVERED;
}

void quicly_local_cid_init_set(quicly_local_cid_set_t *set, quicly_cid_encryptor_t *encryptor,
                               const quicly_cid_plaintext_t *new_cid)
{
    *set = (quicly_local_cid_set_t){
        ._encryptor = encryptor,
        ._size = 1,
    };

    /* initialize cids[0] */
    if (encryptor != NULL) {
        assert(new_cid->path_id == 0);
        set->plaintext = *new_cid;
        generate_cid(set, 0);
    } else {
        /* we have a zero-length CID at cids[0] */
    }
    set->cids[0].state =
        QUICLY_LOCAL_CID_STATE_DELIVERED; /* no need to use NCID frames, the use delivers this CID to the remote peer */

    for (size_t i = 1; i < PTLS_ELEMENTSOF(set->cids); i++)
        set->cids[i].sequence = UINT64_MAX;
}

int quicly_local_cid_set_size(quicly_local_cid_set_t *set, size_t size)
{
    int is_pending = 0;

    assert(size <= PTLS_ELEMENTSOF(set->cids));
    assert(set->_size <= size);

    for (size_t i = set->_size; i < size; i++)
        set->cids[i].state = QUICLY_LOCAL_CID_STATE_IDLE;

    set->_size = size;

    /* First we prepare N CIDs (to be precise here we prepare N-1, as we already had one upon initialization).
     * Later, every time one of the CIDs is retired, we immediately prepare one additional CID
     * to always fill the CID list. */
    for (size_t i = 0; i < size; i++) {
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_IDLE)
            continue;

        if (!generate_cid(set, i))
            break;
        do_mark_pending(set, i);
        is_pending = 1;
    }

    return is_pending;
}

void quicly_local_cid_on_sent(quicly_local_cid_set_t *set, size_t num_sent)
{
    assert(num_sent <= set->_size);

    /* first, mark the first `num_sent` CIDs as INFLIGHT */
    for (size_t i = 0; i < num_sent; i++) {
        assert(set->cids[i].state == QUICLY_LOCAL_CID_STATE_PENDING);
        set->cids[i].state = QUICLY_LOCAL_CID_STATE_INFLIGHT;
    }

    /* then move the remaining PENDING CIDs (if any) to the front of the array */
    for (size_t i = num_sent; i < set->_size; i++) {
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_PENDING)
            break;
        swap_cids(&set->cids[i], &set->cids[i - num_sent]);
    }
}

static size_t find_index(const quicly_local_cid_set_t *set, uint64_t sequence)
{
    for (size_t i = 0; i < set->_size; i++) {
        if (set->cids[i].sequence == sequence)
            return i;
    }

    return SIZE_MAX;
}

void quicly_local_cid_on_acked(quicly_local_cid_set_t *set, uint64_t sequence)
{
    size_t i = find_index(set, sequence);
    if (i == SIZE_MAX)
        return;

    do_mark_delivered(set, i);
}

int quicly_local_cid_on_lost(quicly_local_cid_set_t *set, uint64_t sequence)
{
    size_t i = find_index(set, sequence);
    if (i == SIZE_MAX)
        return has_pending(set);

    /* if it's already delivered, ignore the packet loss event (no need for retransmission) */
    if (set->cids[i].state == QUICLY_LOCAL_CID_STATE_DELIVERED)
        return has_pending(set);

    do_mark_pending(set, i);

    return 1;
}

int quicly_local_cid_retire(quicly_local_cid_set_t *set, uint64_t sequence, int *_has_pending)
{
    /* find the CID to be retired, also check if there is at least one CID that has been issued */
    size_t retired_at = set->_size;
    int becomes_empty = 1;
    for (size_t i = 0; i < set->_size; i++) {
        if (set->cids[i].state == QUICLY_LOCAL_CID_STATE_IDLE)
            continue;
        if (set->cids[i].sequence == sequence) {
            assert(retired_at == set->_size);
            retired_at = i;
        } else {
            becomes_empty = 0;
        }
    }

    /* nothing to do if given CID has been retired already */
    if (retired_at == set->_size) {
        *_has_pending = has_pending(set);
        return 0;
    }

    /* it is a protocol violation for the remote peer to retire the only CID that is available to it */
    if (becomes_empty)
        return QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION;

    /* retire given CID */
    set->cids[retired_at].state = QUICLY_LOCAL_CID_STATE_IDLE;
    set->cids[retired_at].sequence = UINT64_MAX;

    /* move following PENDING CIDs to front */
    for (size_t i = retired_at + 1; i < set->_size; i++) {
        if (set->cids[i].state != QUICLY_LOCAL_CID_STATE_PENDING)
            break;
        swap_cids(&set->cids[i], &set->cids[retired_at]);
        retired_at = i;
    }

    /* generate one new CID */
    if (generate_cid(set, retired_at)) {
        do_mark_pending(set, retired_at);
        *_has_pending = 1;
    } else {
        *_has_pending = has_pending(set);
    }

    return 0;
}
