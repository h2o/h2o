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
#ifndef quicly_local_cid_h
#define quicly_local_cid_h

#include "quicly/cid.h"

#ifdef __cplusplus
extern "C" {
#endif

enum en_quicly_local_cid_state_t {
    /**
     * this entry is free for use
     */
    QUICLY_LOCAL_CID_STATE_IDLE,
    /**
     * this entry is to be sent at the next round of send operation
     */
    QUICLY_LOCAL_CID_STATE_PENDING,
    /**
     * this entry has been sent and is waiting for ACK (or to be deemed lost)
     */
    QUICLY_LOCAL_CID_STATE_INFLIGHT,
    /**
     * this CID has been delivered to the remote peer (ACKed) and in use
     */
    QUICLY_LOCAL_CID_STATE_DELIVERED,
};

/**
 * records information for sending NEW_CONNECTION_ID frame
 */
typedef struct st_quicly_local_cid_t {
    enum en_quicly_local_cid_state_t state;
    uint64_t sequence;
    quicly_cid_t cid;
    uint8_t stateless_reset_token[QUICLY_STATELESS_RESET_TOKEN_LEN];
} quicly_local_cid_t;

/**
 * manages a list of connection IDs we issue to the remote peer
 */
typedef struct st_quicly_local_cid_set_t {
    /**
     * Identifier of the connection used by quicly. Three tuple of (node_id, thread_id, master_id) is used to identify the
     * connection. `path_id` is maintained by the "local_cid" module, and used for identifying each CID being issued.
     */
    quicly_cid_plaintext_t plaintext;
    /**
     * storage to retain local CIDs
     *
     * Pending CIDs (state == STATE_PENDING) are moved to the front of the array, in the order it was marked as pending.
     * This ensures that pending CIDs are sent in FIFO manner. Order of CIDs with other states is not defined.
     *
     * Actual size of the array is constrained by _size.
     */
    quicly_local_cid_t cids[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
    /**
     * how many entries are actually usable in `cids`?
     */
    size_t _size;
    quicly_cid_encryptor_t *_encryptor;
} quicly_local_cid_set_t;

/**
 * initialize the structure
 *
 * If `encryptor` is non-NULL, it is initialized with size==1 (sequence==0 is registered as DELIVERED).
 * Otherwise, it is initialized with size==0, and the size shall never be increased.
 */
void quicly_local_cid_init_set(quicly_local_cid_set_t *set, quicly_cid_encryptor_t *encryptor,
                               const quicly_cid_plaintext_t *new_cid);
/**
 * sets a new size of locally issued CIDs.
 *
 * The new size must be equal to or grater than the current size, and must be equal to or less than the elements of `cids`.
 *
 * Returns true if there is something to send.
 */
int quicly_local_cid_set_size(quicly_local_cid_set_t *set, size_t new_cap);
/**
 * returns true if all entries in the given set is in IDLE state
 */
static size_t quicly_local_cid_get_size(const quicly_local_cid_set_t *set);
/**
 * tells the module that the first `num_sent` pending CIDs have been sent
 */
void quicly_local_cid_on_sent(quicly_local_cid_set_t *set, size_t num_sent);
/**
 * tells the module that the given sequence number was ACKed
 */
void quicly_local_cid_on_acked(quicly_local_cid_set_t *set, uint64_t sequence);
/**
 * tells the module that the given sequence number was lost
 *
 * returns true if there is something to send
 */
int quicly_local_cid_on_lost(quicly_local_cid_set_t *set, uint64_t sequence);
/**
 * remove the specified CID from the storage.
 *
 * This makes one slot for CIDs empty. The CID generator callback is then called to fill the slot with a new CID.
 * @return 0 if the request was legal, otherwise an error code
 */
int quicly_local_cid_retire(quicly_local_cid_set_t *set, uint64_t sequence, int *has_pending);

/* inline definitions */

inline size_t quicly_local_cid_get_size(const quicly_local_cid_set_t *set)
{
    return set->_size;
}

#ifdef __cplusplus
}
#endif

#endif
