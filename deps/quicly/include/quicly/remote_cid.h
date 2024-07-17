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
#ifndef quicly_received_cid_h
#define quicly_received_cid_h

#include "quicly/cid.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * state of `quicly_remote_cid_t`
 */
typedef enum en_quicly_remote_cid_state_t {
    /**
     * cid and stateless reset token have not been received for the sequence number
     */
    QUICLY_REMOTE_CID_UNAVAILABLE,
    /**
     * cid is in use
     */
    QUICLY_REMOTE_CID_IN_USE,
    /**
     * cid has been receive but has not been used yet
     */
    QUICLY_REMOTE_CID_AVAILABLE
} quicly_remote_cid_state_t;

/**
 * records a CID given by the remote peer
 */
typedef struct st_quicly_remote_cid_t {
    /**
     * state
     */
    quicly_remote_cid_state_t state;
    /**
     * sequence number of the CID; if `state` is UNAVAILABLE, this is a reserved slot meaning that we are expecting to receive a
     * NEW_CONNECTION_ID frame with this sequence number. This helps determine if a received frame is carrying a CID that is already
     * retired.
     */
    uint64_t sequence;
    /**
     * CID; available unless `state` is UNAVAILABLE
     */
    struct st_quicly_cid_t cid;
    /**
     * stateless reset token; only usable if `is_active` is true
     */
    uint8_t stateless_reset_token[QUICLY_STATELESS_RESET_TOKEN_LEN];
} quicly_remote_cid_t;

/**
 * structure to hold active connection IDs received from the remote peer
 */
typedef struct st_quicly_remote_cid_set_t {
    /**
     * We retain QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT active connection IDs. `cids[0]` used to retain the current DCID, but it is
     * no longer the case. DCID of the non-probing path should now be obtained via `get_dcid(conn->paths[0])` where `paths[0]` is
     * the non-probing path.
     */
    quicly_remote_cid_t cids[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT];
    /**
     * we expect to receive CIDs with sequence number smaller than or equal to this number
     */
    uint64_t _largest_sequence_expected;
} quicly_remote_cid_set_t;

/**
 * Initializes the set. If `initial_cid` is NULL, the first value is automatically generated so that the endpoint running as client
 * can use it. Stateless reset token of the initial CID is set to a random value so that it would not match against any value being
 * received.
 */
void quicly_remote_cid_init_set(quicly_remote_cid_set_t *set, ptls_iovec_t *initial_cid, void (*random_bytes)(void *, size_t));
/**
 * registers received connection ID
 * returns 0 if successful (registered or ignored because of duplication/stale information), transport error code otherwise
 */
int quicly_remote_cid_register(quicly_remote_cid_set_t *set, uint64_t sequence, const uint8_t *cid, size_t cid_len,
                               const uint8_t srt[QUICLY_STATELESS_RESET_TOKEN_LEN], uint64_t retire_prior_to,
                               uint64_t unregistered_seqs[QUICLY_LOCAL_ACTIVE_CONNECTION_ID_LIMIT], size_t *num_unregistered_seqs);
/**
 * unregisters specified CID from the store
 */
void quicly_remote_cid_unregister(quicly_remote_cid_set_t *set, uint64_t sequence);

#ifdef __cplusplus
}
#endif

#endif
