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
#ifndef quicly_cid_h
#define quicly_cid_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include "picotls.h"
#include "quicly/constants.h"

/**
 * Guard value. We would never send path_id of this value.
 */
#define QUICLY_MAX_PATH_ID UINT8_MAX

typedef struct st_quicly_cid_t {
    uint8_t cid[QUICLY_MAX_CID_LEN_V1];
    uint8_t len;
} quicly_cid_t;

/**
 * The structure of CID issued by quicly.
 *
 * Authentication of the CID can be done by validating if server_id and thread_id contain correct values.
 */
typedef struct st_quicly_cid_plaintext_t {
    /**
     * the internal "connection ID" unique to each connection (rather than QUIC's CID being unique to each path)
     */
    uint32_t master_id;
    /**
     * path ID of the connection; we issue up to 255 CIDs per connection (see QUICLY_MAX_PATH_ID)
     */
    uint32_t path_id : 8;
    /**
     * for intra-node routing
     */
    uint32_t thread_id : 24;
    /**
     * for inter-node routing; available only when using a 16-byte cipher to encrypt CIDs, otherwise set to zero. See
     * quicly_context_t::is_clustered.
     */
    uint64_t node_id;
} quicly_cid_plaintext_t;

/**
 * CID encryption
 */
typedef struct st_quicly_cid_encryptor_t {
    /**
     * encrypts CID and optionally generates a stateless reset token
     */
    void (*encrypt_cid)(struct st_quicly_cid_encryptor_t *self, quicly_cid_t *encrypted, void *stateless_reset_token,
                        const quicly_cid_plaintext_t *plaintext);
    /**
     * decrypts CID. plaintext->thread_id should contain a randomly distributed number when validation fails, so that the value can
     * be used for distributing load among the threads within the process.
     * @param len length of encrypted bytes if known, or 0 if unknown (short header packet)
     * @return length of the CID, or SIZE_MAX if decryption failed
     */
    size_t (*decrypt_cid)(struct st_quicly_cid_encryptor_t *self, quicly_cid_plaintext_t *plaintext, const void *encrypted,
                          size_t len);
    /**
     * generates a stateless reset token (returns if generated)
     */
    int (*generate_stateless_reset_token)(struct st_quicly_cid_encryptor_t *self, void *token, const void *cid);
} quicly_cid_encryptor_t;

static void quicly_set_cid(quicly_cid_t *dest, ptls_iovec_t src);
static int quicly_cid_is_equal(const quicly_cid_t *cid, ptls_iovec_t vec);

/* inline functions */

inline int quicly_cid_is_equal(const quicly_cid_t *cid, ptls_iovec_t vec)
{
    return cid->len == vec.len && memcmp(cid->cid, vec.base, vec.len) == 0;
}

inline void quicly_set_cid(quicly_cid_t *dest, ptls_iovec_t src)
{
    memcpy(dest->cid, src.base, src.len);
    dest->len = src.len;
}

#ifdef __cplusplus
}
#endif

#endif
