/*
 * Copyright (c) 2017-2019 Fastly, Kazuho Oku
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
#ifndef quicly_defaults_h
#define quicly_defaults_h

#ifdef __cplusplus
extern "C" {
#endif

#include "quicly.h"

extern const quicly_context_t quicly_spec_context;
extern const quicly_context_t quicly_performant_context;

/**
 *
 */
extern quicly_packet_allocator_t quicly_default_packet_allocator;
/**
 * Instantiates a CID cipher.
 * The CID cipher MUST be a block cipher. It MAY be a 64-bit block cipher (e.g., blowfish) when `quicly_cid_plaintext_t::node_id` is
 * not utilized by the application. Otherwise, it MUST be a 128-bit block cipher (e.g., AES).
 * The reset token cipher MUST be a 128-bit block cipher.
 */
quicly_cid_encryptor_t *quicly_new_default_cid_encryptor(ptls_cipher_algorithm_t *cid_cipher,
                                                         ptls_cipher_algorithm_t *reset_token_cipher, ptls_hash_algorithm_t *hash,
                                                         ptls_iovec_t key);
/**
 *
 */
void quicly_free_default_cid_encryptor(quicly_cid_encryptor_t *self);
/**
 *
 */
extern quicly_stream_scheduler_t quicly_default_stream_scheduler;
/**
 *
 */
extern quicly_now_t quicly_default_now;
/**
 *
 */
extern quicly_crypto_engine_t quicly_default_crypto_engine;

#ifdef __cplusplus
}
#endif

#endif
