/*
 * Copyright (c) 2025 Fastly, Kazuho Oku
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
#include "../deps/picotest/picotest.h"
#include "test.h"

void test_quiclb(ptls_cipher_algorithm_t *algo)
{
    static const uint8_t key[PTLS_QUICLB_KEY_SIZE] = {0xfd, 0xf7, 0x26, 0xa9, 0x89, 0x3e, 0xc0, 0x5c,
                                                      0x06, 0x32, 0xd3, 0x95, 0x66, 0x80, 0xba, 0xf0},
                         plaintext[PTLS_QUICLB_MAX_BLOCK_SIZE] = {0x31, 0x44, 0x1a, 0x9c, 0x69, 0xc2, 0x75},
                         test_vector_encrypted[] = {0x67, 0x94, 0x7d, 0x29, 0xbe, 0x05, 0x4a};
    uint8_t tmp[PTLS_QUICLB_MAX_BLOCK_SIZE];

    /* round-trip test; also check the result when the input vector is exactly that of draft-ietf-quic-load-balancers-21 */
    for (size_t len = PTLS_QUICLB_MIN_BLOCK_SIZE; len <= PTLS_QUICLB_MAX_BLOCK_SIZE; ++len) {
        /* encrypt */
        ptls_cipher_context_t *ctx = ptls_cipher_new(algo, 1, key);
        ptls_cipher_encrypt(ctx, tmp, plaintext, len);
        ptls_cipher_free(ctx);
        if (len == sizeof(test_vector_encrypted))
            ok(memcmp(tmp, test_vector_encrypted, len) == 0);
        /* decrypt */
        ctx = ptls_cipher_new(algo, 0, key);
        ptls_cipher_encrypt(ctx, tmp, tmp, len);
        ptls_cipher_free(ctx);
        ok(memcmp(tmp, plaintext, len) == 0);
    }
}

