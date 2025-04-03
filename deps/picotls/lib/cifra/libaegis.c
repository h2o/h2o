/*
 * Copyright (c) 2023 Frank Denis
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

#include "picotls/minicrypto.h"
#include "../libaegis.h"

ptls_aead_algorithm_t ptls_minicrypto_aegis128l = {"AEGIS-128L",
                                                   PTLS_AEGIS128L_CONFIDENTIALITY_LIMIT,
                                                   PTLS_AEGIS128L_INTEGRITY_LIMIT,
                                                   NULL,
                                                   NULL,
                                                   PTLS_AEGIS128L_KEY_SIZE,
                                                   PTLS_AEGIS128L_IV_SIZE,
                                                   PTLS_AEGIS128L_TAG_SIZE,
                                                   {0, 0},
                                                   0,
                                                   0,
                                                   sizeof(struct aegis128l_context_t),
                                                   aegis128l_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_aegis128lsha256 = {.id = PTLS_CIPHER_SUITE_AEGIS128L_SHA256,
                                                       .name = PTLS_CIPHER_SUITE_NAME_AEGIS128L_SHA256,
                                                       .aead = &ptls_minicrypto_aegis128l,
                                                       .hash = &ptls_minicrypto_sha256};

ptls_aead_algorithm_t ptls_minicrypto_aegis256 = {"AEGIS-256",
                                                  PTLS_AEGIS256_CONFIDENTIALITY_LIMIT,
                                                  PTLS_AEGIS256_INTEGRITY_LIMIT,
                                                  NULL,
                                                  NULL,
                                                  PTLS_AEGIS256_KEY_SIZE,
                                                  PTLS_AEGIS256_IV_SIZE,
                                                  PTLS_AEGIS256_TAG_SIZE,
                                                  {0, 0},
                                                  0,
                                                  0,
                                                  sizeof(struct aegis256_context_t),
                                                  aegis256_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_aegis256sha512 = {.id = PTLS_CIPHER_SUITE_AEGIS256_SHA512,
                                                      .name = PTLS_CIPHER_SUITE_NAME_AEGIS256_SHA512,
                                                      .aead = &ptls_minicrypto_aegis256,
                                                      .hash = &ptls_minicrypto_sha512};
