/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include <stddef.h>
#include "picotls.h"
#include "picotls/minicrypto.h"

ptls_cipher_suite_t *ptls_minicrypto_cipher_suites[] = {// ciphers used with sha512 and sha384 (must be first)
                                                        &ptls_minicrypto_aes256gcmsha384,

                                                        // ciphers used with sha256
                                                        &ptls_minicrypto_aes128gcmsha256,
                                                        &ptls_minicrypto_chacha20poly1305sha256,
                                                        NULL};

ptls_cipher_suite_t *ptls_minicrypto_cipher_suites_all[] = {// ciphers used with sha512 and sha384 (must be first)
#ifdef PTLS_HAVE_AEGIS
                                                           &ptls_minicrypto_aegis256sha512,
#endif
                                                           &ptls_minicrypto_aes256gcmsha384,

                                                           // ciphers used with sha256
#ifdef PTLS_HAVE_AEGIS
                                                           &ptls_minicrypto_aegis128lsha256,
#endif
                                                           &ptls_minicrypto_aes128gcmsha256,
                                                           &ptls_minicrypto_chacha20poly1305sha256,
                                                           NULL};
