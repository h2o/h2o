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
#ifndef picotls_bcrypt_h
#define picotls_bcrypt_h

#ifdef __cplusplus
extern "C" {
#endif

#include "../picotls.h"

#ifdef _WINDOWS
#include <bcrypt.h>

extern ptls_cipher_algorithm_t ptls_bcrypt_aes128ecb;
extern ptls_cipher_algorithm_t ptls_bcrypt_aes256ecb;
extern ptls_cipher_algorithm_t ptls_bcrypt_aes128ctr;
extern ptls_cipher_algorithm_t ptls_bcrypt_aes256ctr;

extern ptls_aead_algorithm_t ptls_bcrypt_aes128gcm;
extern ptls_aead_algorithm_t ptls_bcrypt_aes256gcm;

extern ptls_hash_algorithm_t ptls_bcrypt_sha256;
extern ptls_hash_algorithm_t ptls_bcrypt_sha384;

extern ptls_cipher_suite_t ptls_bcrypt_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_bcrypt_aes256gcmsha384;
#endif

#ifdef __cplusplus
}
#endif

#endif /* picotls_bcrypt_h */
