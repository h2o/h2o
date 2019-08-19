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
#ifndef test_h
#define test_h

#include "picotls.h"
#include "picotls/ffx.h"

/* raw private key and certificate using secp256v1 */
#define SECP256R1_PRIVATE_KEY                                                                                                      \
    "\xc1\x74\xb4\xf9\x5e\xfe\x7a\x01\x0e\xbe\x4a\xe8\x33\xb2\x36\x13\xfc\x65\xe9\x65\x91\xa8\x39\x9e\x9a\x80\xfb\xab\xd1\xff\xba" \
    "\x3a"
#define SECP256R1_CERTIFICATE                                                                                                      \
    "\x30\x82\x02\x60\x30\x82\x01\x48\xa0\x03\x02\x01\x02\x02\x01\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00" \
    "\x30\x1a\x31\x18\x30\x16\x06\x03\x55\x04\x03\x13\x0f\x70\x69\x63\x6f\x74\x6c\x73\x20\x74\x65\x73\x74\x20\x63\x61\x30\x1e\x17" \
    "\x0d\x31\x38\x30\x32\x32\x33\x30\x35\x33\x31\x30\x34\x5a\x17\x0d\x32\x38\x30\x32\x32\x31\x30\x35\x33\x31\x30\x34\x5a\x30\x1b" \
    "\x31\x19\x30\x17\x06\x03\x55\x04\x03\x13\x10\x74\x65\x73\x74\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30\x59\x30\x13" \
    "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\xda\xc8\xa5\x40\x54\xba\x33\xda" \
    "\x18\xa9\x41\x7f\x49\x53\xdf\x60\xe6\xa6\x3d\xb6\x8e\x53\x3a\x9f\xdd\x19\x14\x5e\xab\x03\xcf\xbc\xfb\x36\x98\x16\x24\x8f\x07" \
    "\x29\x6d\x15\xd8\x4f\x30\xe8\x09\x64\xfb\x14\xfc\x86\x7c\xd4\x06\xc2\xfd\x9d\xe8\x99\x3f\x48\x8c\x2b\xa3\x7b\x30\x79\x30\x09" \
    "\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x2c\x06\x09\x60\x86\x48\x01\x86\xf8\x42\x01\x0d\x04\x1f\x16\x1d\x4f\x70\x65\x6e\x53" \
    "\x53\x4c\x20\x47\x65\x6e\x65\x72\x61\x74\x65\x64\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x30\x1d\x06\x03\x55\x1d\x0e" \
    "\x04\x16\x04\x14\xee\x30\x86\x16\xa1\xd2\x69\xad\x64\xe4\xd7\x77\x6b\xb2\xfd\x5c\x4f\x01\xa2\xb5\x30\x1f\x06\x03\x55\x1d\x23" \
    "\x04\x18\x30\x16\x80\x14\xbf\x79\xca\x97\xb2\x60\x78\x20\x96\xaa\x46\x57\x9c\xdf\xa7\xb2\x23\xf5\x25\x63\x30\x0d\x06\x09\x2a" \
    "\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x8f\xac\x9c\x01\x6d\x81\xaa\x8c\xae\x5d\xb5\x16\x74\xea\xe8\xeb" \
    "\x26\x5b\xb1\x66\xd5\x6b\xd4\x4d\x79\x0d\x6d\x87\xa9\xb6\xbf\x74\x2d\xc1\xb2\x2e\x52\xb6\x4b\xca\x0d\x01\x45\x38\x58\x1a\xd2" \
    "\x6a\x6d\x20\x98\x5a\x51\xb0\x6f\x2c\x3f\x0f\x12\x88\xed\x7c\x09\xa5\x74\x00\x21\x3d\x4b\xd2\x2d\x54\xaa\x53\x8b\x64\xf9\x1e" \
    "\xea\xa5\x8a\xe7\x61\x5e\x56\x92\x52\x36\x3e\xa0\x68\x59\x9c\x7d\xb3\xe8\x5c\x4b\x77\x6e\xde\x28\xed\x18\x91\xa9\x9c\x39\xd2" \
    "\x96\xcc\x98\x05\x8c\x74\xdc\x1e\x12\x5b\x38\xbd\x56\xcb\xa3\xe8\xe1\x2a\x5a\x2b\xd2\x32\x45\xc1\x10\x85\x20\x6c\x6b\x34\xea" \
    "\x66\x91\x0e\x2e\xb8\x64\x87\x9f\x07\xbc\x23\x4f\x23\xad\xbe\x89\xdf\x0a\x98\x47\xe9\x63\x02\xd3\x41\xf4\x2d\xa4\xce\xdd\xe3" \
    "\xd8\x41\x08\xfe\xdf\x47\xc0\xe7\x63\x8e\x1f\xf0\x4b\xc5\xae\xab\xc0\xba\x38\x3e\xe3\x90\x9c\x08\xbd\x75\x1c\xb9\xb8\x54\x43" \
    "\x1d\x99\x42\xe0\xa2\xb7\x75\xbb\x14\x03\x79\x9a\xf6\x07\xd8\xa5\xab\x2b\x3a\x70\x8b\x77\x85\x70\x8a\x98\x38\x9b\x35\x09\xf6" \
    "\x62\x6b\x29\x4a\xa7\xa7\xf9\x3b\xde\xd8\xc8\x90\x57\xf2\x76\x2a\x23\x0b\x01\x68\xc6\x9a\xf2"

/* secp256r1 key that lasts until 2028 */
#define ESNIKEYS                                                                                                                   \
    "\xff\x02\xcf\x27\xde\x17\x00\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x00\x45"                                         \
    "\x00\x17\x00\x41\x04\x3e\xee\xf7\x10\xe3\x75\x07\xa8\xfb\x3e\xfc\x62\x50\x24\x95\xa0"                                         \
    "\x61\x6e\xff\x6b\x63\x0f\xa3\xfd\xcc\x33\x36\xd0\xb1\x2d\x55\xba\xb0\x06\xbd\xb4\x29"                                         \
    "\x82\xc6\xd9\xee\x66\x84\xa9\x63\x94\x44\xbe\x04\xe7\xee\xcf\xab\xc2\xc9\xdd\x40\xe6"                                         \
    "\xc8\x89\x88\xed\x94\x86\x00\x02\x13\x01\x01\x04\x00\x00\x00\x00\x5d\x1c\xc0\x63\x00"                                         \
    "\x00\x4e\x94\xee\x6b\xc0\x62\x00\x00"
#define ESNI_SECP256R1KEY                                                                                                          \
    "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE "                         \
    "KEY-----\nMHcCAQEEIGrRVTfTXuOVewLt/g+Ugvg9XW/g4lGXrkZ8fdYaYuJCoAoGCCqGSM49\nAwEHoUQDQgAEPu73EON1B6j7PvxiUCSVoGFu/"            \
    "2tjD6P9zDM20LEtVbqwBr20KYLG\n2e5mhKljlES+BOfuz6vCyd1A5siJiO2Uhg==\n-----END EC PRIVATE KEY-----\n"

extern ptls_context_t *ctx, *ctx_peer;
extern ptls_verify_certificate_t *verify_certificate;

struct st_ptls_ffx_test_variants_t {
    ptls_cipher_algorithm_t *algo;
    int bit_length;
};
extern struct st_ptls_ffx_test_variants_t ffx_variants[7];

#define DEFINE_FFX_AES128_ALGORITHMS(backend)                                                                                      \
    PTLS_FFX_CIPHER_ALGO(ptls_##backend##_aes128ctr, 31, 6, 16);                                                                   \
    PTLS_FFX_CIPHER_ALGO(ptls_##backend##_aes128ctr, 53, 4, 16);                                                                   \
    PTLS_FFX_CIPHER_ALGO(ptls_##backend##_aes128ctr, 125, 8, 16)
#define DEFINE_FFX_CHACHA20_ALGORITHMS(backend)                                                                                    \
    PTLS_FFX_CIPHER_ALGO(ptls_##backend##_chacha20, 32, 6, 32);                                                                    \
    PTLS_FFX_CIPHER_ALGO(ptls_##backend##_chacha20, 57, 4, 32);                                                                    \
    PTLS_FFX_CIPHER_ALGO(ptls_##backend##_chacha20, 256, 8, 32)

#define ADD_FFX_ALGORITHM(a, bl)                                                                                                   \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; ffx_variants[i].algo != NULL; ++i)                                                                             \
            ;                                                                                                                      \
        ffx_variants[i] = (struct st_ptls_ffx_test_variants_t){&(a), (bl)};                                                        \
    } while (0)

#define ADD_FFX_AES128_ALGORITHMS(backend)                                                                                         \
    ADD_FFX_ALGORITHM(ptls_ffx_ptls_##backend##_aes128ctr_b125_r8, 125);                                                           \
    ADD_FFX_ALGORITHM(ptls_ffx_ptls_##backend##_aes128ctr_b31_r6, 31);                                                             \
    ADD_FFX_ALGORITHM(ptls_ffx_ptls_##backend##_aes128ctr_b53_r4, 53)

#define ADD_FFX_CHACHA20_ALGORITHMS(backend)                                                                                       \
    ADD_FFX_ALGORITHM(ptls_ffx_ptls_##backend##_chacha20_b256_r8, 256);                                                            \
    ADD_FFX_ALGORITHM(ptls_ffx_ptls_##backend##_chacha20_b32_r6, 32);                                                              \
    ADD_FFX_ALGORITHM(ptls_ffx_ptls_##backend##_chacha20_b57_r4, 57)

void test_key_exchange(ptls_key_exchange_algorithm_t *client, ptls_key_exchange_algorithm_t *server);
void test_picotls(void);
void test_picotls_esni(ptls_key_exchange_context_t **keys);

#endif
