/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "chacha20poly1305.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void vector(const char *keystr,
                   const char *noncestr,
                   const char *headerstr,
                   const char *plainstr,
                   const char *cipherstr,
                   const char *tagstr)
{
  /* inputs */
  uint8_t K[32], N[12], H[12], A[16];
  uint8_t C[265], P[265];

  unhex(K, sizeof K, keystr);
  unhex(N, sizeof N, noncestr);
  size_t headerlen = unhex(H, sizeof H, headerstr);
  size_t plainlen  = unhex(P, sizeof P, plainstr);
  size_t cipherlen = unhex(C, sizeof C, cipherstr);
  unhex(A, sizeof A, tagstr);

  assert(cipherlen == plainlen);

  /* working data */
  uint8_t out[265], ourtag[16];

  /* check encryption works. */
  cf_chacha20poly1305_encrypt(K, N,
                              H, headerlen,
                              P, plainlen,
                              out, ourtag);

  TEST_CHECK(memcmp(out, C, cipherlen) == 0);
  TEST_CHECK(memcmp(ourtag, A, sizeof A) == 0);

  /* proper decryption */
  TEST_CHECK(0 == cf_chacha20poly1305_decrypt(K, N,
                                              H, headerlen,
                                              C, cipherlen,
                                              A, out));
  TEST_CHECK(0 == memcmp(out, P, plainlen));

  /* failure decryption */
  C[0] ^= 0xff;

  TEST_CHECK(1 == cf_chacha20poly1305_decrypt(K, N,
                                              H, headerlen,
                                              C, cipherlen,
                                              A, out));
}

static void test_vectors(void)
{
  /* Test vector from section 2.8.2. */
  vector("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
         "070000004041424344454647",
         "50515253c0c1c2c3c4c5c6c7",
         "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
         "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
         "1ae10b594f09e26a7e902ecbd0600691");

  /* Test vector from A.5. */
  vector("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
         "000000000102030405060708",
         "f33388860000000000004e91",
         "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
         "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
         "eead9d67890cbb22392336fea1851f38");
}

TEST_LIST = {
  { "vectors", test_vectors },
  { 0 }
};

