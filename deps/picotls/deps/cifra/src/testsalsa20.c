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

#include "salsa20.h"

#include "testutil.h"
#include "handy.h"
#include "cutest.h"

static void test_salsa20_core(void)
{
  uint8_t k0[16], k1[16], nonce[16], sigma[16], out[64], expect[64];

  /* From section 8. */
  memset(k0, 0, sizeof k0);
  memset(k1, 0, sizeof k1);
  memset(nonce, 0, sizeof nonce);
  memset(sigma, 0, sizeof sigma);

  cf_salsa20_core(k0, k1, nonce, sigma, out);
  
  unhex(expect, 64, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  /*
  d39f0d73
  4c3752b70375de25bfbbea8831edb330
  016ab2db
  afc7a6305610b3cf1ff0203f0f535da1
  74933071
  ee37cc244fc9eb4f03519c2fcb1af4f3
  58766836
  */
  unhex(k0, 16, "4c3752b70375de25bfbbea8831edb330");
  unhex(k1, 16, "ee37cc244fc9eb4f03519c2fcb1af4f3");
  unhex(nonce, 16, "afc7a6305610b3cf1ff0203f0f535da1");
  unhex(sigma, 16, "d39f0d73016ab2db7493307158766836");

  cf_salsa20_core(k0, k1, nonce, sigma, out);

  unhex(expect, 64, "6d2ab2a89cf0f8eea8c4becb1a6eaa9a1d1d961a961eebf9bea3fb30459033397628989db4391b5e6b2aec231b6f7272dbece8876f9b6e1218e85f9eb31330ca");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  /*
  58766836
  4fc9eb4f03519c2fcb1af4f3bfbbea88
  d39f0d73
  4c3752b70375de255610b3cf31edb330
  016ab2db
  afc7a630ee37cc241ff0203f0f535da1
  74933071
  */
  unhex(k0, 16, "4fc9eb4f03519c2fcb1af4f3bfbbea88");
  unhex(k1, 16, "afc7a630ee37cc241ff0203f0f535da1");
  unhex(nonce, 16, "4c3752b70375de255610b3cf31edb330");
  unhex(sigma, 16, "58766836d39f0d73016ab2db74933071");
  
  cf_salsa20_core(k0, k1, nonce, sigma, out);
  
  unhex(expect, 64, "b31330cadbece8876f9b6e1218e85f9e1a6eaa9a6d2ab2a89cf0f8eea8c4becb459033391d1d961a961eebf9bea3fb301b6f72727628989db4391b5e6b2aec23");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  /* From section 9. */
  for (size_t i = 0; i < 16; i++)
  {
    k0[i] = 1 + i;
    k1[i] = 201 + i;
    nonce[i] = 101 + i;
  }

  cf_salsa20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);
  
  unhex(expect, 64, "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a");
  TEST_CHECK(memcmp(expect, out, 64) == 0);
  
  cf_salsa20_core(k0, k0, nonce, (const uint8_t *) "expand 16-byte k", out);
  
  unhex(expect, 64, "27ad2ef81ec852113043feef25120df7f1c83d900a3732b9062ff6fd8f56bbe186556ef6a1a32bebe75eab3391d6701d0ee80510978cb78dab097ab568b6b1c1");
  TEST_CHECK(memcmp(expect, out, 64) == 0);
}

static void test_salsa20(void)
{
  cf_salsa20_ctx ctx;
  uint8_t key[32], nonce[8], cipher[64], expect[64];

  unhex(key, 32, "0102030405060708090a0b0c0d0e0f10c9cacbcccdcecfd0d1d2d3d4d5d6d7d8");
  memset(nonce, 0, 8);

  cf_salsa20_init(&ctx, key, sizeof key, nonce);
  unhex(ctx.nonce, 16, "65666768696a6b6c6d6e6f7071727374");
  memset(cipher, 0, 64);
  cf_salsa20_cipher(&ctx, cipher, cipher, 64);

  unhex(expect, 64, "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a");
  TEST_CHECK(memcmp(expect, cipher, 64) == 0);

  cf_salsa20_init(&ctx, key, 16, nonce);
  unhex(ctx.nonce, 16, "65666768696a6b6c6d6e6f7071727374");
  memset(cipher, 0, 64);
  cf_salsa20_cipher(&ctx, cipher, cipher, 64);

  unhex(expect, 64, "27ad2ef81ec852113043feef25120df7f1c83d900a3732b9062ff6fd8f56bbe186556ef6a1a32bebe75eab3391d6701d0ee80510978cb78dab097ab568b6b1c1");
  TEST_CHECK(memcmp(expect, cipher, 64) == 0);
}

static void test_chacha20_core(void)
{
  uint8_t k0[16], k1[16], nonce[16], out[64], expect[64];

  /* From draft-agl-tls-chacha20poly1305-04 section 7. */

  memset(k0, 0, sizeof k0);
  memset(k1, 0, sizeof k1);
  memset(nonce, 0, sizeof nonce);

  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);

  unhex(expect, 60, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669");
  TEST_CHECK(memcmp(expect, out, 60) == 0);

  k1[15] = 0x01;
  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);

  unhex(expect, 60, "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275");
  TEST_CHECK(memcmp(expect, out, 60) == 0);

  memset(k1, 0, sizeof k1);
  nonce[15] = 0x01;

  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);

  unhex(expect, 60, "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3");
  TEST_CHECK(memcmp(expect, out, 60) == 0);

  memset(nonce, 0, sizeof nonce);
  nonce[8] = 0x01;
  
  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);

  unhex(expect, 64, "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  unhex(k0, 16, "000102030405060708090a0b0c0d0e0f");
  unhex(k1, 16, "101112131415161718191a1b1c1d1e1f");
  unhex(nonce, 16, "00000000000000000001020304050607");

  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);

  unhex(expect, 64, "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a");
  TEST_CHECK(memcmp(expect, out, 64) == 0);
  
  nonce[0]++;
  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);
  
  unhex(expect, 64, "38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c7");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  nonce[0]++;
  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);
  
  unhex(expect, 64, "9db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d7");
  TEST_CHECK(memcmp(expect, out, 64) == 0);

  nonce[0]++;
  cf_chacha20_core(k0, k1, nonce, (const uint8_t *) "expand 32-byte k", out);

  unhex(expect, 64, "0eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9");
  TEST_CHECK(memcmp(expect, out, 64) == 0);
}

static void test_chacha20(void)
{
  uint8_t key[32], nonce[8], block[256], expect[256];

  unhex(key, 32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  unhex(nonce, 8, "0001020304050607");
  unhex(expect, 256, "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9");
  memset(block, 0, 256);

  cf_chacha20_ctx ctx;
  cf_chacha20_init(&ctx, key, sizeof key, nonce);
  cf_chacha20_cipher(&ctx, block, block, sizeof block);

  TEST_CHECK(memcmp(expect, block, sizeof expect) == 0);

  /* Check 128-bit mode works. */
  cf_chacha20_init(&ctx, key, 16, nonce);
  cf_chacha20_cipher(&ctx, block, block, sizeof block);
}

TEST_LIST = {
  { "salsa20-core", test_salsa20_core },
  { "chacha20-core", test_chacha20_core },
  { "salsa20", test_salsa20 },
  { "chacha20", test_chacha20 },
  { 0 }
};

