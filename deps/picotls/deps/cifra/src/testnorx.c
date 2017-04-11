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

#include "norx.h"
#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_vector(void)
{
  uint8_t K[16], N[8], A[128], M[128], Z[128], C[128], T[16];

  /* This is from the v2.0 paper, section A.2. */

  unhex(K, sizeof K, "000102030405060708090a0b0c0d0e0f");
  unhex(N, sizeof N, "f0e0d0c0b0a09080");

  for (unsigned i = 0; i < 128; i++)
  {
    A[i] = M[i] = Z[i] = i;
  }

  cf_norx32_encrypt(K, N,
                    A, sizeof A,
                    M, sizeof M,
                    Z, sizeof Z,
                    C, T);

  uint8_t expect_C[128], expect_T[16];

  unhex(expect_C, sizeof expect_C, "f4afc8e66d2d80de0a7f719c899624c9ad896ec7c61739d5376d0648c7bcb204e57db05c6f83b3ff4315e8a4ef2f2c855f21ea4c51ac6de575773ba548f36e636a13b979d953bb91298ea4a6e2aa27402991e0da541997825407b2f12441de3ae6c5dbfe41b12f1480d234832765111e4c09deef9fe3971618d2217c4b77921e");
  unhex(expect_T, sizeof expect_T, "7810131eea2eab1e5da05d23d4e3cb99");

  TEST_CHECK(memcmp(C, expect_C, sizeof C) == 0);
  TEST_CHECK(memcmp(T, expect_T, sizeof T) == 0);

  uint8_t M2[128];
  TEST_CHECK(0 ==
             cf_norx32_decrypt(K, N,
                               A, sizeof A,
                               C, sizeof C,
                               Z, sizeof Z,
                               T,
                               M2));

  TEST_CHECK(memcmp(M, M2, sizeof M) == 0);
  T[0] ^= 0xff;

  TEST_CHECK(cf_norx32_decrypt(K, N,
                               A, sizeof A,
                               C, sizeof C,
                               Z, sizeof Z,
                               T,
                               M2));
}

#include "testnorx.katdata.inc"

static void test_kat(void)
{
  uint8_t K[16], N[16], H[256], W[256];
  const uint8_t *kats = kat_data;

#define FILL(arr, c) \
  do { \
    for (size_t i = 0; i < sizeof arr; i++) \
      arr[i] = (i * c + 123) & 0xff; \
  } while (0)
  FILL(N, 181);
  FILL(K, 191);
  FILL(H, 193);
  FILL(W, 197);
#undef FILL

  for (size_t i = 0; i < sizeof W; i++)
  {
    uint8_t C[256];
    uint8_t A[16];

    cf_norx32_encrypt(K, N,
                      H, i,
                      W, i,
                      NULL, 0,
                      C, A);

    TEST_CHECK(memcmp(kats, C, i) == 0);
    kats += i;
    TEST_CHECK(memcmp(kats, A, sizeof A) == 0);
    kats += sizeof A;

    uint8_t M[256] = { 0 };
    TEST_CHECK(0 == cf_norx32_decrypt(K, N,
                                      H, i,
                                      C, i,
                                      NULL, 0,
                                      A, M));

    TEST_CHECK(0 == memcmp(M, W, i));
  }
}

TEST_LIST = {
  { "vector", test_vector },
  { "kat", test_kat },
  { 0 }
};

