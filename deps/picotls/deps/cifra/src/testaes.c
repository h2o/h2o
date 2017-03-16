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

#include "aes.h"
#include "modes.h"
#include "bitops.h"
#include "gf128.h"

#include "handy.h"
#include "cutest.h"
#include "testutil.h"

static void test_memclean(void)
{
  uint8_t buf[32], buf2[32];
  memset(buf, 0xff, sizeof buf);
  mem_clean(buf + 1, sizeof buf - 2);
  TEST_CHECK(buf[0] == 0xff);
  TEST_CHECK(buf[1] == 0x00);
  TEST_CHECK(buf[16] == 0x00);
  TEST_CHECK(buf[30] == 0x00);
  TEST_CHECK(buf[31] == 0xff);

  memcpy(buf2, buf, sizeof buf);
  TEST_CHECK(buf2[0] == 0xff);
  TEST_CHECK(buf2[1] == 0x00);
  TEST_CHECK(buf2[16] == 0x00);
  TEST_CHECK(buf2[30] == 0x00);
  TEST_CHECK(buf2[31] == 0xff);

  memset(buf2, 0xee, sizeof buf);
  TEST_CHECK(buf2[0] == 0xee);
  TEST_CHECK(buf2[1] == 0xee);
  TEST_CHECK(buf2[2] == 0xee);
  TEST_CHECK(buf2[3] == 0xee);
  TEST_CHECK(buf2[30] == 0xee);
  TEST_CHECK(buf2[31] == 0xee);
}

static void test_bitops_select(void)
{
  uint8_t tab8[8];
  uint32_t tab32[32];
  
  for (size_t i = 0; i < 8; i++)
    tab8[i] = 1 << i;
  for (size_t i = 0; i < 32; i++)
    tab32[i] = 1 << i;

  for (size_t i = 0; i < 8; i++)
  {
    TEST_CHECK(select_u8(i, tab8, 8) == tab8[i]);
  }

  for (size_t i = 0; i < 32; i++)
  {
    TEST_CHECK(select_u32(i, tab32, 32) == tab32[i]);
  }
}

static void test_bitops_incr(void)
{
  uint8_t buf[4];

#define CHECK_BE(start, add, end) \
  { \
    write32_be((start), buf); \
    for (size_t i = 0; i < (add); i++) \
      incr_be(buf, sizeof buf); \
    TEST_CHECK(read32_be(buf) == (end)); \
  }

#define CHECK_LE(start, add, end) \
  { \
    write32_le((start), buf); \
    for (size_t i = 0; i < (add); i++) \
      incr_le(buf, sizeof buf); \
    TEST_CHECK(read32_le(buf) == (end)); \
  }

  CHECK_BE(0, 1, 1);
  CHECK_BE(0, 256, 256);
  CHECK_BE(256, 256, 512);
  CHECK_BE(0xffffffff, 1, 0);

  CHECK_LE(0, 1, 1);
  CHECK_LE(0, 256, 256);
  CHECK_LE(0x7fffffff, 1, 0x80000000);
  CHECK_LE(0xffffffff, 1, 0);

#undef CHECK_BE
#undef CHECK_LE
}

static void test_bitops_unaligned(void)
{
  uint8_t in[4], out[4];

#define CHECK(outw, len, offs) \
  { \
    memset(out, 0, sizeof out); \
    copy_bytes_unaligned(out, in, len, offs); \
    TEST_CHECK(read32_be(out) == (outw)); \
  }

  write32_be(0x11223344, in);

  CHECK(0x11223344, 4, 0);
  CHECK(0x22446600, 3, 1);
  CHECK(0x4488cd00, 3, 2);
  CHECK(0x89119a00, 3, 3);
  CHECK(0x12233400, 3, 4);
  CHECK(0x24466800, 3, 5);
  CHECK(0x488cd100, 3, 6);
  CHECK(0x9119a200, 3, 7);
  CHECK(0x22334400, 3, 8);
  CHECK(0x44660000, 2, 9);
  CHECK(0x33440000, 2, 16);

#undef CHECK
}

static void test_expand(const uint8_t *key, size_t nkey,
                        const uint32_t *answer, size_t roundkeys)
{
  cf_aes_context ctx;

  cf_aes_init(&ctx, key, nkey);

  for (size_t i = 0; i < roundkeys; i++)
  {
    TEST_CHECK(ctx.ks[i] == answer[i]);
  }
}

static void test_expand_128(void)
{
  /* This is FIPS-197 appendix A.1. */
  const uint8_t key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };

  const uint32_t answer[] = {
    0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1,
    0x23a33939, 0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
    0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f,
    0xb671253b, 0xdb0bad00, 0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
    0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, 0x4e54f70e, 0x5f5fc9f3,
    0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
    0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
    0xe13f0cc8, 0xb6630ca6
  };
  
  test_expand(key, sizeof key, answer, ARRAYCOUNT(answer));
}

static void test_expand_192(void)
{
  /* This is FIPS-197 appendix A.2. */
  const uint8_t key[] = {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 
    0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
  };

  const uint32_t answer[] = {
    0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
    0xfe0c91f7, 0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
    0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386,
    0x485af057, 0x21efb14f, 0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
    0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, 0xc0a69407, 0xd19da4e1,
    0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
    0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df,
    0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
    0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202
  };

  test_expand(key, sizeof key, answer, ARRAYCOUNT(answer));
}

static void test_expand_256(void)
{
  /* And this is A.3. */
  const uint8_t key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
    0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
  };

  const uint32_t answer[] = {
    0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7,
    0x2d9810a3, 0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
    0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917,
    0xfee94248, 0xde8ebe96, 0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
    0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464, 0x98c5bfc9, 0xbebd198e,
    0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
    0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
    0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
    0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34,
    0x9adf6ace, 0xbd10190d, 0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e
  };

  test_expand(key, sizeof key, answer, ARRAYCOUNT(answer));
}

static void vector(const char *input, const char *output,
                   const char *key)
{
  uint8_t keybuf[32], inbuf[16], outbuf[16], tmp[16];
  size_t nkey = sizeof keybuf;
  cf_aes_context ctx;

  nkey = unhex(keybuf, 32, key);
  unhex(inbuf, 16, input);
  unhex(outbuf, 16, output);

  cf_aes_init(&ctx, keybuf, nkey);
  cf_aes_encrypt(&ctx, inbuf, tmp);
  TEST_CHECK(memcmp(tmp, outbuf, 16) == 0);
  
  cf_aes_decrypt(&ctx, outbuf, tmp);
  TEST_CHECK(memcmp(tmp, inbuf, 16) == 0);
  cf_aes_finish(&ctx);
}

static void test_vectors(void)
{
  vector("00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a",
         "000102030405060708090a0b0c0d0e0f");
  vector("00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191",
         "000102030405060708090a0b0c0d0e0f1011121314151617");
  vector("00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

TEST_LIST = {
  { "handy-memclean", test_memclean },
  { "bitops-select", test_bitops_select },
  { "bitops-incr", test_bitops_incr },
  { "bitops-unaligned", test_bitops_unaligned },
  { "key-expansion-128", test_expand_128 },
  { "key-expansion-192", test_expand_192 },
  { "key-expansion-256", test_expand_256 },
  { "vectors", test_vectors },
  { 0 }
};

