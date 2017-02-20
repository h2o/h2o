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

#ifndef TESTSHA_H
#define TESTSHA_H

#include "hmac.h"

/* Common functions for testing hash functions.
 * You shouldn't use this file. */

static void vector(const cf_chash *hash,
                   const void *vmsg, size_t nmsg,
                   const char *expect, size_t nexpect)
{
  uint8_t digest[CF_MAXHASH];
  const uint8_t *msg = vmsg;
  size_t orig_nmsg = nmsg;

  cf_chash_ctx ctx;
  hash->init(&ctx);

  /* Input in carefully chosen chunk sizes to exercise blockwise code. */
  if (nmsg)
  {
    hash->update(&ctx, msg, 1);
    nmsg--;
    msg++;
  }

  hash->update(&ctx, msg, nmsg);
  hash->digest(&ctx, digest);
  TEST_CHECK(nexpect == hash->hashsz);
  TEST_CHECK(memcmp(digest, expect, nexpect) == 0);

  /* Now try with other arrangements. */
  msg = vmsg;
  nmsg = orig_nmsg;

  hash->init(&ctx);
  if (nmsg >= hash->blocksz)
  {
    hash->update(&ctx, msg, hash->blocksz - 1);
    nmsg -= hash->blocksz - 1;
    msg += hash->blocksz - 1;
  }

  hash->update(&ctx, msg, nmsg);
  hash->digest(&ctx, digest);
  TEST_CHECK(memcmp(digest, expect, nexpect) == 0);
}

/* These are shared between RFC2202 and RFC4231. */
static inline void hmac_test(const cf_chash *hash,
                             const void *hi_there,
                             const void *jefe,
                             const void *aa_dd,
                             const void *counter_key)
{
  uint8_t sig[CF_MAXHASH];
  uint8_t key[25], message[50];

  /* Key: 0x0b * 20
   * Message: "Hi There"
   */
  memset(key, 0x0b, 20);
  memcpy(message, "Hi There", 8);
  cf_hmac(key, 20, message, 8, sig, hash);

  TEST_CHECK(memcmp(sig, hi_there, hash->hashsz) == 0);

  /* Key: "Jefe"
   * Message: "what do ya want for nothing?"
   */
  memcpy(key, "Jefe", 4);
  memcpy(message, "what do ya want for nothing?", 28);
  cf_hmac(key, 4, message, 28, sig, hash);
  TEST_CHECK(memcmp(sig, jefe, hash->hashsz) == 0);

  /* Key: 0xaa * 20
   * Message: 0xdd * 50
   */
  memset(key, 0xaa, 20);
  memset(message, 0xdd, 50);
  cf_hmac(key, 20, message, 50, sig, hash);
  TEST_CHECK(memcmp(sig, aa_dd, hash->hashsz) == 0);

  /* Key: 0x01..0x19
   * Message: 0xcd * 50
   */
  for (uint8_t i = 1; i < 26; i++)
    key[i - 1] = i;
  memset(message, 0xcd, 50);
  cf_hmac(key, 25, message, 50, sig, hash);
  TEST_CHECK(memcmp(sig, counter_key, hash->hashsz) == 0);
}

/* These are specific to RFC4231. */
static inline void hmac_test_sha2(const cf_chash *hash,
                                  const char *long_key,
                                  const char *long_message)
{
  uint8_t sig[CF_MAXHASH];
  uint8_t key[131], message[152];

  /* Key: 0xaa * 131
   * Message: "Test Using Larger Than Block-Size Key - Hash Key First"
   */
  memset(key, 0xaa, 131);
  memcpy(message, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
  cf_hmac(key, 131, message, 54, sig, hash);
  TEST_CHECK(memcmp(sig, long_key, hash->hashsz) == 0);

  /* Key: 0xaa * 131
   * Message: "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
   */
  memset(key, 0xaa, 131);
  memcpy(message, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", 152);
  cf_hmac(key, 131, message, 152, sig, hash);
  TEST_CHECK(memcmp(sig, long_message, hash->hashsz) == 0);
}

/* This is as hmac_test_sha2, except the sizes are specific to
 * a 512-bit block.  This is from RFC2202. */
static inline void hmac_test_sha1(const cf_chash *hash,
                                  const char *long_key,
                                  const char *long_message)
{
  uint8_t sig[CF_MAXHASH];
  uint8_t key[80], message[73];

  /* Key: 0xaa * 80
   * Message: "Test Using Larger Than Block-Size Key - Hash Key First"
   */
  memset(key, 0xaa, 80);
  memcpy(message, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
  cf_hmac(key, 80, message, 54, sig, hash);
  TEST_CHECK(memcmp(sig, long_key, hash->hashsz) == 0);

  /* Key: 0xaa * 80
   * Message: "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
   */
  memset(key, 0xaa, 80);
  memcpy(message, "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data", 73);
  cf_hmac(key, 80, message, 73, sig, hash);
  TEST_CHECK(memcmp(sig, long_message, hash->hashsz) == 0);
}

typedef void (*final_fn)(void *ctx, uint8_t *out);

/* Check incremental interface works, and final function likewise. */
static void vector_abc_final(const cf_chash *hash, const void *vfinal_fn,
                             const void *expect, size_t nexpect)
{
  uint8_t digest[CF_MAXHASH];

  final_fn final = vfinal_fn;
  cf_chash_ctx ctx;
  hash->init(&ctx);
  hash->update(&ctx, "a", 1);
  hash->digest(&ctx, digest);
  hash->update(&ctx, "b", 1);
  hash->digest(&ctx, digest);
  hash->update(&ctx, "c", 1);
  final(&ctx, digest);

  TEST_CHECK(hash->hashsz == nexpect);
  TEST_CHECK(memcmp(expect, digest, nexpect) == 0);
}

/* Check length-checking vectors work (generated by programs in ../extra_vecs) */
static inline void vector_length(const cf_chash *h,
                                 size_t max,
                                 const void *expect, size_t nexpect)
{
  cf_chash_ctx outer, inner;
  uint8_t digest[CF_MAXHASH];

  h->init(&outer);

  for (size_t n = 0; n < max; n++)
  {
    h->init(&inner);
    
    for (size_t i = 0; i < n; i++)
    {
      uint8_t byte = (uint8_t) n & 0xff;
      h->update(&inner, &byte, 1);
    }

    h->digest(&inner, digest);

    h->update(&outer, digest, h->hashsz);
  }

  h->digest(&outer, digest);

  TEST_CHECK(h->hashsz == nexpect);
  TEST_CHECK(memcmp(expect, digest, nexpect) == 0);
}

#endif
