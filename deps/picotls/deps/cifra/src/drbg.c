/*
 * cifra - embedded cryptography library
 * Written in 2016 by Joseph Birr-Pixton <jpixton@gmail.com>
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

#include "drbg.h"
#include "handy.h"
#include "bitops.h"
#include "sha2.h"
#include "tassert.h"

#include <string.h>

#define MAX_DRBG_GENERATE 0x10000ul

static void hash_df(const cf_chash *H,
                    const void *in1, size_t nin1,
                    const void *in2, size_t nin2,
                    const void *in3, size_t nin3,
                    const void *in4, size_t nin4,
                    uint8_t *out, size_t nout)
{
  uint8_t counter = 1;
  uint32_t bits_to_return = nout * 8;
  uint8_t cbuf[4];
  uint8_t block[CF_MAXHASH];

  write32_be(bits_to_return, cbuf);

  while (nout)
  {
    /* Make a block.  This is the hash of:
     *   counter || bits_to_return || in1 || in2 || in3 | in4
     */
    cf_chash_ctx ctx;
    H->init(&ctx);
    H->update(&ctx, &counter, sizeof counter);
    H->update(&ctx, cbuf, sizeof cbuf);
    H->update(&ctx, in1, nin1);
    H->update(&ctx, in2, nin2);
    H->update(&ctx, in3, nin3);
    H->update(&ctx, in4, nin4);
    H->digest(&ctx, block);

    size_t take = MIN(H->hashsz, nout);
    memcpy(out, block, take);
    out += take;
    nout -= take;

    counter += 1;
  }
}

void cf_hash_drbg_sha256_init(cf_hash_drbg_sha256 *ctx,
                              const void *entropy, size_t nentropy,
                              const void *nonce, size_t nnonce,
                              const void *persn, size_t npersn)
{
  mem_clean(ctx, sizeof *ctx);

  /* 1. seed_material = entropy_input || nonce || personalization_string
   * 2. seed = Hash_df(seed_material, seedlen)
   * 3. V = seed */
  hash_df(&cf_sha256,
          entropy, nentropy,
          nonce, nnonce,
          persn, npersn,
          NULL, 0,
          ctx->V, sizeof ctx->V);

  /* 4. C = Hash_df(0x00 || V, seedlen) */
  uint8_t zero = 0;
  hash_df(&cf_sha256,
          &zero, sizeof zero,
          ctx->V, sizeof ctx->V,
          NULL, 0,
          NULL, 0,
          ctx->C, sizeof ctx->C);

  /* 5. reseed_counter = 1 */
  ctx->reseed_counter = 1;
}

/* Add out += in, mod 2^nout.
 * Runs in time dependent on nout and nin, but not the contents of out or in.
 */
static void add(uint8_t *out, size_t nout, const uint8_t *in, size_t nin)
{
  assert(nout >= nin);

  uint16_t carry = 0;
  int oi, ii;

  for (oi = nout - 1, ii = nin - 1;
       oi >= 0;
       ii--, oi--)
  {
    carry += out[oi];
    if (ii >= 0)
      carry += in[ii];
    out[oi] = carry & 0xff;
    carry >>= 8;
  }
}

static void hash_process_addnl(const cf_chash *H,
                               const void *input, size_t ninput,
                               uint8_t *V, size_t nV)
{
  if (!ninput)
    return;

  /* 2.1. w = Hash(0x02 || V || additional_input) */
  uint8_t two = 2;
  uint8_t w[CF_MAXHASH];
  cf_chash_ctx ctx;
  H->init(&ctx);
  H->update(&ctx, &two, sizeof two);
  H->update(&ctx, V, nV);
  H->update(&ctx, input, ninput);
  H->digest(&ctx, w);

  /* 2.2. V = (V + w) mod 2 ^ seedlen */
  add(V, nV, w, H->hashsz);
}

static void hash_generate(const cf_chash *H,
                          uint8_t *data, size_t ndata, /* initialised with V */
                          void *out, size_t nout)
{
  cf_chash_ctx ctx;
  uint8_t w[CF_MAXHASH];
  uint8_t *bout = out;
  uint8_t one = 1;

  while (nout)
  {
    /* 4.1. w = Hash(data) */
    H->init(&ctx);
    H->update(&ctx, data, ndata);
    H->digest(&ctx, w);

    /* 4.2. W = W || w */
    size_t take = MIN(H->hashsz, nout);
    memcpy(bout, w, take);
    bout += take;
    nout -= take;

    /* 4.3. data = (data + 1) mod 2 ^ seedlen */
    add(data, ndata, &one, sizeof one);
  }
}

static void hash_step(const cf_chash *H,
                      uint8_t *V, size_t nV,
                      const uint8_t *C, size_t nC,
                      uint32_t *reseed_counter)
{
  /* 4. h = Hash(0x03 || V) */
  uint8_t h[CF_MAXHASH];
  uint8_t three = 3;
  cf_chash_ctx ctx;

  H->init(&ctx);
  H->update(&ctx, &three, sizeof three);
  H->update(&ctx, V, nV);
  H->digest(&ctx, h);

  /* 5. V = (V + h + C + reseed_counter) mod 2 ^ seedlen */
  uint8_t reseed_counter_buf[4];
  write32_be(*reseed_counter, reseed_counter_buf);

  add(V, nV, h, H->hashsz);
  add(V, nV, C, nC);
  add(V, nV, reseed_counter_buf, sizeof reseed_counter_buf);

  /* 6. reseed_counter = reseed_counter + 1 */
  *reseed_counter = *reseed_counter + 1;
}

/* This is Hash_DRBG_Generate_algorithm.
 * nout is a maximum of MAX_DRBG_GENERATE */
static void hash_gen_request(cf_hash_drbg_sha256 *ctx,
                             const void *addnl, size_t naddnl,
                             void *out, size_t nout)
{
  uint8_t data[440/8]; /* a temporary copy of V, which gets incremented by generate */

  assert(!cf_hash_drbg_sha256_needs_reseed(ctx));

  hash_process_addnl(&cf_sha256, addnl, naddnl, ctx->V, sizeof ctx->V);
  assert(sizeof data == sizeof ctx->V);
  memcpy(data, ctx->V, sizeof ctx->V);
  hash_generate(&cf_sha256, data, sizeof data, out, nout);
  hash_step(&cf_sha256, ctx->V, sizeof ctx->V, ctx->C, sizeof ctx->C, &ctx->reseed_counter);
}

void cf_hash_drbg_sha256_gen_additional(cf_hash_drbg_sha256 *ctx,
                                        const void *addnl, size_t naddnl,
                                        void *out, size_t nout)
{
  uint8_t *bout = out;

  /* Generate output in requests of MAX_DRBG_GENERATE in size. */
  while (nout != 0)
  {
    size_t take = MIN(MAX_DRBG_GENERATE, nout);
    hash_gen_request(ctx, addnl, naddnl, bout, take);
    bout += take;
    nout -= take;

    /* Add additional data only once. */
    addnl = NULL;
    naddnl = 0;
  }
}

void cf_hash_drbg_sha256_gen(cf_hash_drbg_sha256 *ctx,
                             void *out, size_t nout)
{
  cf_hash_drbg_sha256_gen_additional(ctx,
                                     NULL, 0,
                                     out, nout);
}

void cf_hash_drbg_sha256_reseed(cf_hash_drbg_sha256 *ctx,
                                const void *entropy, size_t nentropy,
                                const void *addnl, size_t naddnl)
{
  /* 1. seed_material = 0x01 || V || entropy_input || additional_input
   * 2. seed = Hash_df(seed_material, seedlen)
   * 3. V = seed */
  uint8_t one = 1;
  /* stash V in C, because it cannot alias output */
  memcpy(ctx->C, ctx->V, sizeof ctx->C);
  hash_df(&cf_sha256,
          &one, sizeof one,
          ctx->C, sizeof ctx->C,
          entropy, nentropy,
          addnl, naddnl,
          ctx->V, sizeof ctx->V);

  /* 4. C = Hash_df(0x00 || V, seedlen) */
  uint8_t zero = 0;
  hash_df(&cf_sha256,
          &zero, sizeof zero,
          ctx->V, sizeof ctx->V,
          NULL, 0,
          NULL, 0,
          ctx->C, sizeof ctx->C);

  /* 5. reseed_counter = 1 */
  ctx->reseed_counter = 1;
}

uint32_t cf_hash_drbg_sha256_needs_reseed(const cf_hash_drbg_sha256 *ctx)
{
  /* we need reseeding after 2 ^ 32 - 1 requests. */
  return ctx->reseed_counter == 0;
}

/* --- HMAC_DRBG --- */

/* provided_data is in1 || in2 || in3.
 * K is already scheduled in ctx->hmac. */
static void hmac_drbg_update(cf_hmac_drbg *ctx,
                             const void *in1, size_t nin1,
                             const void *in2, size_t nin2,
                             const void *in3, size_t nin3)
{
  cf_hmac_ctx local;
  const cf_chash *H = ctx->hmac.hash;
  uint8_t new_key[CF_MAXHASH];
  uint8_t zero = 0;

  /* 1. K = HMAC(K, V || 0x00 || provided_data) */
  local = ctx->hmac;
  cf_hmac_update(&local, ctx->V, H->hashsz);
  cf_hmac_update(&local, &zero, sizeof zero);
  cf_hmac_update(&local, in1, nin1);
  cf_hmac_update(&local, in2, nin2);
  cf_hmac_update(&local, in3, nin3);
  cf_hmac_finish(&local, new_key);
  cf_hmac_init(&ctx->hmac, H, new_key, H->hashsz);
  mem_clean(new_key, sizeof new_key);

  /* 2. V = HMAC(K, V) */
  local = ctx->hmac;
  cf_hmac_update(&local, ctx->V, H->hashsz);
  cf_hmac_finish(&local, ctx->V);

  /* 3. if (provided_data = null) then return K and V */
  if (nin1 == 0 && nin2 == 0 && nin3 == 0)
    return;

  /* 4. K = HMAC(K, V || 0x01 || provided_data) */
  uint8_t one = 1;
  local = ctx->hmac;
  cf_hmac_update(&local, ctx->V, H->hashsz);
  cf_hmac_update(&local, &one, sizeof one);
  cf_hmac_update(&local, in1, nin1);
  cf_hmac_update(&local, in2, nin2);
  cf_hmac_update(&local, in3, nin3);
  cf_hmac_finish(&local, new_key);
  cf_hmac_init(&ctx->hmac, H, new_key, H->hashsz);
  mem_clean(new_key, sizeof new_key);

  /* 5. V = HMAC(K, V) */
  local = ctx->hmac;
  cf_hmac_update(&local, ctx->V, H->hashsz);
  cf_hmac_finish(&local, ctx->V);
}

void cf_hmac_drbg_init(cf_hmac_drbg *ctx,
                       const cf_chash *hash,
                       const void *entropy, size_t nentropy,
                       const void *nonce, size_t nnonce,
                       const void *persn, size_t npersn)
{
  mem_clean(ctx, sizeof *ctx);

  assert(hash->hashsz <= CF_MAXHASH);

  /* 2. Key = 0x00 00 ... 00
   * 3. V = 0x01 01 ... 01 */
  uint8_t initial_key[CF_MAXHASH];
  memset(initial_key, 0x00, hash->hashsz);
  memset(ctx->V, 0x01, hash->hashsz);
  cf_hmac_init(&ctx->hmac, hash, initial_key, hash->hashsz);

  /* 1. seed_material = entropy_input || nonce || personalization_string
   * 4. (Key, V) = HMAC_DRBG_Update(seed_material, Key, V) */
  hmac_drbg_update(ctx, entropy, nentropy, nonce, nnonce, persn, npersn);

  /* 5. reseed_counter = 1 */
  ctx->reseed_counter = 1;
}

uint32_t cf_hmac_drbg_needs_reseed(const cf_hmac_drbg *ctx)
{
  return ctx->reseed_counter == 0;
}

static void hmac_drbg_generate(cf_hmac_drbg *ctx,
                               const void *addnl, size_t naddnl,
                               void *out, size_t nout)
{
  /* 1. If reseed_counter > reseed_interval, then return an indication
   * that a reseed is required */
  assert(!cf_hmac_drbg_needs_reseed(ctx));

  /* 2. If additional_input != null, then
   *    (Key, V) = HMAC_DRBG_Update(additional_input, Key, V)
   */
  if (naddnl)
    hmac_drbg_update(ctx, addnl, naddnl, NULL, 0, NULL, 0);

  /* 3. temp = Null
   * 4. While (len(temp) < requested_number_of_bits) do:
   *   4.1. V = HMAC(Key, V)
   *   4.2. temp = temp || V
   * 5. returned_bits = leftmost(temp, requested_number_of_bits)
   *
   * We write the contents of temp directly into the caller's
   * out buffer.
   */
  uint8_t *bout = out;
  cf_hmac_ctx local;

  while (nout)
  {
    local = ctx->hmac;
    cf_hmac_update(&local, ctx->V, ctx->hmac.hash->hashsz);
    cf_hmac_finish(&local, ctx->V);

    size_t take = MIN(ctx->hmac.hash->hashsz, nout);
    memcpy(bout, ctx->V, take);
    bout += take;
    nout -= take;
  }

  /* 6. (Key, V) = HMAC_DRBG_Update(additional_input, Key, V) */
  hmac_drbg_update(ctx, addnl, naddnl, NULL, 0, NULL, 0);

  /* 7. reseed_counter = reseed_counter + 1 */
  ctx->reseed_counter++;
}

void cf_hmac_drbg_gen_additional(cf_hmac_drbg *ctx,
                                 const void *addnl, size_t naddnl,
                                 void *out, size_t nout)
{
  uint8_t *bout = out;

  while (nout != 0)
  {
    size_t take = MIN(MAX_DRBG_GENERATE, nout);
    hmac_drbg_generate(ctx, addnl, naddnl, bout, take);
    bout += take;
    nout -= take;

    /* Add additional data only once. */
    addnl = NULL;
    naddnl = 0;
  }
}

void cf_hmac_drbg_gen(cf_hmac_drbg *ctx, void *out, size_t nout)
{
  cf_hmac_drbg_gen_additional(ctx,
                              NULL, 0,
                              out, nout);
}

void cf_hmac_drbg_reseed(cf_hmac_drbg *ctx,
                         const void *entropy, size_t nentropy,
                         const void *addnl, size_t naddnl)
{
  /* 1. seed_material = entropy_input || additional_input
   * 2. (Key, V) = HMAC_DRBG_Update(seed_material, Key, V) */
  hmac_drbg_update(ctx, entropy, nentropy, addnl, naddnl, NULL, 0);
  
  /* 3. reseed_counter = 1 */
  ctx->reseed_counter = 1;
}
