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

#include <string.h>

#include "sha3.h"
#include "blockwise.h"
#include "handy.h"
#include "bitops.h"
#include "tassert.h"

/* The round constants, pre-interleaved.  See bitinter.py */
static const cf_sha3_bi round_constants[24] = {
  { 0x00000001, 0x00000000 }, { 0x00000000, 0x00000089 },
  { 0x00000000, 0x8000008b }, { 0x00000000, 0x80008080 },
  { 0x00000001, 0x0000008b }, { 0x00000001, 0x00008000 },
  { 0x00000001, 0x80008088 }, { 0x00000001, 0x80000082 },
  { 0x00000000, 0x0000000b }, { 0x00000000, 0x0000000a },
  { 0x00000001, 0x00008082 }, { 0x00000000, 0x00008003 },
  { 0x00000001, 0x0000808b }, { 0x00000001, 0x8000000b },
  { 0x00000001, 0x8000008a }, { 0x00000001, 0x80000081 },
  { 0x00000000, 0x80000081 }, { 0x00000000, 0x80000008 },
  { 0x00000000, 0x00000083 }, { 0x00000000, 0x80008003 },
  { 0x00000001, 0x80008088 }, { 0x00000000, 0x80000088 },
  { 0x00000001, 0x00008000 }, { 0x00000000, 0x80008082 }
};

static const uint8_t rotation_constants[5][5] = {
  {  0,  1, 62, 28, 27, },
  { 36, 44,  6, 55, 20, },
  {  3, 10, 43, 25, 39, },
  { 41, 45, 15, 21,  8, },
  { 18,  2, 61, 56, 14, }
};

/* --- Bit interleaving and uninterleaving --- */
/* See bitinter.py for models of these bit twiddles.  The originals
 * come from "Hacker's Delight" by Henry Warren, where they are named
 * shuffle2 and unshuffle.
 * See:
 *   http://www.hackersdelight.org/hdcodetxt/shuffle.c.txt
 *
 * The overriding aim is to change bit ordering:
 *   AaBbCcDd -> ABCDabcd
 * and back.  Once they're in the shuffled form, we can extract
 * odd/even bits by taking the half words from each pair.
 */

static inline uint32_t shuffle_out(uint32_t x)
{
  uint32_t t;
  t = (x ^ (x >> 1)) & 0x22222222;  x = x ^ t ^ (t << 1);
  t = (x ^ (x >> 2)) & 0x0c0c0c0c;  x = x ^ t ^ (t << 2);
  t = (x ^ (x >> 4)) & 0x00f000f0;  x = x ^ t ^ (t << 4);
  t = (x ^ (x >> 8)) & 0x0000ff00;  x = x ^ t ^ (t << 8);
  return x;
}

/* Convert ABCDabcd -> AaBbCcDd. */
static inline uint32_t shuffle_in(uint32_t x)
{
  uint32_t t;
  t = (x ^ (x >> 8)) & 0x0000ff00;  x = x ^ t ^ (t << 8);
  t = (x ^ (x >> 4)) & 0x00f000f0;  x = x ^ t ^ (t << 4);
  t = (x ^ (x >> 2)) & 0x0c0c0c0c;  x = x ^ t ^ (t << 2);
  t = (x ^ (x >> 1)) & 0x22222222;  x = x ^ t ^ (t << 1);
  return x;
}

static inline void read64_bi(cf_sha3_bi *out, const uint8_t data[8])
{
  uint32_t lo = read32_le(data + 0),
           hi = read32_le(data + 4);

  lo = shuffle_out(lo);
  hi = shuffle_out(hi);

  out->odd = (lo & 0x0000ffff) | (hi << 16);
  out->evn = (lo >> 16) | (hi & 0xffff0000);
}

static inline void write64_bi(const cf_sha3_bi *bi, uint8_t data[8])
{
  uint32_t lo = (bi->odd & 0x0000ffff) | (bi->evn << 16),
           hi = (bi->odd >> 16) | (bi->evn & 0xffff0000);

  lo = shuffle_in(lo);
  hi = shuffle_in(hi);

  write32_le(lo, data + 0);
  write32_le(hi, data + 4);
}

static inline void rotl_bi_1(cf_sha3_bi *out, const cf_sha3_bi *in)
{
  /* in bit-interleaved representation, a rotation of 1
   * is a swap plus a single rotation of the odd word. */
  out->odd = rotl32(in->evn, 1);
  out->evn = in->odd;
}

static inline void rotl_bi_n(cf_sha3_bi *out, const cf_sha3_bi *in, uint8_t rot)
{
  uint8_t half = rot >> 1;

  /* nb. rot is a constant, so this isn't a branch leak. */
  if (rot & 1)
  {
    out->odd = rotl32(in->evn, half + 1);
    out->evn = rotl32(in->odd, half);
  } else {
    out->evn = rotl32(in->evn, half);
    out->odd = rotl32(in->odd, half);
  }
}

/* --- */

static void sha3_init(cf_sha3_context *ctx, uint16_t rate_bits, uint16_t capacity_bits)
{
  mem_clean(ctx, sizeof *ctx);
  ctx->rate = rate_bits / 8;
  ctx->capacity = capacity_bits / 8;
}

static void absorb(cf_sha3_context *ctx, const uint8_t *data, uint16_t sz)
{
  uint16_t lanes = sz / 8;

  for (uint16_t x = 0, y = 0, i = 0; i < lanes; i++)
  {
    cf_sha3_bi bi;
    read64_bi(&bi, data);
    ctx->A[x][y].odd ^= bi.odd;
    ctx->A[x][y].evn ^= bi.evn;
    data += 8;

    x++;
    if (x == 5)
    {
      y++;
      x = 0;
    }
  }
}

/* Integers [-1,20] mod 5. To avoid a divmod.  Indices
 * are constants; not data-dependant. */
static const uint8_t mod5_table[] = {
  4,
  0,
  1, 2, 3, 4, 0, 1, 2, 3, 4, 0,
  1, 2, 3, 4, 0, 1, 2, 3, 4, 0
};

#define MOD5(x) (mod5_table[(x) + 1])

static void theta(cf_sha3_context *ctx)
{
  cf_sha3_bi C[5], D[5];

  for (int x = 0; x < 5; x++)
  {
    C[x].odd = ctx->A[x][0].odd ^ ctx->A[x][1].odd ^ ctx->A[x][2].odd ^ ctx->A[x][3].odd ^ ctx->A[x][4].odd;
    C[x].evn = ctx->A[x][0].evn ^ ctx->A[x][1].evn ^ ctx->A[x][2].evn ^ ctx->A[x][3].evn ^ ctx->A[x][4].evn;
  }

  for (int x = 0; x < 5; x++)
  {
    cf_sha3_bi r;
    rotl_bi_1(&r, &C[MOD5(x + 1)]);
    D[x].odd = C[MOD5(x - 1)].odd ^ r.odd;
    D[x].evn = C[MOD5(x - 1)].evn ^ r.evn;

    for (int y = 0; y < 5; y++)
    {
      ctx->A[x][y].odd ^= D[x].odd;
      ctx->A[x][y].evn ^= D[x].evn;
    }
  }
}

static void rho_pi_chi(cf_sha3_context *ctx)
{
  cf_sha3_bi B[5][5] = { { { 0 } } };

  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++)
      rotl_bi_n(&B[y][MOD5(2 * x + 3 * y)], &ctx->A[x][y], rotation_constants[y][x]);

  for (int x = 0; x < 5; x++)
  {
    unsigned x1 = MOD5(x + 1);
    unsigned x2 = MOD5(x + 2);

    for (int y = 0; y < 5; y++)
    {
      ctx->A[x][y].odd = B[x][y].odd ^ ((~ B[x1][y].odd) & B[x2][y].odd);
      ctx->A[x][y].evn = B[x][y].evn ^ ((~ B[x1][y].evn) & B[x2][y].evn);
    }
  }
}

static void permute(cf_sha3_context *ctx)
{
  for (int r = 0; r < 24; r++)
  {
    theta(ctx);
    rho_pi_chi(ctx);

    /* iota */
    ctx->A[0][0].odd ^= round_constants[r].odd;
    ctx->A[0][0].evn ^= round_constants[r].evn;
  }
}

static void extract(cf_sha3_context *ctx, uint8_t *out, size_t nbytes)
{
  uint16_t lanes = (nbytes + 7) / 8;

  for (uint16_t x = 0, y = 0, i = 0; i < lanes; i++)
  {
    if (nbytes >= 8)
    {
      write64_bi(&ctx->A[x][y], out);
      out += 8;
      nbytes -= 8;
    } else {
      uint8_t buf[8];
      write64_bi(&ctx->A[x][y], buf);
      memcpy(out, buf, nbytes);
      out += nbytes;
      nbytes = 0;
    }
    
    x++;
    if (x == 5)
    {
      y++;
      x = 0;
    }
  }
}

static void squeeze(cf_sha3_context *ctx, uint8_t *out, size_t nbytes)
{
  while (nbytes)
  {
    size_t take = MIN(nbytes, ctx->rate);
    extract(ctx, out, take);
    out += take;
    nbytes -= take;

    assert(nbytes == 0);
#if 0
    /* Note: if we ever have |H| >= rate, we need to permute
     * after each rate-length block.
     *
     * This cannot currently happen. */
    if (nbytes)
      permute(ctx);
#endif
  }
}

static void sha3_block(void *vctx, const uint8_t *data)
{
  cf_sha3_context *ctx = vctx;

  absorb(ctx, data, ctx->rate);
  permute(ctx);
}

static void sha3_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, ctx->rate,
                          data, nbytes,
                          sha3_block, ctx);
}

/* Padding and domain separation constants.
 *
 * FIPS 202 specifies that 0b01 is appended to hash function
 * input, and 0b1111 is appended to SHAKE input.
 *
 * This is done in internal (little endian) bit ordering, and
 * we convolve it with the leftmost (first) padding bit, so:
 *
 * Hash: 0b110
 * SHAKE: 0b11111
 */
  
#define DOMAIN_HASH_PAD  0x06
#define DOMAIN_SHAKE_PAD 0x1f

static void pad(cf_sha3_context *ctx, uint8_t domain, size_t npad)
{
  assert(npad >= 1);

  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, ctx->rate,
                       domain, 0x00, 0x80,
                       npad,
                       sha3_block, ctx);
}

static void pad_and_squeeze(cf_sha3_context *ctx, uint8_t *out, size_t nout)
{
  pad(ctx, DOMAIN_HASH_PAD, ctx->rate - ctx->npartial);
  assert(ctx->npartial == 0);

  squeeze(ctx, out, nout);
  mem_clean(ctx, sizeof *ctx);
}

/* SHA3-224 */
void cf_sha3_224_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 1152, 448);
}

void cf_sha3_224_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_224_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_224_digest_final(&ours, hash);
}

void cf_sha3_224_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_224_HASHSZ);
}

const cf_chash cf_sha3_224 = {
  .hashsz = CF_SHA3_224_HASHSZ,
  .blocksz = CF_SHA3_224_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_224_init,
  .update = (cf_chash_update) cf_sha3_224_update,
  .digest = (cf_chash_digest) cf_sha3_224_digest
};

/* SHA3-256 */
void cf_sha3_256_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 1088, 512);
}

void cf_sha3_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_256_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_256_digest_final(&ours, hash);
}

void cf_sha3_256_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_256_HASHSZ);
}

const cf_chash cf_sha3_256 = {
  .hashsz = CF_SHA3_256_HASHSZ,
  .blocksz = CF_SHA3_256_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_256_init,
  .update = (cf_chash_update) cf_sha3_256_update,
  .digest = (cf_chash_digest) cf_sha3_256_digest
};

/* SHA3-384 */
void cf_sha3_384_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 832, 768);
}

void cf_sha3_384_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_384_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_384_digest_final(&ours, hash);
}

void cf_sha3_384_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_384_HASHSZ);
}

const cf_chash cf_sha3_384 = {
  .hashsz = CF_SHA3_384_HASHSZ,
  .blocksz = CF_SHA3_384_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_384_init,
  .update = (cf_chash_update) cf_sha3_384_update,
  .digest = (cf_chash_digest) cf_sha3_384_digest
};

/* SHA3-512 */
void cf_sha3_512_init(cf_sha3_context *ctx)
{
  sha3_init(ctx, 576, 1024);
}

void cf_sha3_512_update(cf_sha3_context *ctx, const void *data, size_t nbytes)
{
  sha3_update(ctx, data, nbytes);
}

void cf_sha3_512_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ])
{
  cf_sha3_context ours = *ctx;
  cf_sha3_512_digest_final(&ours, hash);
}

void cf_sha3_512_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ])
{
  pad_and_squeeze(ctx, hash, CF_SHA3_512_HASHSZ);
}

const cf_chash cf_sha3_512 = {
  .hashsz = CF_SHA3_512_HASHSZ,
  .blocksz = CF_SHA3_512_BLOCKSZ,
  .init = (cf_chash_init) cf_sha3_512_init,
  .update = (cf_chash_update) cf_sha3_512_update,
  .digest = (cf_chash_digest) cf_sha3_512_digest
};
