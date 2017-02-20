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

#include "sha2.h"
#include "blockwise.h"
#include "bitops.h"
#include "handy.h"
#include "tassert.h"

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

# define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define BSIG0(x) (rotr32((x), 2) ^ rotr32((x), 13) ^ rotr32((x), 22))
# define BSIG1(x) (rotr32((x), 6) ^ rotr32((x), 11) ^ rotr32((x), 25))
# define SSIG0(x) (rotr32((x), 7) ^ rotr32((x), 18) ^ ((x) >> 3))
# define SSIG1(x) (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))

void cf_sha256_init(cf_sha256_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x6a09e667;
  ctx->H[1] = 0xbb67ae85;
  ctx->H[2] = 0x3c6ef372;
  ctx->H[3] = 0xa54ff53a;
  ctx->H[4] = 0x510e527f;
  ctx->H[5] = 0x9b05688c;
  ctx->H[6] = 0x1f83d9ab;
  ctx->H[7] = 0x5be0cd19;
}

void cf_sha224_init(cf_sha256_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0xc1059ed8;
  ctx->H[1] = 0x367cd507;
  ctx->H[2] = 0x3070dd17;
  ctx->H[3] = 0xf70e5939;
  ctx->H[4] = 0xffc00b31;
  ctx->H[5] = 0x68581511;
  ctx->H[6] = 0x64f98fa7;
  ctx->H[7] = 0xbefa4fa4;
}

static void sha256_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha256_context *ctx = vctx;

  /* This is a 16-word window into the whole W array. */
  uint32_t W[16];

  uint32_t a = ctx->H[0],
           b = ctx->H[1],
           c = ctx->H[2],
           d = ctx->H[3],
           e = ctx->H[4],
           f = ctx->H[5],
           g = ctx->H[6],
           h = ctx->H[7],
           Wt;

  size_t t;
  for (t = 0; t < 64; t++)
  {
    /* For W[0..16] we process the input into W.
     * For W[16..64] we compute the next W value:
     *
     * W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
     *
     * But all W indices are reduced mod 16 into our window.
     */
    if (t < 16)
    {
      W[t] = Wt = read32_be(inp);
      inp += 4;
    } else {
      Wt = SSIG1(W[(t - 2) % 16]) +
           W[(t - 7) % 16] +
           SSIG0(W[(t - 15) % 16]) +
           W[(t - 16) % 16];
      W[t % 16] = Wt;
    }

    uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K[t] + Wt;
    uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  ctx->H[0] += a;
  ctx->H[1] += b;
  ctx->H[2] += c;
  ctx->H[3] += d;
  ctx->H[4] += e;
  ctx->H[5] += f;
  ctx->H[6] += g;
  ctx->H[7] += h;

  ctx->blocks++;
}

void cf_sha256_update(cf_sha256_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha256_update_block, ctx);
}

void cf_sha224_update(cf_sha256_context *ctx, const void *data, size_t nbytes)
{
  cf_sha256_update(ctx, data, nbytes);
}

void cf_sha256_digest(const cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ])
{
  /* We copy the context, so the finalisation doesn't effect the caller's
   * context.  This means the caller can do:
   *
   * x = init()
   * x.update('hello')
   * h1 = x.digest()
   * x.update(' world')
   * h2 = x.digest()
   *
   * to get h1 = H('hello') and h2 = H('hello world')
   *
   * This wouldn't work if we applied MD-padding to *ctx.
   */

  cf_sha256_context ours = *ctx;
  cf_sha256_digest_final(&ours, hash);
}

void cf_sha256_digest_final(cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ])
{
  uint64_t digested_bytes = ctx->blocks;
  digested_bytes = digested_bytes * CF_SHA256_BLOCKSZ + ctx->npartial;
  uint64_t digested_bits = digested_bytes * 8;

  size_t padbytes = CF_SHA256_BLOCKSZ - ((digested_bytes + 8) % CF_SHA256_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha256_update_block, ctx);

  /* Now hash length. */
  uint8_t buf[8];
  write64_be(digested_bits, buf);
  cf_sha256_update(ctx, buf, 8);

  /* We ought to have got our padding calculation right! */
  assert(ctx->npartial == 0);

  write32_be(ctx->H[0], hash + 0);
  write32_be(ctx->H[1], hash + 4);
  write32_be(ctx->H[2], hash + 8);
  write32_be(ctx->H[3], hash + 12);
  write32_be(ctx->H[4], hash + 16);
  write32_be(ctx->H[5], hash + 20);
  write32_be(ctx->H[6], hash + 24);
  write32_be(ctx->H[7], hash + 28);
  
  memset(ctx, 0, sizeof *ctx);
}

void cf_sha224_digest(const cf_sha256_context *ctx, uint8_t hash[CF_SHA224_HASHSZ])
{
  uint8_t full[CF_SHA256_HASHSZ];
  cf_sha256_digest(ctx, full);
  memcpy(hash, full, CF_SHA224_HASHSZ);
}

void cf_sha224_digest_final(cf_sha256_context *ctx, uint8_t hash[CF_SHA224_HASHSZ])
{
  uint8_t full[CF_SHA256_HASHSZ];
  cf_sha256_digest_final(ctx, full);
  memcpy(hash, full, CF_SHA224_HASHSZ);
}

const cf_chash cf_sha224 = {
  .hashsz = CF_SHA224_HASHSZ,
  .blocksz = CF_SHA256_BLOCKSZ,
  .init = (cf_chash_init) cf_sha224_init,
  .update = (cf_chash_update) cf_sha224_update,
  .digest = (cf_chash_digest) cf_sha224_digest
};

const cf_chash cf_sha256 = {
  .hashsz = CF_SHA256_HASHSZ,
  .blocksz = CF_SHA256_BLOCKSZ,
  .init = (cf_chash_init) cf_sha256_init,
  .update = (cf_chash_update) cf_sha256_update,
  .digest = (cf_chash_digest) cf_sha256_digest
};

