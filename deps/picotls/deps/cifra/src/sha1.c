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

#include "sha1.h"
#include "blockwise.h"
#include "bitops.h"
#include "handy.h"
#include "tassert.h"

void cf_sha1_init(cf_sha1_context *ctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->H[0] = 0x67452301;
  ctx->H[1] = 0xefcdab89;
  ctx->H[2] = 0x98badcfe;
  ctx->H[3] = 0x10325476;
  ctx->H[4] = 0xc3d2e1f0;
}

static void sha1_update_block(void *vctx, const uint8_t *inp)
{
  cf_sha1_context *ctx = vctx;

  /* This is a 16-word window into the whole W array. */
  uint32_t W[16];

  uint32_t a = ctx->H[0],
           b = ctx->H[1],
           c = ctx->H[2],
           d = ctx->H[3],
           e = ctx->H[4],
           Wt;

  for (size_t t = 0; t < 80; t++)
  {
    /* For W[0..16] we process the input into W.
     * For W[16..79] we compute the next W value:
     *
     * W[t] = (W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]) <<< 1
     *
     * But all W indices are reduced mod 16 into our window.
     */
    if (t < 16)
    {
      W[t] = Wt = read32_be(inp);
      inp += 4;
    } else {
      Wt = W[(t - 3) % 16] ^ W[(t - 8) % 16] ^ W[(t - 14) % 16] ^ W[(t - 16) % 16];
      Wt = rotl32(Wt, 1);
      W[t % 16] = Wt;
    }

    uint32_t f, k;

    if (t <= 19)
    {
      f = (b & c) | (~b & d);
      k = 0x5a827999;
    } else if (t <= 39) {
      f = b ^ c ^ d;
      k = 0x6ed9eba1;
    } else if (t <= 59) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8f1bbcdc;
    } else {
      f = b ^ c ^ d;
      k = 0xca62c1d6;
    }

    uint32_t temp = rotl32(a, 5) + f + e + k + Wt;
    e = d;
    d = c;
    c = rotl32(b, 30);
    b = a;
    a = temp;
  }

  ctx->H[0] += a;
  ctx->H[1] += b;
  ctx->H[2] += c;
  ctx->H[3] += d;
  ctx->H[4] += e;

  ctx->blocks++;
}

void cf_sha1_update(cf_sha1_context *ctx, const void *data, size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                          data, nbytes,
                          sha1_update_block, ctx);
}

void cf_sha1_digest(const cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ])
{
  cf_sha1_context ours = *ctx;
  cf_sha1_digest_final(&ours, hash);
}

void cf_sha1_digest_final(cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ])
{
  uint64_t digested_bytes = ctx->blocks;
  digested_bytes = digested_bytes * CF_SHA1_BLOCKSZ + ctx->npartial;
  uint64_t digested_bits = digested_bytes * 8;

  size_t padbytes = CF_SHA1_BLOCKSZ - ((digested_bytes + 8) % CF_SHA1_BLOCKSZ);

  /* Hash 0x80 00 ... block first. */
  cf_blockwise_acc_pad(ctx->partial, &ctx->npartial, sizeof ctx->partial,
                       0x80, 0x00, 0x00, padbytes,
                       sha1_update_block, ctx);

  /* Now hash length. */
  uint8_t buf[8];
  write64_be(digested_bits, buf);
  cf_sha1_update(ctx, buf, 8);

  /* We ought to have got our padding calculation right! */
  assert(ctx->npartial == 0);

  write32_be(ctx->H[0], hash + 0);
  write32_be(ctx->H[1], hash + 4);
  write32_be(ctx->H[2], hash + 8);
  write32_be(ctx->H[3], hash + 12);
  write32_be(ctx->H[4], hash + 16);
  
  memset(ctx, 0, sizeof *ctx);
}

const cf_chash cf_sha1 = {
  .hashsz = CF_SHA1_HASHSZ,
  .blocksz = CF_SHA1_BLOCKSZ,
  .init = (cf_chash_init) cf_sha1_init,
  .update = (cf_chash_update) cf_sha1_update,
  .digest = (cf_chash_digest) cf_sha1_digest
};

