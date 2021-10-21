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

#include "bitops.h"
#include "salsa20.h"
#include "blockwise.h"
#include "tassert.h"

#include <string.h>
#include <stdlib.h>

void cf_chacha20_core(const uint8_t key0[16],
                      const uint8_t key1[16],
                      const uint8_t nonce[16],
                      const uint8_t constant[16],
                      uint8_t out[64])
{
  uint32_t z0, z1, z2, z3, z4, z5, z6, z7,
           z8, z9, za, zb, zc, zd, ze, zf;

  uint32_t x0 = z0 = read32_le(constant + 0),
           x1 = z1 = read32_le(constant + 4),
           x2 = z2 = read32_le(constant + 8),
           x3 = z3 = read32_le(constant + 12),
           x4 = z4 = read32_le(key0 + 0),
           x5 = z5 = read32_le(key0 + 4),
           x6 = z6 = read32_le(key0 + 8),
           x7 = z7 = read32_le(key0 + 12),
           x8 = z8 = read32_le(key1 + 0),
           x9 = z9 = read32_le(key1 + 4),
           xa = za = read32_le(key1 + 8),
           xb = zb = read32_le(key1 + 12),
           xc = zc = read32_le(nonce + 0),
           xd = zd = read32_le(nonce + 4),
           xe = ze = read32_le(nonce + 8),
           xf = zf = read32_le(nonce + 12);

#define QUARTER(a, b, c, d) \
  a += b; d = rotl32(d ^ a, 16); \
  c += d; b = rotl32(b ^ c, 12); \
  a += b; d = rotl32(d ^ a, 8);  \
  c += d; b = rotl32(b ^ c, 7);

  int i;
  for (i = 0; i < 10; i++)
  {
    QUARTER(z0, z4, z8, zc);
    QUARTER(z1, z5, z9, zd);
    QUARTER(z2, z6, za, ze);
    QUARTER(z3, z7, zb, zf);
    QUARTER(z0, z5, za, zf);
    QUARTER(z1, z6, zb, zc);
    QUARTER(z2, z7, z8, zd);
    QUARTER(z3, z4, z9, ze);
  }

  x0 += z0;
  x1 += z1;
  x2 += z2;
  x3 += z3;
  x4 += z4;
  x5 += z5;
  x6 += z6;
  x7 += z7;
  x8 += z8;
  x9 += z9;
  xa += za;
  xb += zb;
  xc += zc;
  xd += zd;
  xe += ze;
  xf += zf;

  write32_le(x0, out + 0);
  write32_le(x1, out + 4);
  write32_le(x2, out + 8);
  write32_le(x3, out + 12);
  write32_le(x4, out + 16);
  write32_le(x5, out + 20);
  write32_le(x6, out + 24);
  write32_le(x7, out + 28);
  write32_le(x8, out + 32);
  write32_le(x9, out + 36);
  write32_le(xa, out + 40);
  write32_le(xb, out + 44);
  write32_le(xc, out + 48);
  write32_le(xd, out + 52);
  write32_le(xe, out + 56);
  write32_le(xf, out + 60);
}

static const uint8_t *chacha20_tau = (const uint8_t *) "expand 16-byte k";
static const uint8_t *chacha20_sigma = (const uint8_t *) "expand 32-byte k";

static void set_key(cf_chacha20_ctx *ctx, const uint8_t *key, size_t nkey)
{
  switch (nkey)
  {
    case 16:
      memcpy(ctx->key0, key, 16);
      memcpy(ctx->key1, key, 16);
      ctx->constant = chacha20_tau;
      break;
    case 32:
      memcpy(ctx->key0, key, 16);
      memcpy(ctx->key1, key + 16, 16);
      ctx->constant = chacha20_sigma;
      break;
    default:
      abort();
  }
}

void cf_chacha20_init(cf_chacha20_ctx *ctx, const uint8_t *key, size_t nkey, const uint8_t nonce[8])
{
  set_key(ctx, key, nkey);
  memset(ctx->nonce, 0, sizeof ctx->nonce);
  memcpy(ctx->nonce + 8, nonce, 8);
  ctx->nblock = 0;
  ctx->ncounter = 8;
}

void cf_chacha20_init_custom(cf_chacha20_ctx *ctx, const uint8_t *key, size_t nkey,
                             const uint8_t nonce[16], size_t ncounter)
{
  assert(ncounter > 0);
  set_key(ctx, key, nkey);
  memcpy(ctx->nonce, nonce, sizeof ctx->nonce);
  ctx->nblock = 0;
  ctx->ncounter = ncounter;
}

static void cf_chacha20_next_block(void *vctx, uint8_t *out)
{
  cf_chacha20_ctx *ctx = vctx;
  cf_chacha20_core(ctx->key0,
                   ctx->key1,
                   ctx->nonce,
                   ctx->constant,
                   out);
  incr_le(ctx->nonce, ctx->ncounter);
}

void cf_chacha20_cipher(cf_chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t bytes)
{
  cf_blockwise_xor(ctx->block, &ctx->nblock, 64,
                   input, output, bytes,
                   cf_chacha20_next_block,
                   ctx);
}
