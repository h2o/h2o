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

#include "poly1305.h"
#include "bitops.h"
#include "handy.h"
#include "blockwise.h"

#include <string.h>
#include <stdio.h>

void cf_poly1305_init(cf_poly1305 *ctx,
                      const uint8_t r[16],
                      const uint8_t s[16])
{
  memset(ctx, 0, sizeof *ctx);

  ctx->r[0]  = r[0];
  ctx->r[1]  = r[1];
  ctx->r[2]  = r[2];
  ctx->r[3]  = r[3] & 0x0f;
  ctx->r[4]  = r[4] & 0xfc;
  ctx->r[5]  = r[5];
  ctx->r[6]  = r[6];
  ctx->r[7]  = r[7] & 0x0f;
  ctx->r[8]  = r[8] & 0xfc;
  ctx->r[9]  = r[9];
  ctx->r[10] = r[10];
  ctx->r[11] = r[11] & 0x0f;
  ctx->r[12] = r[12] & 0xfc;
  ctx->r[13] = r[13];
  ctx->r[14] = r[14];
  ctx->r[15] = r[15] & 0x0f;
  ctx->r[16] = 0;

  memcpy(ctx->s, s, 16);
}

static void poly1305_add(uint32_t h[17],
                         const uint32_t x[17])
{
  uint32_t carry = 0;
  int i;

  for (i = 0; i < 17; i++)
  {
    carry += h[i] + x[i];
    h[i] = carry & 0xff;
    carry >>= 8;
  }
}

/* Minimal reduction/carry chain. */
static void poly1305_min_reduce(uint32_t x[17])
{
  uint32_t carry = 0;
  int i;
  for (i = 0; i < 16; i++)
  {
    carry += x[i];
    x[i] = carry & 0xff;
    carry >>= 8;
  }

  /* 2 ** 130 - 5 = 0x3fffffffffffffffffffffffffffffffb
   *                  ^
   * So 2 bits of carry are put into top word.
   * Remaining bits get multiplied by 5 and carried back
   * into bottom */
  carry += x[16];
  x[16] = carry & 0x03;
  carry = 5 * (carry >> 2);

  for (i = 0; i < 16; i++)
  {
    carry += x[i];
    x[i] = carry & 0xff;
    carry >>= 8;
  }

  x[16] += carry;
}

/* This is - 2 ** 130 - 5 in twos complement. */
static const uint32_t negative_1305[17] = {
  0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0xfc
};

static void poly1305_full_reduce(uint32_t x[17])
{
  uint32_t xsub[17];
  size_t i;

  for (i = 0; i < 17; i++)
    xsub[i] = x[i];

  poly1305_add(xsub, negative_1305);

  /* If x - (2 ** 130 - 5) is negative, then
   * x didn't need reduction: we discard the results.
   * Do this in a side-channel silent way. */
  uint32_t negative_mask = mask_u32(xsub[16] & 0x80, 0x80);
  uint32_t positive_mask = negative_mask ^ 0xffffffff;

  for (i = 0; i < 17; i++)
    x[i] = (x[i] & negative_mask) | (xsub[i] & positive_mask);
}

static void poly1305_mul(uint32_t x[17],
                         const uint32_t y[17])
{
  uint32_t r[17];
  int i;

  for (i = 0; i < 17; i++)
  {
    uint32_t accum = 0;
    int j;

    for (j = 0; j <= i; j++)
      accum += x[j] * y[i - j];

    /* Add in carries.  These get shifted 130 bits
     * to the right, with a combination of byte indexing
     * and shifting (136 bits right, then 6 bits left).
     *
     * nb. 5 << 6 is made up of two parts:
     *   5: reduction of 2 ** 130 leaves a multiple 5
     *   shift 6 places left
     *     17 * 8: byte indexing shift (136 bits)
     *     130: desired shift
     */
    for (j = i + 1; j < 17; j++)
      accum += (5 << 6) * x[j] * y[i + 17 - j];

    r[i] = accum;
  }

  poly1305_min_reduce(r);

  for (i = 0; i < 17; i++)
    x[i] = r[i];
}

static void poly1305_block(cf_poly1305 *ctx,
                           const uint32_t c[17])
{
  poly1305_add(ctx->h, c);
  poly1305_mul(ctx->h, ctx->r);
}

static void poly1305_whole_block(void *vctx,
                                 const uint8_t *buf)
{
  cf_poly1305 *ctx = vctx;
  uint32_t c[17];
  int i;

  for (i = 0; i < 16; i++)
    c[i] = buf[i];

  c[16] = 1;
  poly1305_block(ctx, c);
}

static void poly1305_last_block(cf_poly1305 *ctx)
{
  uint32_t c[17] = { 0 };
  size_t i;

  for (i = 0; i < ctx->npartial; i++)
    c[i] = ctx->partial[i];

  c[ctx->npartial] = 1;
  poly1305_block(ctx, c);
}

void cf_poly1305_update(cf_poly1305 *ctx,
                        const uint8_t *buf,
                        size_t nbytes)
{
  cf_blockwise_accumulate(ctx->partial, &ctx->npartial,
                          sizeof ctx->partial,
                          buf, nbytes,
                          poly1305_whole_block,
                          ctx);
}

void cf_poly1305_finish(cf_poly1305 *ctx,
                        uint8_t out[16])
{
  if (ctx->npartial)
    poly1305_last_block(ctx);

  uint32_t s[17];
  size_t i;
  for (i = 0; i < 16; i++)
    s[i] = ctx->s[i];
  s[16] = 0;

  poly1305_full_reduce(ctx->h);
  poly1305_add(ctx->h, s);

  for (i = 0; i < 16; i++)
    out[i] = ctx->h[i];

  mem_clean(ctx, sizeof *ctx);
}

