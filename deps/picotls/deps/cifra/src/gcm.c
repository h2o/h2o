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

#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "blockwise.h"
#include "bitops.h"
#include "gf128.h"
#include "tassert.h"

#include <string.h>

#define STATE_INVALID 0
#define STATE_AAD 1
#define STATE_CIPHER 2

static void ghash_init(ghash_ctx *ctx, uint8_t H[16])
{
  memset(ctx, 0, sizeof *ctx);
  cf_gf128_frombytes_be(H, ctx->H);
  ctx->state = STATE_AAD;
}

static void ghash_block(void *vctx, const uint8_t *data)
{
  ghash_ctx *ctx = vctx;
  cf_gf128 gfdata;
  cf_gf128_frombytes_be(data, gfdata);
  cf_gf128_add(gfdata, ctx->Y, ctx->Y);
  cf_gf128_mul(ctx->Y, ctx->H, ctx->Y);
}

static void ghash_add(ghash_ctx *ctx, const uint8_t *buf, size_t n)
{
  cf_blockwise_accumulate(ctx->buffer, &ctx->buffer_used,
                          sizeof ctx->buffer,
                          buf, n,
                          ghash_block,
                          ctx);
}

static void ghash_add_pad(ghash_ctx *ctx)
{
  if (ctx->buffer_used == 0)
    return;

  memset(ctx->buffer + ctx->buffer_used, 0, sizeof(ctx->buffer) - ctx->buffer_used);
  ghash_block(ctx, ctx->buffer);
  ctx->buffer_used = 0;
}

static void ghash_add_aad(ghash_ctx *ctx, const uint8_t *buf, size_t n)
{
  assert(ctx->state == STATE_AAD);
  ctx->len_aad += n;
  ghash_add(ctx, buf, n);
}

static void ghash_add_cipher(ghash_ctx *ctx, const uint8_t *buf, size_t n)
{
  if (ctx->state == STATE_AAD)
  {
    ghash_add_pad(ctx);
    ctx->state = STATE_CIPHER;
  }
  
  assert(ctx->state == STATE_CIPHER);
  ctx->len_cipher += n;
  ghash_add(ctx, buf, n);
}

static void ghash_final(ghash_ctx *ctx, uint8_t out[16])
{
  uint8_t lenbuf[8];

  if (ctx->state == STATE_AAD || ctx->state == STATE_CIPHER)
  {
    ghash_add_pad(ctx);
    ctx->state = STATE_INVALID;
  }

  /* Add len(A) || len(C) */
  write64_be(ctx->len_aad * 8, lenbuf);
  ghash_add(ctx, lenbuf, sizeof lenbuf);

  write64_be(ctx->len_cipher * 8, lenbuf);
  ghash_add(ctx, lenbuf, sizeof lenbuf);

  assert(ctx->buffer_used == 0);
  cf_gf128_tobytes_be(ctx->Y, out);
}

void cf_gcm_encrypt_init(const cf_prp *prp, void *prpctx, cf_gcm_ctx *gcmctx,
                         const uint8_t *header, size_t nheader,
                         const uint8_t *nonce, size_t nnonce)
{
  uint8_t H[16] = { 0 };

  /* H = E_K(0^128) */
  prp->encrypt(prpctx, H, H);

  /* Produce CTR nonce, Y_0:
   *
   * if len(IV) == 96
   *   Y_0 = IV || 0^31 || 1
   * otherwise
   *   Y_0 = GHASH(H, {}, IV)
   */

  if (nnonce == 12)
  {
    memcpy(gcmctx->Y0, nonce, nnonce);
    gcmctx->Y0[12] = gcmctx->Y0[13] = gcmctx->Y0[14] = 0x00;
    gcmctx->Y0[15] = 0x01;
  } else {
    ghash_init(&gcmctx->gh, H);
    ghash_add_cipher(&gcmctx->gh, nonce, nnonce);
    ghash_final(&gcmctx->gh, gcmctx->Y0);
  }

  /* Hash AAD */
  ghash_init(&gcmctx->gh, H);
  ghash_add_aad(&gcmctx->gh, header, nheader);

  /* Produce ciphertext */
  memset(gcmctx->e_Y0, 0, sizeof(gcmctx->e_Y0));
  cf_ctr_init(&gcmctx->ctr, prp, prpctx, gcmctx->Y0);
  cf_ctr_custom_counter(&gcmctx->ctr, 12, 4); /* counter is 2^32 */
  cf_ctr_cipher(&gcmctx->ctr, gcmctx->e_Y0, gcmctx->e_Y0, sizeof gcmctx->e_Y0); /* first block is tag offset */

  mem_clean(H, sizeof H);
}

void cf_gcm_encrypt_update(cf_gcm_ctx *gcmctx, const uint8_t *plain, size_t nplain, uint8_t *cipher)
{
  cf_ctr_cipher(&gcmctx->ctr, plain, cipher, nplain);
  ghash_add_cipher(&gcmctx->gh, cipher, nplain);
}

void cf_gcm_encrypt_final(cf_gcm_ctx *gcmctx, uint8_t *tag, size_t ntag)
{
  /* Post-process ghash output */
  uint8_t full_tag[16] = { 0 };
  ghash_final(&gcmctx->gh, full_tag);
  
  assert(ntag > 1 && ntag <= 16);
  xor_bb(tag, full_tag, gcmctx->e_Y0, ntag);

  mem_clean(full_tag, sizeof full_tag);
  mem_clean(gcmctx, sizeof *gcmctx);
}

void cf_gcm_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag)
{
  cf_gcm_ctx gcmctx;

  cf_gcm_encrypt_init(prp, prpctx, &gcmctx, header, nheader, nonce, nnonce);
  cf_gcm_encrypt_update(&gcmctx, plain, nplain, cipher);
  cf_gcm_encrypt_final(&gcmctx, tag, ntag);
}

int cf_gcm_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain)
{
  uint8_t H[16] = { 0 };
  uint8_t Y0[16]; 

  /* H = E_K(0^128) */
  prp->encrypt(prpctx, H, H);

  /* Produce CTR nonce, Y_0:
   *
   * if len(IV) == 96
   *   Y_0 = IV || 0^31 || 1
   * otherwise
   *   Y_0 = GHASH(H, {}, IV)
   */

  if (nnonce == 12)
  {
    memcpy(Y0, nonce, nnonce);
    Y0[12] = Y0[13] = Y0[14] = 0x00;
    Y0[15] = 0x01;
  } else {
    ghash_ctx gh;
    ghash_init(&gh, H);
    ghash_add_cipher(&gh, nonce, nnonce);
    ghash_final(&gh, Y0);
  }
  
  /* Hash AAD. */
  ghash_ctx gh;
  ghash_init(&gh, H);
  ghash_add_aad(&gh, header, nheader);

  /* Start counter mode, to obtain offset on tag. */
  uint8_t e_Y0[16] = { 0 };
  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, prpctx, Y0);
  cf_ctr_custom_counter(&ctr, 12, 4);
  cf_ctr_cipher(&ctr, e_Y0, e_Y0, sizeof e_Y0);

  /* Hash ciphertext. */
  ghash_add_cipher(&gh, cipher, ncipher);

  /* Produce tag. */
  uint8_t full_tag[16];
  ghash_final(&gh, full_tag);
  assert(ntag > 1 && ntag <= 16);
  xor_bb(full_tag, full_tag, e_Y0, ntag);

  int err = 1;
  if (!mem_eq(full_tag, tag, ntag))
    goto x_err;
  
  /* Complete decryption. */
  cf_ctr_cipher(&ctr, cipher, plain, ncipher);
  err = 0;
 
x_err:
  mem_clean(H, sizeof H);
  mem_clean(Y0, sizeof Y0);
  mem_clean(e_Y0, sizeof e_Y0);
  mem_clean(full_tag, sizeof full_tag);
  mem_clean(&gh, sizeof gh);
  mem_clean(&ctr, sizeof ctr);
  return err;
}
