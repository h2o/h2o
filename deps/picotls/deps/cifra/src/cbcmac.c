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
#include "bitops.h"
#include "blockwise.h"
#include "gf128.h"
#include "tassert.h"

#include <string.h>

void cf_cbcmac_stream_init(cf_cbcmac_stream *ctx, const cf_prp *prp, void *prpctx)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->prp = prp;
  ctx->prpctx = prpctx;
  cf_cbcmac_stream_reset(ctx);
}

void cf_cbcmac_stream_reset(cf_cbcmac_stream *ctx)
{
  uint8_t iv_zero[CF_MAXBLOCK] = { 0 };
  cf_cbc_init(&ctx->cbc, ctx->prp, ctx->prpctx, iv_zero);
  mem_clean(ctx->buffer, sizeof ctx->buffer);
  ctx->used = 0;
}

static void cbcmac_process(void *vctx, const uint8_t *block)
{
  cf_cbcmac_stream *ctx = vctx;
  uint8_t output[CF_MAXBLOCK];
  cf_cbc_encrypt(&ctx->cbc, block, output, 1);
}

void cf_cbcmac_stream_update(cf_cbcmac_stream *ctx, const uint8_t *data, size_t len)
{
  cf_blockwise_accumulate(ctx->buffer, &ctx->used, ctx->prp->blocksz,
                          data, len,
                          cbcmac_process,
                          ctx);
}

void cf_cbcmac_stream_finish_block_zero(cf_cbcmac_stream *ctx)
{
  if (ctx->used == 0)
    return;

  memset(ctx->buffer + ctx->used, 0, ctx->prp->blocksz - ctx->used);
  cbcmac_process(ctx, ctx->buffer);
  ctx->used = 0;
}

void cf_cbcmac_stream_nopad_final(cf_cbcmac_stream *ctx, uint8_t out[CF_MAXBLOCK])
{
  assert(ctx->used == 0);
  memcpy(out, ctx->cbc.block, ctx->prp->blocksz);
}

void cf_cbcmac_stream_pad_final(cf_cbcmac_stream *ctx, uint8_t out[CF_MAXBLOCK])
{
  uint8_t npad = ctx->prp->blocksz - ctx->used;
  cf_blockwise_acc_byte(ctx->buffer, &ctx->used, ctx->prp->blocksz,
                        npad, npad,
                        cbcmac_process, ctx);
  cf_cbcmac_stream_nopad_final(ctx, out);
}
