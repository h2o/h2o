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

#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/**
 * HMAC
 * ====
 * This is a one-shot and incremental interface to computing
 * HMAC with any hash function.
 *
 * (Note: HMAC with SHA3 is possible, but is probably not a
 * sensible thing to want.)
 */

/* .. c:type:: cf_hmac_ctx
 * HMAC incremental interface context.
 *
 * .. c:member:: cf_hmac_ctx.hash
 * Hash function description.
 *
 * .. c:member:: cf_hmac_ctx.inner
 * Inner hash computation.
 *
 * .. c:member:: cf_hmac_ctx.outer
 * Outer hash computation.
 */
typedef struct
{
  const cf_chash *hash;
  cf_chash_ctx inner;
  cf_chash_ctx outer;
} cf_hmac_ctx;

/* .. c:function:: $DECL
 * Set up ctx for computing a HMAC using the given hash and key. */
void cf_hmac_init(cf_hmac_ctx *ctx,
                  const cf_chash *hash,
                  const uint8_t *key, size_t nkey);

/* .. c:function:: $DECL
 * Input data. */
void cf_hmac_update(cf_hmac_ctx *ctx,
                    const void *data, size_t ndata);

/* .. c:function:: $DECL
 * Finish and compute HMAC.
 * `ctx->hash->hashsz` bytes are written to `out`. */
void cf_hmac_finish(cf_hmac_ctx *ctx, uint8_t *out);

/* .. c:function:: $DECL
 * One shot interface: compute `HMAC_hash(key, msg)`, writing the
 * answer (which is `hash->hashsz` long) to `out`.
 *
 * This function does not fail. */
void cf_hmac(const uint8_t *key, size_t nkey,
             const uint8_t *msg, size_t nmsg,
             uint8_t *out,
             const cf_chash *hash);

#endif
