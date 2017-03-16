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

#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/**
 * SHA1
 * ====
 *
 * You shouldn't use this for anything new.
 */

/* .. c:macro:: CF_SHA1_HASHSZ
 * The output size of SHA1: 20 bytes. */
#define CF_SHA1_HASHSZ 20

/* .. c:macro:: CF_SHA1_BLOCKSZ
 * The block size of SHA1: 64 bytes. */
#define CF_SHA1_BLOCKSZ 64

/* .. c:type:: cf_sha1_context
 * Incremental SHA1 hashing context.
 *
 * .. c:member:: cf_sha1_context.H
 * Intermediate values.
 *
 * .. c:member:: cf_sha1_context.partial
 * Unprocessed input.
 *
 * .. c:member:: cf_sha1_context.npartial
 * Number of bytes of unprocessed input.
 *
 * .. c:member:: cf_sha1_context.blocks
 * Number of full blocks processed.
 */
typedef struct
{
  uint32_t H[5];                    /* State. */
  uint8_t partial[CF_SHA1_BLOCKSZ]; /* Partial block of input. */
  uint32_t blocks;                  /* Number of full blocks processed into H. */
  size_t npartial;                  /* Number of bytes in prefix of partial. */
} cf_sha1_context;

/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 */
extern void cf_sha1_init(cf_sha1_context *ctx);

/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data if there isn't enough to make
 * a full block.
 */
extern void cf_sha1_update(cf_sha1_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA1_HASHSZ` bytes to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_sha1_digest(const cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA1_HASHSZ` bytes to `hash`.
 *
 * This destroys `ctx`, but uses less stack than :c:func:`cf_sha1_digest`.
 */
extern void cf_sha1_digest_final(cf_sha1_context *ctx, uint8_t hash[CF_SHA1_HASHSZ]);

/* .. c:var:: cf_sha1
 * Abstract interface to SHA1.  See :c:type:`cf_chash` for more information.
 */
extern const cf_chash cf_sha1;

#endif
