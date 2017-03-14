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

#ifndef CHASH_H
#define CHASH_H

#include <stddef.h>
#include <stdint.h>

/**
 * General hash function description
 * =================================
 * This allows us to make use of hash functions without depending
 * on a specific one.  This is useful in implementing, for example,
 * :doc:`HMAC <hmac>`.
 */

/* .. c:type:: cf_chash_init
 * Hashing initialisation function type.
 *
 * Functions of this type should initialise the context in preparation
 * for hashing a message with `cf_chash_update` functions.
 *
 * :rtype: void
 * :param ctx: hash function-specific context structure.
 */
typedef void (*cf_chash_init)(void *ctx);

/* .. c:type:: cf_chash_update
 * Hashing data processing function type.
 *
 * Functions of this type hash `count` bytes of data at `data`,
 * updating the contents of `ctx`.
 *
 * :rtype: void
 * :param ctx: hash function-specific context structure.
 * :param data: input data to hash.
 * :param count: number of bytes to hash.
 */
typedef void (*cf_chash_update)(void *ctx, const void *data, size_t count);

/* .. c:type:: cf_chash_digest
 * Hashing completion function type.
 *
 * Functions of this type complete a hashing operation,
 * writing :c:member:`cf_chash.hashsz` bytes to `hash`.
 *
 * This function does not change `ctx` -- any padding which needs doing
 * must be done seperately (in a copy of `ctx`, say).
 *
 * This means you can interlave `_update` and `_digest` calls to
 * learn `H(A)` and `H(A || B)` without hashing `A` twice.
 *
 * :rtype: void
 * :param ctx: hash function-specific context structure.
 * :param hash: location to write hash result.
 */
typedef void (*cf_chash_digest)(const void *ctx, uint8_t *hash);

/* .. c:type:: cf_chash
 * This type describes an incremental hash function in an abstract way.
 *
 * .. c:member:: cf_chash.hashsz
 * The hash function's output, in bytes.
 *
 * .. c:member:: cf_chash.blocksz
 * The hash function's internal block size, in bytes.
 *
 * .. c:member:: cf_chash.init
 * Context initialisation function.
 *
 * .. c:member:: cf_chash:update
 * Data processing function.
 *
 * .. c:member:: cf_chash:digest
 * Completion function.
 *
 */
typedef struct
{
  size_t hashsz;
  size_t blocksz;

  cf_chash_init init;
  cf_chash_update update;
  cf_chash_digest digest;
} cf_chash;

/* .. c:macro:: CF_CHASH_MAXCTX
 * The maximum size of a :c:type:`cf_chash_ctx`.  This allows
 * use to put a structure in automatic storage that can
 * store working data for any supported hash function. */
#define CF_CHASH_MAXCTX 360

/* .. c:macro:: CF_CHASH_MAXBLK
 * Maximum hash function block size (in bytes). */
#define CF_CHASH_MAXBLK 128

/* .. c:macro:: CF_MAXHASH
 * Maximum hash function output (in bytes). */
#define CF_MAXHASH 64

/* .. c:type:: cf_chash_ctx
 * A type usable with any `cf_chash` as a context. */
typedef union
{
  uint8_t ctx[CF_CHASH_MAXCTX];
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
} cf_chash_ctx;

/* .. c:function:: $DECL
 * One shot hashing: `out = h(m)`.
 *
 * Using the hash function `h`, `nm` bytes at `m` are hashed and `h->hashsz` bytes
 * of result is written to the buffer `out`.
 *
 * :param h: hash function description.
 * :param m: message buffer.
 * :param nm: message length.
 * :param out: hash result buffer (written).
 */
void cf_hash(const cf_chash *h, const void *m, size_t nm, uint8_t *out);

#endif
