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

#ifndef SHA2_H
#define SHA2_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/**
 * SHA224/SHA256
 * =============
 */

/* .. c:macro:: CF_SHA224_HASHSZ
 * The output size of SHA224: 28 bytes. */
#define CF_SHA224_HASHSZ 28

/* .. c:macro:: CF_SHA224_BLOCKSZ
 * The block size of SHA224: 64 bytes. */
#define CF_SHA224_BLOCKSZ 64

/* .. c:macro:: CF_SHA256_HASHSZ
 * The output size of SHA256: 32 bytes. */
#define CF_SHA256_HASHSZ 32

/* .. c:macro:: CF_SHA256_BLOCKSZ
 * The block size of SHA256: 64 bytes. */
#define CF_SHA256_BLOCKSZ 64

/* .. c:type:: cf_sha256_context
 * Incremental SHA256 hashing context.
 *
 * .. c:member:: cf_sha256_context.H
 * Intermediate values.
 *
 * .. c:member:: cf_sha256_context.partial
 * Unprocessed input.
 *
 * .. c:member:: cf_sha256_context.npartial
 * Number of bytes of unprocessed input.
 *
 * .. c:member:: cf_sha256_context.blocks
 * Number of full blocks processed.
 */
typedef struct
{
  uint32_t H[8];                      /* State. */
  uint8_t partial[CF_SHA256_BLOCKSZ]; /* Partial block of input. */
  uint32_t blocks;                    /* Number of full blocks processed into H. */
  size_t npartial;                    /* Number of bytes in prefix of partial. */
} cf_sha256_context;

/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 */
extern void cf_sha256_init(cf_sha256_context *ctx);

/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data if there isn't enough to make
 * a full block.
 */
extern void cf_sha256_update(cf_sha256_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA256_HASHSZ` bytes to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_sha256_digest(const cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA256_HASHSZ` bytes to `hash`.
 *
 * This destroys `ctx`, but uses less stack than :c:func:`cf_sha256_digest`.
 */
extern void cf_sha256_digest_final(cf_sha256_context *ctx, uint8_t hash[CF_SHA256_HASHSZ]);

/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 *
 * nb. SHA224 uses SHA256's underlying types.
 */
extern void cf_sha224_init(cf_sha256_context *ctx);

/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data if there isn't enough to make
 * a full block.
 */
extern void cf_sha224_update(cf_sha256_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA224_HASHSZ` bytes to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_sha224_digest(const cf_sha256_context *ctx, uint8_t hash[CF_SHA224_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA224_HASHSZ` bytes to `hash`.
 *
 * This destroys `ctx`, but uses less stack than :c:func:`cf_sha224_digest`.
 */
extern void cf_sha224_digest_final(cf_sha256_context *ctx, uint8_t hash[CF_SHA224_HASHSZ]);

/* .. c:var:: cf_sha224
 * Abstract interface to SHA224.  See :c:type:`cf_chash` for more information.
 */
extern const cf_chash cf_sha224;

/* .. c:var:: cf_sha256
 * Abstract interface to SHA256.  See :c:type:`cf_chash` for more information.
 */
extern const cf_chash cf_sha256;

/**
 * SHA384/SHA512
 * =============
 */

/* .. c:macro:: CF_SHA384_HASHSZ
 * The output size of SHA384: 48 bytes. */
#define CF_SHA384_HASHSZ 48

/* .. c:macro:: CF_SHA384_BLOCKSZ
 * The block size of SHA384: 128 bytes. */
#define CF_SHA384_BLOCKSZ 128

/* .. c:macro:: CF_SHA512_HASHSZ
 * The output size of SHA512: 64 bytes. */
#define CF_SHA512_HASHSZ 64

/* .. c:macro:: CF_SHA512_BLOCKSZ
 * The block size of SHA512: 128 bytes. */
#define CF_SHA512_BLOCKSZ 128

/* .. c:type:: cf_sha512_context
 * Incremental SHA512 hashing context.
 *
 * .. c:member:: cf_sha512_context.H
 * Intermediate values.
 *
 * .. c:member:: cf_sha512_context.partial
 * Unprocessed input.
 *
 * .. c:member:: cf_sha512_context.npartial
 * Number of bytes of unprocessed input.
 *
 * .. c:member:: cf_sha512_context.blocks
 * Number of full blocks processed.
 */
typedef struct
{
  uint64_t H[8];
  uint8_t partial[CF_SHA512_BLOCKSZ];
  uint32_t blocks;
  size_t npartial;
} cf_sha512_context;

/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 */
extern void cf_sha512_init(cf_sha512_context *ctx);

/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data if there isn't enough to make
 * a full block.
 */
extern void cf_sha512_update(cf_sha512_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA512_HASHSZ` bytes to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_sha512_digest(const cf_sha512_context *ctx, uint8_t hash[CF_SHA512_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA512_HASHSZ` bytes to `hash`.
 *
 * This destroys `ctx`, but uses less stack than :c:func:`cf_sha512_digest`.
 */
extern void cf_sha512_digest_final(cf_sha512_context *ctx, uint8_t hash[CF_SHA512_HASHSZ]);

/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 *
 * nb. SHA384 uses SHA512's underlying types.
 */
extern void cf_sha384_init(cf_sha512_context *ctx);

/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data if there isn't enough to make
 * a full block.
 */
extern void cf_sha384_update(cf_sha512_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA384_HASHSZ` bytes to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_sha384_digest(const cf_sha512_context *ctx, uint8_t hash[CF_SHA384_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hash operation, writing `CF_SHA384_HASHSZ` bytes to `hash`.
 *
 * This destroys `ctx`, but uses less stack than :c:func:`cf_sha384_digest`.
 */
extern void cf_sha384_digest_final(cf_sha512_context *ctx, uint8_t hash[CF_SHA384_HASHSZ]);

/* .. c:var:: cf_sha384
 * Abstract interface to SHA384.  See :c:type:`cf_chash` for more information.
 */
extern const cf_chash cf_sha384;

/* .. c:var:: cf_sha512
 * Abstract interface to SHA512.  See :c:type:`cf_chash` for more information.
 */
extern const cf_chash cf_sha512;

#endif
