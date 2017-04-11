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

#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/**
 * SHA3/Keccak
 * ===========
 * This implementation is compatible with FIPS 202,
 * rather than the original Keccak submission.
 *
 */

/* .. c:macro:: CF_SHA3_224_HASHSZ
 * The output size of SHA3-224: 28 bytes. */
#define CF_SHA3_224_HASHSZ 28

/* .. c:macro:: CF_SHA3_256_HASHSZ
 * The output size of SHA3-256: 32 bytes. */
#define CF_SHA3_256_HASHSZ 32

/* .. c:macro:: CF_SHA3_384_HASHSZ
 * The output size of SHA3-384: 48 bytes. */
#define CF_SHA3_384_HASHSZ 48

/* .. c:macro:: CF_SHA3_512_HASHSZ
 * The output size of SHA3-512: 64 bytes. */
#define CF_SHA3_512_HASHSZ 64

/* .. c:macro:: CF_SHA3_224_BLOCKSZ
 * The block size of SHA3-224. */
#define CF_SHA3_224_BLOCKSZ 144

/* .. c:macro:: CF_SHA3_256_BLOCKSZ
 * The block size of SHA3-256. */
#define CF_SHA3_256_BLOCKSZ 136

/* .. c:macro:: CF_SHA3_384_BLOCKSZ
 * The block size of SHA3-384. */
#define CF_SHA3_384_BLOCKSZ 104

/* .. c:macro:: CF_SHA3_512_BLOCKSZ
 * The block size of SHA3-512. */
#define CF_SHA3_512_BLOCKSZ 72

/* We use bit-interleaved internal representation.  This
 * stores a 64 bit quantity in two 32 bit words: one word
 * contains odd bits, the other even.  This means 64-bit rotations
 * are cheaper to compute. */
typedef struct
{
  uint32_t odd, evn;
} cf_sha3_bi;

/* .. c:type:: cf_sha3_context
 * Incremental SHA3 hashing context.
 *
 * .. c:member:: cf_sha3_context.A
 * Intermediate state.
 *
 * .. c:member:: cf_sha3_context.partial
 * Unprocessed input.
 *
 * .. c:member:: cf_sha3_context.npartial
 * Number of bytes of unprocessed input.
 *
 * .. c:member:: cf_sha3_context.rate
 * Sponge absorption rate.
 *
 * .. c:member:: cf_sha3_context.rate
 * Sponge capacity.
 */
typedef struct
{
  /* State is a 5x5 block of 64-bit values, for Keccak-f[1600]. */
  cf_sha3_bi A[5][5];
  uint8_t partial[CF_SHA3_224_BLOCKSZ];
  size_t npartial;
  uint16_t rate, capacity; /* rate and capacity, in bytes. */
} cf_sha3_context;


/* -- _init functions -- */

/* .. c:function:: $DECL */
extern void cf_sha3_224_init(cf_sha3_context *ctx);

/* .. c:function:: $DECL */
extern void cf_sha3_256_init(cf_sha3_context *ctx);

/* .. c:function:: $DECL */
extern void cf_sha3_384_init(cf_sha3_context *ctx);

/* .. c:function:: $DECL
 * Sets up `ctx` ready to hash a new message.
 */
extern void cf_sha3_512_init(cf_sha3_context *ctx);

/* -- _update functions -- */

/* .. c:function:: $DECL */
extern void cf_sha3_224_update(cf_sha3_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL */
extern void cf_sha3_256_update(cf_sha3_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL */
extern void cf_sha3_384_update(cf_sha3_context *ctx, const void *data, size_t nbytes);

/* .. c:function:: $DECL
 * Hashes `nbytes` at `data`.  Copies the data for processing later if there
 * isn't enough to make a full block.
 */
extern void cf_sha3_512_update(cf_sha3_context *ctx, const void *data, size_t nbytes);

/* -- _digest functions -- */

/* .. c:function:: $DECL */
extern void cf_sha3_224_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ]);

/* .. c:function:: $DECL */
extern void cf_sha3_256_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ]);

/* .. c:function:: $DECL */
extern void cf_sha3_384_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hashing operation, writing result to `hash`.
 *
 * This leaves `ctx` unchanged.
 */
extern void cf_sha3_512_digest(const cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ]);

/* -- _digest_final functions -- */

/* .. c:function:: $DECL */
extern void cf_sha3_224_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_224_HASHSZ]);

/* .. c:function:: $DECL */
extern void cf_sha3_256_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_256_HASHSZ]);

/* .. c:function:: $DECL */
extern void cf_sha3_384_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_384_HASHSZ]);

/* .. c:function:: $DECL
 * Finishes the hashing operation, writing result to `hash`.
 *
 * This destroys the contents of `ctx`.
 */
extern void cf_sha3_512_digest_final(cf_sha3_context *ctx, uint8_t hash[CF_SHA3_512_HASHSZ]);

/* .. c:var:: cf_sha3_224
 * .. c:var:: cf_sha3_256
 * .. c:var:: cf_sha3_384
 * .. c:var:: cf_sha3_512
 * Abstract interface to SHA3 functions.  See :c:type:`cf_chash` for more information.
 */
extern const cf_chash cf_sha3_224;
extern const cf_chash cf_sha3_256;
extern const cf_chash cf_sha3_384;
extern const cf_chash cf_sha3_512;

#endif
