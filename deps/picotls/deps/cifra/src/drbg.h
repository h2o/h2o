/*
 * cifra - embedded cryptography library
 * Written in 2016 by Joseph Birr-Pixton <jpixton@gmail.com>
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

#ifndef DRBG_H
#define DRBG_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"
#include "hmac.h"

/**
 * Hash_DRBG
 * =========
 * This is Hash_DRBG from SP800-90A rev 1, with SHA256 as
 * the underlying hash function.
 *
 * This generator enforces a `reseed_interval` of 2^32-1:
 * use :c:func:`cf_hash_drbg_sha256_needs_reseed` to check
 * whether you need to reseed before use, and reseed using
 * :c:func:`cf_hash_drbg_sha256_reseed`.  If you try to use
 * the generator when it thinks it needs reseeding, it will
 * call `abort`.
 *
 * Internally it enforces a `max_number_of_bits_per_request`
 * of 2^19 bits.  It sorts out chunking up multiple requests
 * for you though, so feel free to ask for more than 2^16 bytes
 * at a time.  If you provide additional input when doing that,
 * it is added only once, on the first subrequest.
 *
 * It does not enforce any `max_length` or
 * `max_personalization_string_length`.
 */

/* .. c:type:: cf_hash_drbg_sha256
 * Hash_DRBG with SHA256 context.
 *
 * .. c:member:: cf_hash_drbg_sha256.V
 * Current internal state.
 *
 * .. c:member:: cf_hash_drbg_sha256.C
 * Current update offset.
 *
 * .. c:member:: cf_hash_drbg_sha256.reseed_counter
 * Current number of times entropy has been extracted from
 * generator.
 */
typedef struct
{
  uint8_t V[440/8];
  uint8_t C[440/8];
  uint32_t reseed_counter;
} cf_hash_drbg_sha256;

/* .. c:function:: $DECL
 * Initialises the generator state `ctx`, using the provided `entropy`,
 * `nonce` and personalisation string `persn`.
 */
extern void cf_hash_drbg_sha256_init(cf_hash_drbg_sha256 *ctx,
                                     const void *entropy, size_t nentropy,
                                     const void *nonce, size_t nnonce,
                                     const void *persn, size_t npersn);

/* .. c:function:: $DECL
 * Returns non-zero if the generator needs reseeding.  If
 * this function returns non-zero, the next :c:func:`cf_hash_drbg_sha256_gen`
 * or :c:func:`cf_hash_drbg_sha256_gen_additional` call will call `abort`.
 */
extern uint32_t cf_hash_drbg_sha256_needs_reseed(const cf_hash_drbg_sha256 *ctx);

/* .. c:function:: $DECL
 * Reseeds the generator with the given `entropy` and additional data `addnl`.
 */
extern void cf_hash_drbg_sha256_reseed(cf_hash_drbg_sha256 *ctx,
                                       const void *entropy, size_t nentropy,
                                       const void *addnl, size_t naddnl);

/* .. c:function:: $DECL
 * Generates pseudo-random output, writing `nout` bytes at `out`.
 * This function aborts if the generator needs seeding.
 */
extern void cf_hash_drbg_sha256_gen(cf_hash_drbg_sha256 *ctx,
                                    void *out, size_t nout);

/* .. c:function:: $DECL
 * Generates pseudo-random output, writing `nout` bytes at `out`.
 * At the same time, `addnl` is input to the generator as further
 * entropy.
 * This function aborts if the generator needs seeding.
 */
extern void cf_hash_drbg_sha256_gen_additional(cf_hash_drbg_sha256 *ctx,
                                               const void *addnl, size_t naddnl,
                                               void *out, size_t nout);

/**
 * HMAC_DRBG
 * =========
 * This is HMAC_DRBG from SP800-90a r1 with any hash function.
 *
 * This generator enforces a `reseed_interval` of 2^32-1:
 * use :c:func:`cf_hmac_drbg_needs_reseed` to check whether
 * you need to reseed before use, and reseed using
 * :c:func:`cf_hmac_drbg_reseed`.  If you try to use the
 * generator when it thinks it needs reseeding, it will
 * call `abort`.
 *
 * Internally it enforces a `max_number_of_bits_per_request`
 * of 2^19 bits.  It sorts out chunking up multiple requests
 * for you though, so feel free to ask for more than 2^16 bytes
 * at a time.  If you provide additional input when doing that,
 * it is added only once, on the first subrequest.
 *
 * It does not enforce any `max_length` or
 * `max_personalization_string_length`.
 */

/* .. c:type:: cf_hmac_drbg
 * HMAC_DRBG context.
 *
 * .. c:member:: cf_hmac_drbg.V
 * Current internal state.
 *
 * .. c:member:: cf_hmac_drbg.hmac
 * Current HMAC context, with key scheduled in it.
 *
 * .. c:member:: cf_hmac_drbg.reseed_counter
 * Current number of times entropy has been extracted from
 * generator.
 */
typedef struct
{
  uint8_t V[CF_MAXHASH];
  cf_hmac_ctx hmac; /* pristine context with key scheduled */
  uint32_t reseed_counter;
} cf_hmac_drbg;

/* .. c:function:: $DECL
 * Initialises the generator state `ctx`, using the provided `entropy`,
 * `nonce` and personalisation string `persn`.
 */
extern void cf_hmac_drbg_init(cf_hmac_drbg *ctx,
                              const cf_chash *hash,
                              const void *entropy, size_t nentropy,
                              const void *nonce, size_t nnonce,
                              const void *persn, size_t npersn);

/* .. c:function:: $DECL
 * Returns non-zero if the generator needs reseeding.  If
 * this function returns non-zero, the next :c:func:`cf_hmac_drbg_gen`
 * or :c:func:`cf_hmac_drbg_gen_additional` call will call `abort`.
 */
extern uint32_t cf_hmac_drbg_needs_reseed(const cf_hmac_drbg *ctx);

/* .. c:function:: $DECL
 * Reseeds the generator with the given `entropy` and additional data
 * `addnl`.
 */
extern void cf_hmac_drbg_reseed(cf_hmac_drbg *ctx,
                                const void *entropy, size_t nentropy,
                                const void *addnl, size_t naddnl);

/* .. c:function:: $DECL
 * Generates pseudo-random output, writing `nout` bytes at `out`.
 * This function aborts if the generator needs seeding.
 */
extern void cf_hmac_drbg_gen(cf_hmac_drbg *ctx,
                             void *out, size_t nout);

/* .. c:function:: $DECL
 * Generates pseudo-random output, writing `nout` bytes at `out`.
 * At the same time, `addnl` is input to the generator as further
 * entropy.
 * This function aborts if the generator needs seeding.
 */
extern void cf_hmac_drbg_gen_additional(cf_hmac_drbg *ctx,
                                        const void *addnl, size_t naddnl,
                                        void *out, size_t nout);

#endif
