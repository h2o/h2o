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

#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>
#include <stddef.h>

/**
 * The Salsa20/Chacha20 stream ciphers
 * ===================================
 *
 * These are similar stream ciphers by djb.
 *
 * A reduced round variant of Salsa20 (Salsa20/12)
 * was selected as a finalist of the eSTREAM stream
 * cipher competition.  This implementation does
 * the full 20 rounds.
 *
 * ChaCha20 is fundamentally like Salsa20, but
 * has a tweaked round function to improve security
 * margin without damaging performance.
 */

/* Salsa20 core transform. */
void cf_salsa20_core(const uint8_t key0[16],
                     const uint8_t key1[16],
                     const uint8_t nonce[16],
                     const uint8_t constant[16],
                     uint8_t out[64]);

/* Chacha20 core transform. */
void cf_chacha20_core(const uint8_t key0[16],
                      const uint8_t key1[16],
                      const uint8_t nonce[16],
                      const uint8_t constant[16],
                      uint8_t out[64]);

/* .. c:type:: cf_salsa20_ctx
 * Incremental interface to Salsa20.
 *
 * .. c:member:: cf_salsa20_ctx.key0
 * Half of key material.
 *
 * .. c:member:: cf_salsa20_ctx.key1
 * Half of key material.
 *
 * .. c:member:: cf_salsa20_ctx.nonce
 * Nonce and counter block.
 *
 * .. c:member:: cf_salsa20_ctx.constant
 * Per-key-length constants.
 *
 * .. c:member:: cf_salsa20_ctx.block
 * Buffer for unused key stream material.
 *
 * .. c:member:: cf_salsa20_ctx.nblock
 * Number of bytes at end of `block` that can be used as key stream.
 *
 */
typedef struct
{
  uint8_t key0[16], key1[16];
  uint8_t nonce[16];
  const uint8_t *constant;
  uint8_t block[64];
  size_t nblock;
  size_t ncounter;
} cf_salsa20_ctx, cf_chacha20_ctx;

/* .. c:type:: cf_chacha20_ctx
 * Incremental interface to Chacha20.  This structure
 * is identical to :c:type:`cf_salsa20_ctx`.
 */

/* .. c:function:: $DECL
 * Salsa20 initialisation function.
 *
 * :param ctx: salsa20 context.
 * :param key: key material.
 * :param nkey: length of key in bytes, either 16 or 32.
 * :param nonce: per-message nonce.
 */
void cf_salsa20_init(cf_salsa20_ctx *ctx, const uint8_t *key, size_t nkey, const uint8_t nonce[8]);

/* .. c:function:: $DECL
 * Chacha20 initialisation function.
 *
 * :param ctx: chacha20 context (written).
 * :param key: key material.
 * :param nkey: length of key in bytes, either 16 or 32.
 * :param nonce: per-message nonce.
 */
void cf_chacha20_init(cf_chacha20_ctx *ctx, const uint8_t *key, size_t nkey, const uint8_t nonce[8]);

/* .. c:function:: $DECL
 * Chacha20 initialisation function.  This version gives full control over the whole
 * initial nonce value, and the size of the counter.  The counter is always at the front
 * of the nonce.
 *
 * :param ctx: chacha20 context (written).
 * :param key: key material.
 * :param nkey: length of key in bytes, either 16 or 32.
 * :param nonce: per-message nonce.  `ncounter` bytes at the start are the block counter.
 * :param ncounter: length, in bytes, of the counter portion of the nonce.
 */
void cf_chacha20_init_custom(cf_chacha20_ctx *ctx, const uint8_t *key, size_t nkey,
                             const uint8_t nonce[16], size_t ncounter);

/* .. c:function:: $DECL
 * Salsa20 encryption/decryption function.
 *
 * :param ctx: salsa20 context.
 * :param input: input data buffer (read), `count` bytes long.
 * :param output: output data buffer (written), `count` bytes long.
 */
void cf_salsa20_cipher(cf_salsa20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t count);

/* .. c:function:: $DECL
 * Chacha20 encryption/decryption function.
 *
 * :param ctx: chacha20 context.
 * :param input: input data buffer (read), `count` bytes long.
 * :param output: output data buffer (written), `count` bytes long.
 */
void cf_chacha20_cipher(cf_chacha20_ctx *ctx, const uint8_t *input, uint8_t *output, size_t count);

#endif
