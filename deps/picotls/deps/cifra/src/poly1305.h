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

#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

/**
 * Poly1305
 * ========
 * This is an incremental interface to computing the poly1305
 * single shot MAC.
 *
 * Note: construct Poly1305-AES with this by taking a 16 byte
 * nonce and encrypting it, and then using the result as an
 * input to this function.
 */

/* .. c:type:: cf_poly1305
 * Poly1305 incremental interface context.
 *
 * .. c:member:: cf_poly1305.h
 * Current accumulator.
 *
 * .. c:member:: cf_poly1305.r
 * Block multiplier.
 *
 * .. c:member:: cf_poly1305.s
 * Final XOR offset.
 *
 * .. c:member:: cf_poly1305.partial
 * Unprocessed input.
 *
 * .. c:member:: cf_poly1305.npartial
 * Number of bytes of unprocessed input.
 *
 */
typedef struct
{
  uint32_t h[17];
  uint32_t r[17];
  uint8_t s[16];
  uint8_t partial[16];
  size_t npartial;
} cf_poly1305;

/* .. c:function:: $DECL
 * Sets up `ctx` ready to compute a new MAC.
 *
 * In Poly1305-AES, `r` is the second half of the 32-byte key.
 * `s` is a nonce encrypted under the first half of the key.
 *
 * :param ctx: context (written)
 * :param r: MAC key.
 * :param s: preprocessed nonce.
 *
 */
void cf_poly1305_init(cf_poly1305 *ctx,
    const uint8_t r[16],
    const uint8_t s[16]);

/* .. c:function:: $DECL
 * Processes `nbytes` at `data`.  Copies the data if there isn't enough to make
 * a full block.
 */
void cf_poly1305_update(cf_poly1305 *ctx,
                        const uint8_t *data,
                        size_t nbytes);

/* .. c:function:: $DECL
 * Finishes the operation, writing 16 bytes to `out`.
 *
 * This destroys `ctx`.
 */
void cf_poly1305_finish(cf_poly1305 *ctx,
                        uint8_t out[16]);

#endif
