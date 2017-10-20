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

#ifndef CURVE25519_H
#define CURVE25519_H

#include <stddef.h>
#include <stdint.h>

/**
 * Curve25519
 * ==========
 * This is `curve25519 <http://cr.yp.to/ecdh.html>`_ with switchable
 * implementations underneath.
 *
 * By default tweetnacl is used on hosts, and the implementation
 * from μNaCl for Cortex-M0, M3 and M4.
 */

/* .. c:function:: $DECL
 * Multiplies `point` by `scalar`, putting the resulting point into `out`. */
void cf_curve25519_mul(uint8_t out[32],
                       const uint8_t scalar[32],
                       const uint8_t point[32]);

/* .. c:function:: $DECL
 * Multiplies `scalar` by the curve25519 base point, putting the resulting
 * point into `out`. */
void cf_curve25519_mul_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
