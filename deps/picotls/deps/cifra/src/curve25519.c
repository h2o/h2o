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

#if defined(CORTEX_M0) || defined(CORTEX_M3) || defined(CORTEX_M4)
#include "arm/unacl/scalarmult.c"

void cf_curve25519_mul(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
  crypto_scalarmult_curve25519(out, scalar, point);
}

void cf_curve25519_mul_base(uint8_t out[32], const uint8_t scalar[32])
{
  crypto_scalarmult_curve25519_base(out, scalar);
}
#else
#include "curve25519.tweetnacl.c"
#endif
