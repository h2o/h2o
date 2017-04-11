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

#ifndef PBKDF2_H
#define PBKDF2_H

#include <stddef.h>
#include <stdint.h>

#include "chash.h"

/**
 * PBKDF2-HMAC
 * ===========
 * This is PBKDF2 as described by PKCS#5/RFC2898 with HMAC as the PRF.
 */

/* .. c:function:: $DECL
 * This computes PBKDF2-HMAC with the given hash functon.
 *
 * :param pw: password input buffer.
 * :param npw: password length.
 * :param salt: salt input buffer.
 * :param nsalt: salt length.
 * :param iterations: non-zero iteration count.  Tune this for performance/security tradeoff.
 * :param out: key material output buffer. `nout` bytes are written here.
 * :param nout: key material length.
 * :param hash: hash function description.
 */
void cf_pbkdf2_hmac(const uint8_t *pw, size_t npw,
                    const uint8_t *salt, size_t nsalt,
                    uint32_t iterations,
                    uint8_t *out, size_t nout,
                    const cf_chash *hash);

#endif
