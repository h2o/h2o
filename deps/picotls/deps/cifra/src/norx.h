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

#ifndef NORX_H
#define NORX_H

#include <stdint.h>
#include <stddef.h>

/**
 * The NORX AEAD cipher
 * ====================
 * This is an implementation of NORX32-4-1 with a one-shot
 * interface.  NORX is a CAESAR candidate with a core similar
 * to ChaCha20 and a sponge structure like Keccak.
 *
 * This is NORX v2.0.  It is not compatible with earlier
 * versions.
 *
 * NORX32 uses a 128-bit key.  Each encryption requires a
 * 64-bit nonce.  An encryption processes one sequence of
 * additional data ('header'), followed by encryption of
 * the plaintext, followed by processing a second sequence
 * of additional data ('trailer').  It outputs a 128-bit
 * tag.
 */

/* .. c:function:: $DECL
 * NORX32-4-1 one-shot encryption interface.
 *
 * :param key: key material.
 * :param nonce: per-message nonce.
 * :param header: header buffer.
 * :param nheader: number of header bytes.
 * :param plaintext: plaintext bytes to be encrypted.
 * :param nbytes: number of plaintext/ciphertext bytes.
 * :param trailer: trailer buffer.
 * :param ntrailer: number of trailer bytes.
 * :param ciphertext: ciphertext output buffer, nbytes in length.
 * :param tag: authentication tag output buffer.
 */
void cf_norx32_encrypt(const uint8_t key[16],
                       const uint8_t nonce[8],
                       const uint8_t *header, size_t nheader,
                       const uint8_t *plaintext, size_t nbytes,
                       const uint8_t *trailer, size_t ntrailer,
                       uint8_t *ciphertext,
                       uint8_t tag[16]);
/* .. c:function:: $DECL
 * NORX32-4-1 one-shot decryption interface.
 *
 * :return: 0 on success, non-zero on error.  Plaintext is zeroed on error.
 *
 * :param key: key material.
 * :param nonce: per-message nonce.
 * :param header: header buffer.
 * :param nheader: number of header bytes.
 * :param ciphertext: ciphertext bytes to be decrypted.
 * :param nbytes: number of plaintext/ciphertext bytes.
 * :param trailer: trailer buffer.
 * :param ntrailer: number of trailer bytes.
 * :param plaintext: plaintext output buffer, nbytes in length.
 * :param tag: authentication tag output buffer.
 */
int cf_norx32_decrypt(const uint8_t key[16],
                      const uint8_t nonce[8],
                      const uint8_t *header, size_t nheader,
                      const uint8_t *ciphertext, size_t nbytes,
                      const uint8_t *trailer, size_t ntrailer,
                      const uint8_t tag[16],
                      uint8_t *plaintext);

#endif
