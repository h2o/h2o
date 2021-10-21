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

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

/**
 * The ChaCha20-Poly1305 AEAD construction
 * =======================================
 * This is a composition of the ChaCha20 stream cipher and
 * the Poly1305 polynomial MAC to form an AEAD.
 * It's specified for use in TLS in the form of RFC7539.
 *
 * It uses a 256-bit key and a 96-bit nonce.
 *
 * This is a one-shot interface.
 */

/* .. c:function:: $DECL
 * ChaCha20-Poly1305 authenticated encryption.
 *
 * :param key: key material.
 * :param nonce: per-message nonce.
 * :param header: header buffer.
 * :param nheader: number of header bytes.
 * :param plaintext: plaintext bytes to be encrypted.
 * :param nbytes: number of plaintext/ciphertext bytes.
 * :param ciphertext: ciphertext output buffer, nbytes in length.
 * :param tag: authentication tag output buffer.
 */
void cf_chacha20poly1305_encrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *header, size_t nheader,
                                 const uint8_t *plaintext, size_t nbytes,
                                 uint8_t *ciphertext,
                                 uint8_t tag[16]);

/* .. c:function:: $DECL
 * ChaCha20-Poly1305 authenticated decryption.
 *
 * :return: 0 on success, non-zero on error.  Plaintext is zeroed on error.
 *
 * :param key: key material.
 * :param nonce: per-message nonce.
 * :param header: header buffer.
 * :param nheader: number of header bytes.
 * :param ciphertext: ciphertext bytes to be decrypted.
 * :param nbytes: number of plaintext/ciphertext bytes.
 * :param plaintext: plaintext output buffer, nbytes in length.
 * :param tag: authentication tag output buffer.
 */
int cf_chacha20poly1305_decrypt(const uint8_t key[32],
                                const uint8_t nonce[12],
                                const uint8_t *header, size_t nheader,
                                const uint8_t *ciphertext, size_t nbytes,
                                const uint8_t tag[16],
                                uint8_t *plaintext);

#endif
