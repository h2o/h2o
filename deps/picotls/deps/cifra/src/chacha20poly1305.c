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

#include "chacha20poly1305.h"
#include "salsa20.h"
#include "poly1305.h"
#include "bitops.h"
#include "handy.h"

#define ENCRYPT 1
#define DECRYPT 0

#define SUCCESS 0
#define FAILURE 1

static int process(const uint8_t key[32],
                   const uint8_t nonce[12],
                   const uint8_t *header, size_t nheader,
                   const uint8_t *input, size_t nbytes,
                   uint8_t *output,
                   int mode,
                   uint8_t tag[16])
{
  /* First, generate the Poly1305 key by running ChaCha20 with the
   * given key and a zero counter.  The first half of the
   * 64-byte output is the key. */
  uint8_t fullnonce[16] = { 0 };
  memcpy(fullnonce + 4, nonce, 12);

  uint8_t polykey[32] = { 0 };
  cf_chacha20_ctx chacha;
  cf_chacha20_init_custom(&chacha, key, 32, fullnonce, 4);
  cf_chacha20_cipher(&chacha, polykey, polykey, sizeof polykey);

  /* Now initialise Poly1305. */
  cf_poly1305 poly;
  cf_poly1305_init(&poly, polykey, polykey + 16);
  mem_clean(polykey, sizeof polykey);

  /* Discard next 32 bytes of chacha20 key stream. */
  cf_chacha20_cipher(&chacha, polykey, polykey, sizeof polykey);
  mem_clean(polykey, sizeof polykey);

  /* The input to Poly1305 is:
   * AAD || pad(AAD) || cipher || pad(cipher) || len_64(aad) || len_64(cipher) */
  uint8_t padbuf[16] = { 0 };

#define PADLEN(x) (16 - ((x) & 0xf))

  /* AAD || pad(AAD) */
  cf_poly1305_update(&poly, header, nheader);
  cf_poly1305_update(&poly, padbuf, PADLEN(nheader));

  /* || cipher */
  if (mode == ENCRYPT)
  {
    /* If we're encrypting, we compute the ciphertext
     * before inputting it into the MAC. */
    cf_chacha20_cipher(&chacha, input, output, nbytes);
    cf_poly1305_update(&poly, output, nbytes);
  } else {
    /* Otherwise: decryption -- input the ciphertext.
     * Delay actual decryption until we checked the MAC. */
    cf_poly1305_update(&poly, input, nbytes);
  }

  /* || pad(cipher) */
  cf_poly1305_update(&poly, padbuf, PADLEN(nbytes));

  /* || len_64(aad) || len_64(cipher) */
  write64_le(nheader, padbuf);
  write64_le(nbytes, padbuf + 8);
  cf_poly1305_update(&poly, padbuf, sizeof padbuf);

  /* MAC computation is now complete. */

  if (mode == ENCRYPT)
  {
    cf_poly1305_finish(&poly, tag);
    mem_clean(&chacha, sizeof chacha);
    return SUCCESS;
  }

  /* Decrypt mode: calculate tag, and check it.
   * If it's correct, proceed with decryption. */
  uint8_t checktag[16];
  cf_poly1305_finish(&poly, checktag);

  if (mem_eq(checktag, tag, sizeof checktag))
  {
    cf_chacha20_cipher(&chacha, input, output, nbytes);
    mem_clean(&chacha, sizeof chacha);
    mem_clean(checktag, sizeof checktag);
    return SUCCESS;
  } else {
    mem_clean(output, nbytes);
    mem_clean(&chacha, sizeof chacha);
    mem_clean(checktag, sizeof checktag);
    return FAILURE;
  }
}

void cf_chacha20poly1305_encrypt(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 const uint8_t *header, size_t nheader,
                                 const uint8_t *plaintext, size_t nbytes,
                                 uint8_t *ciphertext,
                                 uint8_t tag[16])
{
  process(key,
          nonce,
          header, nheader,
          plaintext, nbytes,
          ciphertext,
          ENCRYPT,
          tag);
}

int cf_chacha20poly1305_decrypt(const uint8_t key[32],
                                const uint8_t nonce[12],
                                const uint8_t *header, size_t nheader,
                                const uint8_t *ciphertext, size_t nbytes,
                                const uint8_t tag[16],
                                uint8_t *plaintext)
{
  uint8_t ourtag[16];
  memcpy(ourtag, tag, sizeof ourtag);

  return process(key,
                 nonce,
                 header, nheader,
                 ciphertext, nbytes,
                 plaintext,
                 DECRYPT,
                 ourtag);
}

