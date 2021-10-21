/*
 * Copyright (c) 2019 Christian Huitema <huitema@huitema.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PTLS_FFX_H
#define PTLS_FFX_H

/*
 * Format preserving encryption using the FFX algorithm.
 *
 * We demonstrate here a simple encryption process derived
 * from the FFX algorithms, which is effectively a specific
 * mode of running a verified encryption code. The
 * algorithm is Feistel cipher in which the S-boxes are
 * defined by a symmetric encryption algorithm such as
 * AES or ChaCha20.
 * See "Ciphers with Arbitrary Finite Domains" by
 * John Black and Phillip Rogaway, 2001 --
 * http://web.cs.ucdavis.edu/~rogaway/papers/subset.pdf
 *
 * An instantiation of the algorithm is defined by a
 * series of parameters:
 *   - the context of the symmetric crypto algorithm,
 *   - key used for the symmetric algorithm,
 *   - number of rounds,
 *   - length of the block in bits
 *
 * We consider just two symmetric algorithms for now,
 * ChaCha20 and AES128CTR. In theory, any symmetric algorithm
 * operating on a 128 bit block would work, and crytographic
 * hashes producing at least 128 bits of output could also
 * be used. In practice, ChaCha20 and AES128 cover most of
 * the use cases.
 *
 * The implementation will produce a result for any block
 * length lower than 256, although values lower than 32 would
 * not be recommended.
 *
 * The block to be encrypted is passed as a byte array of size
 * (block_length + 7)/8. When the block_length is not a
 * multiple of 8, the algorithm guarantees that the extra bits
 * in the last byte are left untouched. For example, if the
 * block length is 39, the least significant bit of the
 * fifth byte will be copied from input to output.
 *
 * The number of rounds is left as a configuration parameter,
 * which is constrained to be even by our implementation. The
 * required number of passes varies with the application's
 * constraints. The practical minimum is 4 passes. Demanding
 * applications can use 8 passes, and the practical conservative
 * value is 10, as specified by NIST for the FF1 variant of
 * the same algorithm. This choice between 4, 8 or 10 is
 * based on "Luby-Rackoff: 7 Rounds are Enough
 * for 2^n(1-epsilon) Security" by Jacques Patarin, 2003 --
 * https://www.iacr.org/archive/crypto2003/27290510/27290510.pdf
 *
 * Encrypting short numbers, by nature, produces a codebook
 * of limited size. In many applications, the short number is
 * part of a larger object that is passed in clear text. In that
 * case, NIST recommends using as much as possible of that clear
 * text as an initialization vector, used as "tweak" in the
 * FFX algorithm. See:
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 */

typedef struct st_ptls_ffx_context_t {
    ptls_cipher_context_t super;
    ptls_cipher_context_t *enc_ctx;
    int nb_rounds;
    int is_enc;
    size_t byte_length;
    size_t nb_left;
    size_t nb_right;
    uint8_t mask_last_byte;
    uint8_t tweaks[16];
} ptls_ffx_context_t;

/**
 * The PTLS_FFX_CIPHER_ALGO macro will define a variant of the FFX algorithm by specifying
 * the base algorithm (vraiable name of type ptls_cipher_algorithm_t), the bit length
 * of the block, the selected number of blocks and the key size of the base algorithm,
 * in bytes.
 *
 * The macro will automatically generate an algorithm name, of the form:
 *    ptls_ffx_<base algorithm name>_b<bit length>_r<number of rounds>
 * For example, selecting the algorithm "ptls_minicrypto_chacha20" with a block
 * size of 53 bits and 8 rounds will generate the name:
 *    ptls_ffx_ptls_minicrypto_chacha20_b53_r8
 * This name is declared as a static variable.
 *
 * Once the FFX variant is defined, the name can be used to create a
 * cipher context using ptls_cipher_new. The context can then be used
 * through the function ptls_cipher_init, ptls_cipher_encrypt, and
 * can be freed by calling ptls_cipher_free.
 *
 * The ptls_cipher_encrypt will encrypt a code word of the specified
 * bit length, or decrypt it if the context was created with the
 * option "is_enc = 0". The code word is represented as an array of
 * bytes. If the bit length is not a multiple of 8, the remaining
 * low level bits in the last byte will be left unchanged.
 */
#define PTLS_FFX_CIPHER_ALGO_NAME(base, bitlength, nbrounds) #base "-ffx-b" #bitlength "-r" #nbrounds
#define PTLS_FFX_CIPHER_ALGO(base, bitlength, nbrounds, keysize)                                                                   \
    static int ptls_ffx_##base##_b##bitlength##_r##nbrounds##_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key)       \
    {                                                                                                                              \
        return ptls_ffx_setup_crypto(ctx, &base, is_enc, nbrounds, bitlength, key);                                                \
    }                                                                                                                              \
    static ptls_cipher_algorithm_t ptls_ffx_##base##_b##bitlength##_r##nbrounds = {                                                \
        PTLS_FFX_CIPHER_ALGO_NAME(base, bitlength, nbrounds), keysize, (bitlength + 7) / 8, 16, sizeof(ptls_ffx_context_t),        \
        ptls_ffx_##base##_b##bitlength##_r##nbrounds##_setup};

/*
 * The function ptls_ffx_new creates a cipher context for a specific FFX variant.
 * It is equivalent to defining the variant with the PTLS_FFX_CIPHER_ALGO macro,
 * then creating the context using ptls_cipher_new.
 */
ptls_cipher_context_t *ptls_ffx_new(ptls_cipher_algorithm_t *algo, int is_enc, int nb_rounds, size_t bit_length, const void *key);

/**
 * The function ptls_ffx_setup_crypto is called by ptls_cipher_new  or
 * ptls_ffx_new when initializing an FFX variant. It should not be
 * called directly.
 */
int ptls_ffx_setup_crypto(ptls_cipher_context_t *_ctx, ptls_cipher_algorithm_t *algo, int is_enc, int nb_rounds, size_t bit_length,
                          const void *key);
#endif /* PTLS_FFX_H */
