/*
 * Copyright (c) 2023, Christian Huitema
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/build_info.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <mbedtls/error.h>
#include <psa/crypto.h>
#include <psa/crypto_struct.h>
#include <psa/crypto_values.h>
/* #include "ptls_mbedtls.h" */

typedef struct st_ptls_mbedtls_signature_scheme_t {
    uint16_t scheme_id;
    psa_algorithm_t hash_algo;
} ptls_mbedtls_signature_scheme_t;

typedef struct st_ptls_mbedtls_sign_certificate_t {
    ptls_sign_certificate_t super;
    mbedtls_svc_key_id_t key_id;
    psa_key_attributes_t attributes;
    const ptls_mbedtls_signature_scheme_t *schemes;
} ptls_mbedtls_sign_certificate_t;

static const unsigned char ptls_mbedtls_oid_ec_key[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const unsigned char ptls_mbedtls_oid_rsa_key[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static const unsigned char ptls_mbedtls_oid_ed25519[] = {0x2b, 0x65, 0x70};

static const ptls_mbedtls_signature_scheme_t rsa_signature_schemes[] = {{PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, PSA_ALG_SHA_256},
                                                                        {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384, PSA_ALG_SHA_384},
                                                                        {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512, PSA_ALG_SHA_512},
                                                                        {UINT16_MAX, PSA_ALG_NONE}};

static const ptls_mbedtls_signature_scheme_t secp256r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PSA_ALG_SHA_256}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp384r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, PSA_ALG_SHA_384}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp521r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512, PSA_ALG_SHA_512}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t ed25519_signature_schemes[] = {{PTLS_SIGNATURE_ED25519, PSA_ALG_NONE},
                                                                            {UINT16_MAX, PSA_ALG_NONE}};

#if defined(MBEDTLS_PEM_PARSE_C)

/* Mapping of MBEDTLS APIs to Picotls */

static int ptls_mbedtls_parse_der_length(const unsigned char *pem_buf, size_t pem_len, size_t *px, size_t *pl)
{
    int ret = 0;
    size_t x = *px;
    size_t l = pem_buf[x++];

    if (l > 128) {
        size_t ll = l & 0x7F;
        l = 0;
        while (ll > 0 && x + l < pem_len) {
            l *= 256;
            l += pem_buf[x++];
            ll--;
        }
    }

    *pl = l;
    *px = x;

    return ret;
}

static int ptls_mbedtls_parse_ecdsa_field(const unsigned char *pem_buf, size_t pem_len, size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t x = 0;

    // const unsigned char head = { 0x30, l-2, 0x02, 0x01, 0x01, 0x04 }
    if (pem_len < 16 || pem_buf[x++] != 0x30 /* type = sequence */) {
        ret = -1;
    } else {
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);

        if (x + l != pem_len) {
            ret = -1;
        }
    }
    if (ret == 0) {
        if (pem_buf[x++] != 0x02 /* type = int */ || pem_buf[x++] != 0x01 /* length of int = 1 */ ||
            pem_buf[x++] != 0x01 /* version = 1 */ || pem_buf[x++] != 0x04 /*octet string */ || pem_buf[x] + x >= pem_len) {
            ret = -1;
        } else {
            *key_index = x + 1;
            *key_length = pem_buf[x];
            x += 1 + pem_buf[x];

            if (x < pem_len && pem_buf[x] == 0xa0) {
                /* decode the EC parameters, identify the curve */
                x++;
                if (x + pem_buf[x] >= pem_len) {
                    /* EC parameters extend beyond buffer */
                    ret = -1;
                } else {
                    x += pem_buf[x] + 1;
                }
            }

            if (ret == 0 && x < pem_len) {
                /* skip the public key parameter */
                if (pem_buf[x++] != 0xa1 || x >= pem_len) {
                    ret = -1;
                } else {
                    size_t l = 0;
                    ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);
                    x += l;
                }
            }

            if (x != pem_len) {
                ret = -1;
            }
        }
    }
    return ret;
}

/* On input, key_index points at the "key information" in a
 * "private key" message. For EDDSA, this contains an
 * octet string carrying the key itself. On return, key index
 * and key length are updated to point at the key field.
 */
static int ptls_mbedtls_parse_eddsa_key(const unsigned char *pem_buf, size_t pem_len, size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t x = *key_index;
    size_t l_key = 0;

    if (*key_length < 2 || pem_buf[x++] != 0x04) {
        ret = -1;
    } else {
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_key);
        if (x + l_key != *key_index + *key_length) {
            ret = -1;
        } else {

            *key_index = x;
            *key_length = l_key;
        }
    }
    return ret;
}

/* If using PKCS8 encoding, the "private key" field contains the
 * same "ecdsa field" found in PEM "EC PRIVATE KEY" files. We
 * use the same parser, but we need to reset indices so they
 * reflect the unwrapped key.
 */
int ptls_mbedtls_parse_ec_private_key(const unsigned char *pem_buf, size_t pem_len, size_t *key_index, size_t *key_length)
{
    size_t x_offset = 0;
    size_t x_len = 0;
    int ret = ptls_mbedtls_parse_ecdsa_field(pem_buf + *key_index, *key_length, &x_offset, &x_len);

    if (ret == 0) {
        *key_index += x_offset;
        *key_length = x_len;
    }
    return ret;
}

int test_parse_private_key_field(const unsigned char *pem_buf, size_t pem_len, size_t *oid_index, size_t *oid_length,
                                 size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t l_oid = 0;
    size_t x_oid = 0;
    size_t l_key = 0;
    size_t x_key = 0;

    size_t x = 0;
    /*  const unsigned char head = {0x30, l - 2, 0x02, 0x01, 0x00} */
    if (pem_len < 16 || pem_buf[x++] != 0x30 /* type = sequence */) {
        ret = -1;
    } else {
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);

        if (x + l != pem_len) {
            ret = -1;
        }
    }
    if (ret == 0) {
        if (pem_buf[x++] != 0x02 /* type = int */ || pem_buf[x++] != 0x01 /* length of int = 1 */ ||
            pem_buf[x++] != 0x00 /* version = 0 */ || pem_buf[x++] != 0x30 /* sequence */) {
            ret = -1;
        } else {
            /* the sequence contains the OID and optional key attributes,
             * which we ignore for now.
             */
            size_t l_seq = 0;
            size_t x_seq;
            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_seq);
            x_seq = x;
            if (x + l_seq >= pem_len || pem_buf[x++] != 0x06) {
                ret = -1;
            } else {
                l_oid = pem_buf[x++];
                x_oid = x;
                if (x + l_oid > x_seq + l_seq) {
                    ret = -1;
                } else {
                    x = x_seq + l_seq;
                }
            }
        }
    }
    if (ret == 0) {
        /* At that point the oid has been identified.
         * The next parameter is an octet string containing the key info.
         */
        if (x + 2 > pem_len || pem_buf[x++] != 0x04) {
            ret = -1;
        } else {
            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_key);
            x_key = x;
            x += l_key;
            if (x > pem_len) {
                ret = -1;
            }
        }
    }
    *oid_index = x_oid;
    *oid_length = l_oid;
    *key_index = x_key;
    *key_length = l_key;

    return ret;
}

int ptls_mbedtls_get_der_key(mbedtls_pem_context *pem, mbedtls_pk_type_t *pk_type, const unsigned char *key, size_t keylen,
                             const unsigned char *pwd, size_t pwdlen, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
#endif

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    mbedtls_pem_init(pem);

#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(pem, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", key, pwd, pwdlen,
                                      &len);
    }

    if (ret == 0) {
        *pk_type = MBEDTLS_PK_RSA;
        return ret;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {

        return ret;
    }
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret =
            mbedtls_pem_read_buffer(pem, "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", key, pwd, pwdlen, &len);
    }
    if (ret == 0) {
        *pk_type = MBEDTLS_PK_ECKEY;
        return ret;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", key, NULL, 0, &len);
        if (ret == 0) {
            /* info is unknown */
            return ret;
        } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
            return ret;
        }
    }

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----", key,
                                      NULL, 0, &len);
    }
    if (ret == 0) {
        /* infor is unknown */
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
}
#endif

const ptls_mbedtls_signature_scheme_t *ptls_mbedtls_select_signature_scheme(const ptls_mbedtls_signature_scheme_t *available,
                                                                            const uint16_t *algorithms, size_t num_algorithms)
{
    const ptls_mbedtls_signature_scheme_t *scheme;

    /* select the algorithm, driven by server-isde preference of `available` */
    for (scheme = available; scheme->scheme_id != UINT16_MAX; ++scheme) {
        for (size_t i = 0; i != num_algorithms; ++i) {
            if (algorithms[i] == scheme->scheme_id) {
                return scheme;
            }
        }
    }
    return NULL;
}

int ptls_mbedtls_set_available_schemes(ptls_mbedtls_sign_certificate_t *signer)
{
    int ret = 0;
    psa_algorithm_t algo = psa_get_key_algorithm(&signer->attributes);
    size_t nb_bits = psa_get_key_bits(&signer->attributes);

    switch (algo) {
    case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        signer->schemes = rsa_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256):
        signer->schemes = secp256r1_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384):
        signer->schemes = secp384r1_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512):
        signer->schemes = secp521r1_signature_schemes;
        break;
    case PSA_ALG_ECDSA_BASE:
        switch (nb_bits) {
        case 521:
            signer->schemes = secp521r1_signature_schemes;
            break;
        case 384:
            signer->schemes = secp384r1_signature_schemes;
            break;
        case 256:
            signer->schemes = secp256r1_signature_schemes;
            break;
        default:
            signer->schemes = secp256r1_signature_schemes;
            ret = -1;
            break;
        }
        break;
    case PSA_ALG_ED25519PH:
        signer->schemes = ed25519_signature_schemes;
        break;
    default:
        printf("Unknown algo: %x\n", algo);
        ret = -1;
    }

    return ret;
}

/*
 * Sign a certificate
 * - step1, selected a signature algorithm compatible with the public key algorithm
 *   and with the list specified by the application.
 * - step2, compute the hash with the specified algorithm.
 * - step3, compute the signature of the hash using psa_sign_hash.
 *
 * In the case of RSA, we use the algorithm PSA_ALG_RSA_PKCS1V15_SIGN_RAW, which
 * pads the hash according to PKCS1V15 before doing the private key operation.
 * The implementation of RSA/PKCS1V15 also includes a verification step to protect
 * against key attacks through partial faults.
 *
 * MBEDTLS has a "psa_sign_message" that combines step2 and step3. However, it
 * requires specifying an algorithm type that exactly specifies the signature
 * algorithm, such as "RSA with SHA384". This is not compatible with the
 * "RSA sign raw" algorithm. Instead, we decompose the operation in two steps.
 * There is no performance penalty doing so, as "psa_sign_message" is only
 * a convenience API.
 */

int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async,
                                  uint16_t *selected_algorithm, ptls_buffer_t *outbuf, ptls_iovec_t input,
                                  const uint16_t *algorithms, size_t num_algorithms)
{
    int ret = 0;
    ptls_mbedtls_sign_certificate_t *self =
        (ptls_mbedtls_sign_certificate_t *)(((unsigned char *)_self) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
    /* First, find the set of compatible algorithms */
    const ptls_mbedtls_signature_scheme_t *scheme = ptls_mbedtls_select_signature_scheme(self->schemes, algorithms, num_algorithms);

    if (scheme == NULL) {
        ret = PTLS_ERROR_INCOMPATIBLE_KEY;
    } else {
        /* First prepare the hash */
        unsigned char hash_buffer[PTLS_MAX_DIGEST_SIZE];
        unsigned char *hash_value = NULL;

        size_t hash_length = 0;

        if (scheme->hash_algo == PSA_ALG_NONE) {
            hash_value = input.base;
            hash_length = input.len;
        } else {
            if (psa_hash_compute(scheme->hash_algo, input.base, input.len, hash_buffer, PTLS_MAX_DIGEST_SIZE, &hash_length) !=
                PSA_SUCCESS) {
                ret = PTLS_ERROR_NOT_AVAILABLE;
            } else {
                hash_value = hash_buffer;
            }
        }
        if (ret == 0) {
            psa_algorithm_t sign_algo = psa_get_key_algorithm(&self->attributes);
            size_t nb_bits = psa_get_key_bits(&self->attributes);
            size_t nb_bytes = (nb_bits + 7) / 8;
            if (nb_bits == 0) {
                if (sign_algo == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
                    /* assume at most 4096 bit key */
                    nb_bytes = 512;
                } else {
                    /* Max size assumed, secp521r1 */
                    nb_bytes = 124;
                }
            } else if (sign_algo != PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
                nb_bytes *= 2;
            }
            if ((ret = ptls_buffer_reserve(outbuf, nb_bytes)) == 0) {
                size_t signature_length = 0;
                if (psa_sign_hash(self->key_id, sign_algo, hash_value, hash_length, outbuf->base + outbuf->off, nb_bytes,
                                  &signature_length) != 0) {
                    ret = PTLS_ERROR_INCOMPATIBLE_KEY;
                } else {
                    outbuf->off += signature_length;
                }
            }
        }
    }
    return ret;
}

void ptls_mbedtls_dispose_sign_certificate(ptls_sign_certificate_t *_self)
{
    if (_self != NULL) {
        ptls_mbedtls_sign_certificate_t *self =
            (ptls_mbedtls_sign_certificate_t *)(((unsigned char *)_self) -
                                                offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
        /* Destroy the key */
        psa_destroy_key(self->key_id);
        psa_reset_key_attributes(&self->attributes);
        memset(self, 0, sizeof(ptls_mbedtls_sign_certificate_t));
        free(self);
    }
}
/*
 * An RSa key is encoded in DER as:
 * RSAPrivateKey ::= SEQUENCE {
 *   version             INTEGER,  -- must be 0
 *   modulus             INTEGER,  -- n
 *   publicExponent      INTEGER,  -- e
 *   privateExponent     INTEGER,  -- d
 *   prime1              INTEGER,  -- p
 *   prime2              INTEGER,  -- q
 *   exponent1           INTEGER,  -- d mod (p-1)
 *   exponent2           INTEGER,  -- d mod (q-1)
 *   coefficient         INTEGER,  -- (inverse of q) mod p
 * }
 *
 * The number of key bits is the size in bits of the integer N.
 * We must decode the length in octets of the integer representation,
 * then subtract the number of zeros at the beginning of the data.
 */
int ptls_mbedtls_rsa_get_key_bits(const unsigned char *key_value, size_t key_length, size_t *p_nb_bits)
{
    int ret = 0;
    size_t nb_bytes = 0;
    size_t nb_bits = 0;
    size_t x = 0;

    if (key_length > 16 && key_value[x++] == 0x30) {
        /* get the length of the sequence. */
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(key_value, key_length, &x, &l);

        if (x + l != key_length) {
            ret = -1;
        }
    }

    if (ret == 0 && key_value[x] == 0x02 && key_value[x + 1] == 0x01 && key_value[x + 2] == 0x00 && key_value[x + 3] == 0x02) {
        x += 4;
        ret = ptls_mbedtls_parse_der_length(key_value, key_length, &x, &nb_bytes);
    } else {
        ret = -1;
    }

    if (ret == 0) {
        unsigned char v = key_value[x];
        nb_bits = 8 * nb_bytes;

        if (v == 0) {
            nb_bits -= 8;
        } else {
            while ((v & 0x80) == 0) {
                nb_bits--;
                v <<= 1;
            }
        }
    }
    *p_nb_bits = nb_bits;
    return ret;
}

void ptls_mbedtls_set_rsa_key_attributes(ptls_mbedtls_sign_certificate_t *signer, const unsigned char *key_value, size_t key_length)
{
    size_t nb_bits = 0;
    psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&signer->attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    psa_set_key_type(&signer->attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    if (ptls_mbedtls_rsa_get_key_bits(key_value, key_length, &nb_bits) == 0) {
        psa_set_key_bits(&signer->attributes, nb_bits);
    }
}

int ptls_mbedtls_set_ec_key_attributes(ptls_mbedtls_sign_certificate_t *signer, size_t key_length)
{
    int ret = 0;

    psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&signer->attributes, PSA_ALG_ECDSA_BASE);
    psa_set_key_type(&signer->attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    if (key_length == 32) {
        psa_set_key_algorithm(&signer->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_bits(&signer->attributes, 256);
    } else if (key_length == 48) {
        psa_set_key_algorithm(&signer->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384));
        psa_set_key_bits(&signer->attributes, 384);
    } else if (key_length == 66) {
        psa_set_key_algorithm(&signer->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512));
        psa_set_key_bits(&signer->attributes, 521);
    } else {
        ret = -1;
    }

    return ret;
}

int ptls_mbedtls_load_private_key(ptls_context_t *ctx, char const *pem_fname)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;
    mbedtls_pem_context pem = {0};
    mbedtls_pk_type_t pk_type = 0;
    /* mbedtls_svc_key_id_t key_id = 0; */
    size_t key_length = 0;
    size_t key_index = 0;
    ptls_mbedtls_sign_certificate_t *signer = (ptls_mbedtls_sign_certificate_t *)malloc(sizeof(ptls_mbedtls_sign_certificate_t));

    if (signer == NULL) {
        return (PTLS_ERROR_NO_MEMORY);
    }
    memset(signer, 0, sizeof(ptls_mbedtls_sign_certificate_t));
    signer->attributes = psa_key_attributes_init();

    if ((ret = mbedtls_pk_load_file(pem_fname, &buf, &n)) != 0) {
        if (ret == MBEDTLS_ERR_PK_ALLOC_FAILED) {
            return (PTLS_ERROR_NO_MEMORY);
        } else {
            return (PTLS_ERROR_NOT_AVAILABLE);
        }
    }
    ret = ptls_mbedtls_get_der_key(&pem, &pk_type, buf, n, NULL, 0, NULL, NULL);

    /* We cannot use the platform API:
    mbedtls_zeroize_and_free(buf, n);
    so we do our own thing.
    */
    memset(buf, 0, n);
    free(buf);

    if (ret == 0) {
        if (pk_type == MBEDTLS_PK_RSA) {
            key_length = pem.private_buflen;
            ptls_mbedtls_set_rsa_key_attributes(signer, pem.private_buf, key_length);
        } else if (pk_type == MBEDTLS_PK_ECKEY) {
            ret = ptls_mbedtls_parse_ecdsa_field(pem.private_buf, pem.private_buflen, &key_index, &key_length);
            if (ret == 0) {
                ret = ptls_mbedtls_set_ec_key_attributes(signer, key_length);
            }
        } else if (pk_type == MBEDTLS_PK_NONE) {
            /* TODO: not clear whether MBDED TLS supports ED25519 yet. Probably not. */
            /* Should have option to encode RSA or ECDSA using PKCS8 */
            size_t oid_index = 0;
            size_t oid_length = 0;

            psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
            ret =
                test_parse_private_key_field(pem.private_buf, pem.private_buflen, &oid_index, &oid_length, &key_index, &key_length);
            if (ret == 0) {
                /* need to parse the OID in order to set the parameters */

                if (oid_length == sizeof(ptls_mbedtls_oid_ec_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ec_key, sizeof(ptls_mbedtls_oid_ec_key)) == 0) {
                    ret = ptls_mbedtls_parse_ec_private_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                    if (ret == 0) {
                        ret = ptls_mbedtls_set_ec_key_attributes(signer, key_length);
                    }
                } else if (oid_length == sizeof(ptls_mbedtls_oid_ed25519) &&
                           memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ed25519, sizeof(ptls_mbedtls_oid_ed25519)) == 0) {
                    /* We recognized ED25519 -- PSA_ECC_FAMILY_TWISTED_EDWARDS -- PSA_ALG_ED25519PH */
                    psa_set_key_algorithm(&signer->attributes, PSA_ALG_PURE_EDDSA);
                    psa_set_key_type(&signer->attributes, PSA_ECC_FAMILY_TWISTED_EDWARDS);
                    ret = ptls_mbedtls_parse_eddsa_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                    psa_set_key_bits(&signer->attributes, 256);
                } else if (oid_length == sizeof(ptls_mbedtls_oid_rsa_key) &&
                           memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_rsa_key, sizeof(ptls_mbedtls_oid_rsa_key)) == 0) {
                    /* We recognized RSA */
                    key_length = pem.private_buflen;
                    ptls_mbedtls_set_rsa_key_attributes(signer, pem.private_buf, key_length);
                } else {
                    ret = PTLS_ERROR_NOT_AVAILABLE;
                }
            }
        } else {
            ret = -1;
        }

        if (ret == 0) {
            /* Now that we have the DER or bytes for the key, try import into PSA */
            psa_status_t status = psa_import_key(&signer->attributes, pem.private_buf + key_index, key_length, &signer->key_id);

            if (status != PSA_SUCCESS) {
                ret = -1;
            } else {
                ret = ptls_mbedtls_set_available_schemes(signer);
            }
        }
        /* Free the PEM buffer */
        mbedtls_pem_free(&pem);
    }
    if (ret == 0) {
        signer->super.cb = ptls_mbedtls_sign_certificate;
        ctx->sign_certificate = &signer->super;
    } else {
        /* Dispose of what we have allocated. */
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }
    return ret;
}
