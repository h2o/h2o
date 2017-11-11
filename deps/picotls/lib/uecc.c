/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include "sha2.h"
#include "uECC.h"
#include "uECC_vli.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/asn1.h"
#include "picotls/pembase64.h"

#define TYPE_UNCOMPRESSED_PUBLIC_KEY 4

struct st_secp256r1_key_exhchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE];
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE];
};

static int secp256r1_on_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_secp256r1_key_exhchange_t *ctx = (struct st_secp256r1_key_exhchange_t *)*_ctx;
    uint8_t *secbytes = NULL;
    int ret;

    *_ctx = NULL;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE || peerkey.base[0] != TYPE_UNCOMPRESSED_PUBLIC_KEY) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((secbytes = (uint8_t *)malloc(SECP256R1_SHARED_SECRET_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (!uECC_shared_secret(peerkey.base + 1, ctx->priv, secbytes, uECC_secp256r1())) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    *secret = ptls_iovec_init(secbytes, SECP256R1_SHARED_SECRET_SIZE);
    ret = 0;

Exit:
    if (ret != 0)
        free(secbytes);
    ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
    free(ctx);
    return ret;
}

static int secp256r1_create_key_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *pubkey)
{
    struct st_secp256r1_key_exhchange_t *ctx;

    if ((ctx = (struct st_secp256r1_key_exhchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){secp256r1_on_exchange};
    ctx->pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;
    uECC_make_key(ctx->pub + 1, ctx->priv, uECC_secp256r1());

    *_ctx = &ctx->super;
    *pubkey = ptls_iovec_init(ctx->pub, sizeof(ctx->pub));
    return 0;
}

static int secp256r1_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    uint8_t priv[SECP256R1_PRIVATE_KEY_SIZE], *pub = NULL, *secbytes = NULL;
    int ret;

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE || peerkey.base[0] != TYPE_UNCOMPRESSED_PUBLIC_KEY) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((pub = malloc(SECP256R1_PUBLIC_KEY_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((secbytes = malloc(SECP256R1_SHARED_SECRET_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    pub[0] = TYPE_UNCOMPRESSED_PUBLIC_KEY;
    uECC_make_key(pub + 1, priv, uECC_secp256r1());
    if (!uECC_shared_secret(peerkey.base + 1, priv, secbytes, uECC_secp256r1())) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    *pubkey = ptls_iovec_init(pub, SECP256R1_PUBLIC_KEY_SIZE);
    *secret = ptls_iovec_init(secbytes, SECP256R1_SHARED_SECRET_SIZE);
    ret = 0;

Exit:
    ptls_clear_memory(priv, sizeof(priv));
    if (ret != 0) {
        free(secbytes);
        free(pub);
    }
    return ret;
}

static int secp256r1sha256_sign(ptls_sign_certificate_t *_self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *outbuf,
                                ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ptls_minicrypto_secp256r1sha256_sign_certificate_t *self = (ptls_minicrypto_secp256r1sha256_sign_certificate_t *)_self;
    uint8_t hash[32], sig[64];
    size_t i;
    int ret;

    /* check algorithm */
    for (i = 0; i != num_algorithms; ++i)
        if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
            break;
    if (i == num_algorithms)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    { /* calc hash */
        cf_sha256_context ctx;
        cf_sha256_init(&ctx);
        cf_sha256_update(&ctx, input.base, input.len);
        cf_sha256_digest_final(&ctx, hash);
        ptls_clear_memory(&ctx, sizeof(ctx));
    }

    /* sign */
    uECC_sign(self->key, hash, sizeof(hash), sig, uECC_secp256r1());

    /* encode using DER */
    ptls_buffer_push_asn1_sequence(outbuf, {
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig, 32)) != 0)
            goto Exit;
        if ((ret = ptls_buffer_push_asn1_ubigint(outbuf, sig + 32, 32)) != 0)
            goto Exit;
    });

    *selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
    ret = 0;

Exit:
    ptls_clear_memory(hash, sizeof(hash));
    ptls_clear_memory(sig, sizeof(sig));
    return ret;
}

int ptls_minicrypto_init_secp256r1sha256_sign_certificate(ptls_minicrypto_secp256r1sha256_sign_certificate_t *self,
                                                          ptls_iovec_t key)
{
    if (key.len != sizeof(self->key))
        return PTLS_ERROR_INCOMPATIBLE_KEY;

    self->super.cb = secp256r1sha256_sign;
    memcpy(self->key, key.base, sizeof(self->key));

    return 0;
}

ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1 = {PTLS_GROUP_SECP256R1, secp256r1_create_key_exchange,
                                                           secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_minicrypto_key_exchanges[] = {&ptls_minicrypto_secp256r1, NULL};

/*
 * This function could be declared as static, but we want to access it
 * in the unit tests.
 */
size_t ptls_minicrypto_asn1_decode_private_key(ptls_asn1_pkcs8_private_key_t *pkey, int *decode_error,
                                               ptls_minicrypto_log_ctx_t *log_ctx)
{
    uint8_t *bytes = pkey->vec.base;
    size_t bytes_max = pkey->vec.len;

    /* read the ASN1 messages */
    size_t byte_index = 0;
    uint32_t seq0_length = 0;
    size_t last_byte0;
    uint32_t seq1_length = 0;
    size_t last_byte1 = 0;
    uint32_t oid_length;
    size_t last_oid_byte;
    uint32_t key_data_length;
    size_t key_data_last;

    /* start with sequence */
    byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq0_length, NULL, &last_byte0,
                                                        decode_error, log_ctx);

    if (decode_error == 0 && bytes_max != last_byte0) {
        byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index, 0, log_ctx);
        *decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
    }

    if (*decode_error == 0) {
        /* get first component: version, INTEGER, expect value 0 */
        if (byte_index + 3 > bytes_max) {
            byte_index = ptls_asn1_error_message("Cannot find key version", bytes_max, byte_index, 0, log_ctx);
            *decode_error = PTLS_ERROR_INCORRECT_PEM_KEY_VERSION;
        } else if (bytes[byte_index] != 0x02 || bytes[byte_index + 1] != 0x01 || bytes[byte_index + 2] != 0x00) {
            *decode_error = PTLS_ERROR_INCORRECT_PEM_KEY_VERSION;
            byte_index = ptls_asn1_error_message("Incorrect PEM Version", bytes_max, byte_index, 0, log_ctx);
        } else {
            byte_index += 3;
            if (log_ctx != NULL) {
                log_ctx->fn(log_ctx->ctx, "   Version = 1,\n");
            }
        }
    }

    if (*decode_error == 0) {
        /* open embedded sequence */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq1_length, NULL, &last_byte1,
                                                            decode_error, log_ctx);
    }

    if (*decode_error == 0) {
        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "   Algorithm Identifier:\n");
        }
        /* get length of OID */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte1, byte_index, 0x06, &oid_length, NULL, &last_oid_byte,
                                                            decode_error, log_ctx);

        if (*decode_error == 0) {
            if (log_ctx != NULL) {
                /* print the OID value */
                log_ctx->fn(log_ctx->ctx, "      Algorithm:");
                ptls_asn1_dump_content(bytes + byte_index, oid_length, 0, log_ctx);
                log_ctx->fn(log_ctx->ctx, ",\n");
            }
            pkey->algorithm_index = byte_index;
            pkey->algorithm_length = oid_length;
            byte_index += oid_length;
        }
    }

    if (*decode_error == 0) {
        /* get parameters, ANY */
        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "      Parameters:\n");
        }

        pkey->parameters_index = byte_index;

        pkey->parameters_length =
            ptls_asn1_validation_recursive(bytes + byte_index, last_byte1 - byte_index, decode_error, 2, log_ctx);

        byte_index += pkey->parameters_length;

        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "\n");
        }
        /* close sequence */
        if (byte_index != last_byte1) {
            byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index, 2, log_ctx);
            *decode_error = PTLS_ERROR_BER_ELEMENT_TOO_SHORT;
        }
    }

    /* get octet string, key */
    if (*decode_error == 0) {
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte0, byte_index, 0x04, &key_data_length, NULL,
                                                            &key_data_last, decode_error, log_ctx);

        if (*decode_error == 0) {
            pkey->key_data_index = byte_index;
            pkey->key_data_length = key_data_length;
            byte_index += key_data_length;

            if (log_ctx != NULL) {
                log_ctx->fn(log_ctx->ctx, "   Key data (%d bytes):\n", key_data_length);

                (void)ptls_asn1_validation_recursive(bytes + pkey->key_data_index, key_data_length, decode_error, 1, log_ctx);
                log_ctx->fn(log_ctx->ctx, "\n");
            }
        }
    }

    if (*decode_error == 0 && byte_index != last_byte0) {
        byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index, 0, log_ctx);
        *decode_error = PTLS_ERROR_BER_ELEMENT_TOO_SHORT;
    }

    if (log_ctx != NULL) {
        log_ctx->fn(log_ctx->ctx, "\n");
    }

    return byte_index;
}

static int ptls_pem_parse_private_key(char const *pem_fname, ptls_asn1_pkcs8_private_key_t *pkey,
                                      ptls_minicrypto_log_ctx_t *log_ctx)
{
    size_t nb_keys = 0;
    ptls_iovec_t *list = &pkey->vec;
    int ret = ptls_load_pem_objects(pem_fname, "PRIVATE KEY", &list, 1, &nb_keys);

    if (ret == 0) {
        if (nb_keys != 1) {
            ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
        }
    }

    if (ret == 0 && nb_keys == 1) {
        int decode_error = 0;

        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "\nFound PRIVATE KEY, length = %d bytes\n", (int)pkey->vec.len);
        }

        (void)ptls_minicrypto_asn1_decode_private_key(pkey, &decode_error, log_ctx);

        if (decode_error != 0) {
            ret = decode_error;
        }
    }

    return ret;
}

static const uint8_t ptls_asn1_algorithm_ecdsa[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};

static const uint8_t ptls_asn1_curve_secp256r1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

static int ptls_set_ecdsa_private_key(ptls_context_t *ctx, ptls_asn1_pkcs8_private_key_t *pkey, ptls_minicrypto_log_ctx_t *log_ctx)
{
    uint8_t *bytes = pkey->vec.base + pkey->parameters_index;
    size_t bytes_max = pkey->parameters_length;
    size_t byte_index = 0;
    uint8_t *curve_id = NULL;
    uint32_t curve_id_length = 0;
    int decode_error = 0;
    uint32_t seq_length;
    size_t last_byte = 0;
    uint8_t *ecdsa_key_data = NULL;
    uint32_t ecdsa_key_data_length = 0;
    size_t ecdsa_key_data_last = 0;

    /* We expect the parameters to include just the curve ID */

    byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x06, &curve_id_length, NULL, &last_byte,
                                                        &decode_error, log_ctx);

    if (decode_error == 0 && bytes_max != last_byte) {
        byte_index = ptls_asn1_error_message("Length larger than parameters", bytes_max, byte_index, 0, log_ctx);
        decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
    }

    if (decode_error == 0) {
        curve_id = bytes + byte_index;

        if (log_ctx != NULL) {
            /* print the OID value */
            log_ctx->fn(log_ctx->ctx, "Curve: ");
            ptls_asn1_dump_content(curve_id, curve_id_length, 0, log_ctx);
            log_ctx->fn(log_ctx->ctx, "\n");
        }
    }

    /* We expect the key data to follow the ECDSA structure per RFC 5915 */
    bytes = pkey->vec.base + pkey->key_data_index;
    bytes_max = pkey->key_data_length;
    byte_index = 0;

    /* decode the wrapping sequence */
    if (decode_error == 0) {
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq_length, NULL, &last_byte,
                                                            &decode_error, log_ctx);
    }

    if (decode_error == 0 && bytes_max != last_byte) {
        byte_index = ptls_asn1_error_message("Length larger than key data", bytes_max, byte_index, 0, log_ctx);
        decode_error = PTLS_ERROR_BER_ELEMENT_TOO_SHORT;
    }

    /* verify and skip the version number 1 */
    if (decode_error == 0) {
        /* get first component: version, INTEGER, expect value 0 */
        if (byte_index + 3 > bytes_max) {
            byte_index = ptls_asn1_error_message("Cannot find ECDSA Key Data Version", bytes_max, byte_index, 0, log_ctx);
            decode_error = PTLS_ERROR_INCORRECT_ASN1_ECDSA_KEY_SYNTAX;
        } else if (bytes[byte_index] != 0x02 || bytes[byte_index + 1] != 0x01 || bytes[byte_index + 2] != 0x01) {
            decode_error = PTLS_ERROR_INCORRECT_PEM_ECDSA_KEY_VERSION;
            byte_index = ptls_asn1_error_message("Incorrect ECDSA Key Data Version", bytes_max, byte_index, 0, log_ctx);
        } else {
            byte_index += 3;
            if (log_ctx != NULL) {
                log_ctx->fn(log_ctx->ctx, "ECDSA Version = 1,\n");
            }
        }
    }

    /* obtain the octet string that contains the ECDSA private key */
    if (decode_error == 0) {
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte, byte_index, 0x04, &ecdsa_key_data_length, NULL,
                                                            &ecdsa_key_data_last, &decode_error, log_ctx);

        if (decode_error == 0) {
            ecdsa_key_data = bytes + byte_index;
        }
    }

    /* If everything is fine, associate the ECDSA key with the context */
    if (curve_id_length == sizeof(ptls_asn1_curve_secp256r1) && curve_id != NULL &&
        memcmp(curve_id, ptls_asn1_curve_secp256r1, sizeof(ptls_asn1_curve_secp256r1)) == 0) {
        if (SECP256R1_PRIVATE_KEY_SIZE != ecdsa_key_data_length) {
            decode_error = PTLS_ERROR_INCORRECT_PEM_ECDSA_KEYSIZE;
            if (log_ctx != NULL) {
                /* print the OID value */
                log_ctx->fn(log_ctx->ctx, "Wrong SECP256R1 key length, %d instead of %d.\n", ecdsa_key_data_length,
                            SECP256R1_PRIVATE_KEY_SIZE);
            }
        } else {
            ptls_minicrypto_secp256r1sha256_sign_certificate_t *minicrypto_sign_certificate;

            minicrypto_sign_certificate = (ptls_minicrypto_secp256r1sha256_sign_certificate_t *)malloc(
                sizeof(ptls_minicrypto_secp256r1sha256_sign_certificate_t));

            if (minicrypto_sign_certificate == NULL) {
                decode_error = PTLS_ERROR_NO_MEMORY;
            } else {
                memset(minicrypto_sign_certificate, 0, sizeof(ptls_minicrypto_secp256r1sha256_sign_certificate_t));
                decode_error = ptls_minicrypto_init_secp256r1sha256_sign_certificate(
                    minicrypto_sign_certificate, ptls_iovec_init(ecdsa_key_data, ecdsa_key_data_length));
            }
            if (decode_error == 0) {
                ctx->sign_certificate = &minicrypto_sign_certificate->super;

                if (log_ctx != NULL) {
                    /* print the OID value */
                    log_ctx->fn(log_ctx->ctx, "Initialized SECP512R1 signing key with %d bytes.\n", ecdsa_key_data_length);
                }
            } else if (log_ctx != NULL) {
                log_ctx->fn(log_ctx->ctx, "SECP512R1 init with %d bytes returns %d.\n", ecdsa_key_data_length, decode_error);
            }
        }
    } else {
        decode_error = PTLS_ERROR_INCORRECT_PEM_ECDSA_CURVE;
        if (log_ctx != NULL) {
            /* print the OID value */
            log_ctx->fn(log_ctx->ctx, "Curve is not supported for signatures.\n");
        }
    }

    return decode_error;
}

int ptls_minicrypto_load_private_key(ptls_context_t *ctx, char const *pem_fname)
{
    ptls_asn1_pkcs8_private_key_t pkey = {{0}};
    int ret = ptls_pem_parse_private_key(pem_fname, &pkey, NULL);

    /* Check that this is the expected key type.
    * At this point, the minicrypto library only supports ECDSA keys.
    * In theory, we could add support for RSA keys at some point.
    */
    if (ret == 0) {
        if (pkey.algorithm_length == sizeof(ptls_asn1_algorithm_ecdsa) &&
            memcmp(pkey.vec.base + pkey.algorithm_index, ptls_asn1_algorithm_ecdsa, sizeof(ptls_asn1_algorithm_ecdsa)) == 0) {
            ret = ptls_set_ecdsa_private_key(ctx, &pkey, NULL);
        } else {
            ret = -1;
        }
    }

    return ret;
}
