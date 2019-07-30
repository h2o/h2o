/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifdef _WINDOWS
#include "..\picotls\wincompat.h"
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#pragma warning(disable : 4996)
#else
#include <strings.h>
#endif
#include <time.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/pembase64.h"
#include "picotls/openssl.h"

static int emit_esni(ptls_key_exchange_context_t **key_exchanges, ptls_cipher_suite_t **cipher_suites, uint16_t padded_length,
                     uint64_t not_before, uint64_t lifetime, char const *published_sni, char const *file_output)
{
    ptls_buffer_t buf;
    ptls_key_exchange_context_t *ctx[256] = {NULL};
    int ret;

    ptls_buffer_init(&buf, "", 0);

    ptls_buffer_push16(&buf, PTLS_ESNI_VERSION_DRAFT03);
    ptls_buffer_push(&buf, 0, 0, 0, 0); /* checksum, filled later */
    if (published_sni != NULL) {
        ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, published_sni, strlen(published_sni)); });
    } else {
        ptls_buffer_push16(&buf, 0);
    }
    ptls_buffer_push_block(&buf, 2, {
        size_t i;
        for (i = 0; key_exchanges[i] != NULL; ++i) {
            ptls_buffer_push16(&buf, key_exchanges[i]->algo->id);
            ptls_buffer_push_block(&buf, 2,
                                   { ptls_buffer_pushv(&buf, key_exchanges[i]->pubkey.base, key_exchanges[i]->pubkey.len); });
        }
    });
    ptls_buffer_push_block(&buf, 2, {
        size_t i;
        for (i = 0; cipher_suites[i] != NULL; ++i)
            ptls_buffer_push16(&buf, cipher_suites[i]->id);
    });
    ptls_buffer_push16(&buf, padded_length);
    ptls_buffer_push64(&buf, not_before);
    ptls_buffer_push64(&buf, not_before + lifetime - 1);
    ptls_buffer_push_block(&buf, 2, {});
    { /* fill checksum */
        uint8_t d[PTLS_SHA256_DIGEST_SIZE];
        ptls_calc_hash(&ptls_openssl_sha256, d, buf.base, buf.off);
        memcpy(buf.base + 2, d, 4);
    }

    if (file_output != NULL) {
        FILE *fo = fopen(file_output, "wb");
        if (fo == NULL) {
            fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
            goto Exit;
        } else {
            fwrite(buf.base, 1, buf.off, fo);
            fclose(fo);
        }
    } else {
        /* emit the structure to stdout */
        fwrite(buf.base, 1, buf.off, stdout);
        fflush(stdout);
    }

    ret = 0;
Exit : {
    size_t i;
    for (i = 0; ctx[i] != NULL; ++i)
        ctx[i]->on_exchange(ctx + i, 1, NULL, ptls_iovec_init(NULL, 0));
}
    ptls_buffer_dispose(&buf);
    return ret;
}

static void usage(const char *cmd, int status)
{
    printf("picotls-esni - generates an ESNI Resource Record\n"
           "\n"
           "Usage: %s [options]\n"
           "Options:\n"
           "  -n <published-sni>  published sni value\n"
           "  -K <key-file>       private key files (repeat the option to include multiple\n"
           "                      keys)\n"
           "  -c <cipher-suite>   aes128-gcm, chacha20-poly1305, ...\n"
           "  -d <days>           number of days until expiration (default: 90)\n"
           "  -p <padded-length>  padded length (default: 260)\n"
           "  -o <output-file>    write output to specified file instead of stdout\n"
           "                      (use on Windows as stdout is not binary there)\n"
           "  -h                  prints this help\n"
           "\n"
           "-c and -x can be used multiple times.\n"
           "\n",
           cmd);
    exit(status);
}

int main(int argc, char **argv)
{
    char const *published_sni = NULL;
    char const *file_output = NULL;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    struct {
        ptls_key_exchange_context_t *elements[256];
        size_t count;
    } key_exchanges = {{NULL}, 0};
    struct {
        ptls_cipher_suite_t *elements[256];
        size_t count;
    } cipher_suites = {{NULL}, 0};
    uint16_t padded_length = 260;
    uint64_t lifetime = 90 * 86400;

    int ch;

    while ((ch = getopt(argc, argv, "n:K:c:d:p:o:h")) != -1) {
        switch (ch) {
        case 'n':
            published_sni = optarg;
            break;
        case 'K': {
            FILE *fp;
            EVP_PKEY *pkey;

            if ((fp = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }

            if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
                fprintf(stderr, "failed to read private key from file:%s:%s\n", optarg, strerror(errno));
                exit(1);
            }
            fclose(fp);
            if (ptls_openssl_create_key_exchange(key_exchanges.elements + key_exchanges.count++, pkey) != 0) {
                fprintf(stderr, "unknown type of private key found in file:%s\n", optarg);
                exit(1);
            }
            EVP_PKEY_free(pkey);
        } break;
        case 'c': {
            size_t i;
            for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
                if (strcasecmp(ptls_openssl_cipher_suites[i]->aead->name, optarg) == 0)
                    break;
            if (ptls_openssl_cipher_suites[i] == NULL) {
                fprintf(stderr, "unknown cipher-suite: %s\n", optarg);
                exit(1);
            }
            cipher_suites.elements[cipher_suites.count++] = ptls_openssl_cipher_suites[i];
        } break;
        case 'd':
            if (sscanf(optarg, "%" SCNu64, &lifetime) != 1 || lifetime == 0) {
                fprintf(stderr, "lifetime must be a positive integer\n");
                exit(1);
            }
            lifetime *= 86400; /* convert to seconds */
            break;
        case 'p':
#ifdef _WINDOWS
            if (sscanf_s(optarg, "%" SCNu16, &padded_length) != 1 || padded_length == 0) {
                fprintf(stderr, "padded length must be a positive integer\n");
                exit(1);
            }
#else
            if (sscanf(optarg, "%" SCNu16, &padded_length) != 1 || padded_length == 0) {
                fprintf(stderr, "padded length must be a positive integer\n");
                exit(1);
            }
#endif
            break;
        case 'o':
            file_output = optarg;
            break;
        case 'h':
            usage(argv[0], 0);
            break;
        default:
            usage(argv[0], 1);
            break;
        }
    }
    if (cipher_suites.count == 0)
        cipher_suites.elements[cipher_suites.count++] = &ptls_openssl_aes128gcmsha256;
    if (key_exchanges.count == 0) {
        fprintf(stderr, "no private key specified\n");
        exit(1);
    }

    argc -= optind;
    argv += optind;

    if (emit_esni(key_exchanges.elements, cipher_suites.elements, padded_length, time(NULL), lifetime, published_sni,
                  file_output) != 0) {
        fprintf(stderr, "failed to generate ESNI private structure.\n");
        exit(1);
    }

    return 0;
}
