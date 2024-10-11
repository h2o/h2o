/*
 * Copyright (c) 2016,2017 DeNA Co., Ltd., Kazuho Oku, Fastly
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
#ifndef util_h
#define util_h

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <openssl/pem.h>
#include "picotls/pembase64.h"
#include "picotls/openssl.h"

static inline void load_certificate_chain(ptls_context_t *ctx, const char *fn)
{
    if (ptls_load_certificates(ctx, (char *)fn) != 0) {
        fprintf(stderr, "failed to load certificate:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
}

static inline void load_raw_public_key(ptls_iovec_t *raw_public_key, char const *cert_pem_file)
{
    size_t count;
    if (ptls_load_pem_objects(cert_pem_file, "PUBLIC KEY", raw_public_key, 1, &count) != 0) {
        fprintf(stderr, "failed to load public key:%s:%s\n", cert_pem_file, strerror(errno));
        exit(1);
    }
}

static inline void load_private_key(ptls_context_t *ctx, const char *fn)
{
    static ptls_openssl_sign_certificate_t sc;
    FILE *fp;
    EVP_PKEY *pkey;

    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (pkey == NULL) {
        fprintf(stderr, "failed to read private key from file:%s\n", fn);
        exit(1);
    }

    ptls_openssl_init_sign_certificate(&sc, pkey);
    EVP_PKEY_free(pkey);

    ctx->sign_certificate = &sc.super;
}

struct st_util_save_ticket_t {
    ptls_save_ticket_t super;
    char fn[MAXPATHLEN];
};

static int util_save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src)
{
    struct st_util_save_ticket_t *self = (struct st_util_save_ticket_t *)_self;
    FILE *fp;

    if ((fp = fopen(self->fn, "wb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", self->fn, strerror(errno));
        return PTLS_ERROR_LIBRARY;
    }
    fwrite(src.base, 1, src.len, fp);
    fclose(fp);

    return 0;
}

static inline void setup_session_file(ptls_context_t *ctx, ptls_handshake_properties_t *hsprop, const char *fn)
{
    static struct st_util_save_ticket_t st;
    FILE *fp;

    /* setup save_ticket callback */
    strcpy(st.fn, fn);
    st.super.cb = util_save_ticket_cb;
    ctx->save_ticket = &st.super;

    /* load session ticket if possible */
    if ((fp = fopen(fn, "rb")) != NULL) {
        static uint8_t ticket[16384];
        size_t ticket_size = fread(ticket, 1, sizeof(ticket), fp);
        if (ticket_size == 0 || !feof(fp)) {
            fprintf(stderr, "failed to load ticket from file:%s\n", fn);
            exit(1);
        }
        fclose(fp);
        hsprop->client.session_ticket = ptls_iovec_init(ticket, ticket_size);
    }
}

static inline X509_STORE *init_cert_store(char const *crt_file)
{
    int ret = 0;
    X509_STORE *store = X509_STORE_new();

    if (store != NULL) {
        X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        ret = X509_LOOKUP_load_file(lookup, crt_file, X509_FILETYPE_PEM);
        if (ret != 1) {
            fprintf(stderr, "Cannot load store (%s), ret = %d\n", crt_file, ret);
            X509_STORE_free(store);
            exit(1);
        }
    } else {
        fprintf(stderr, "Cannot get a new X509 store\n");
        exit(1);
    }

    return store;
}

static inline void setup_verify_certificate(ptls_context_t *ctx, const char *ca_file)
{
    static ptls_openssl_verify_certificate_t vc;
    ptls_openssl_init_verify_certificate(&vc, ca_file != NULL ? init_cert_store(ca_file) : NULL);
    ctx->verify_certificate = &vc.super;
}

static inline void setup_raw_pubkey_verify_certificate(ptls_context_t *ctx, EVP_PKEY *pubkey)
{
    static ptls_openssl_raw_pubkey_verify_certificate_t vc;
    ptls_openssl_raw_pubkey_init_verify_certificate(&vc, pubkey);
    ctx->verify_certificate = &vc.super;
}

struct st_util_log_event_t {
    ptls_log_event_t super;
    FILE *fp;
};

static void log_event_cb(ptls_log_event_t *_self, ptls_t *tls, const char *type, const char *fmt, ...)
{
    struct st_util_log_event_t *self = (struct st_util_log_event_t *)_self;
    char randomhex[PTLS_HELLO_RANDOM_SIZE * 2 + 1];
    va_list args;

    ptls_hexdump(randomhex, ptls_get_client_random(tls).base, PTLS_HELLO_RANDOM_SIZE);
    fprintf(self->fp, "%s %s ", type, randomhex);

    va_start(args, fmt);
    vfprintf(self->fp, fmt, args);
    va_end(args);

    fprintf(self->fp, "\n");
    fflush(self->fp);
}

static inline void setup_log_event(ptls_context_t *ctx, const char *fn)
{
    static struct st_util_log_event_t ls;

    if ((ls.fp = fopen(fn, "at")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    ls.super.cb = log_event_cb;
    ctx->log_event = &ls.super;
}

/* single-entry session cache */
struct st_util_session_cache_t {
    ptls_encrypt_ticket_t super;
    uint8_t id[32];
    ptls_iovec_t data;
};

static int encrypt_ticket_cb(ptls_encrypt_ticket_t *_self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    struct st_util_session_cache_t *self = (struct st_util_session_cache_t *)_self;
    int ret;

    if (is_encrypt) {

        /* replace the cached entry along with a newly generated session id */
        free(self->data.base);
        if ((self->data.base = (uint8_t *)malloc(src.len)) == NULL)
            return PTLS_ERROR_NO_MEMORY;

        ptls_get_context(tls)->random_bytes(self->id, sizeof(self->id));
        memcpy(self->data.base, src.base, src.len);
        self->data.len = src.len;

        /* store the session id in buffer */
        if ((ret = ptls_buffer_reserve(dst, sizeof(self->id))) != 0)
            return ret;
        memcpy(dst->base + dst->off, self->id, sizeof(self->id));
        dst->off += sizeof(self->id);

    } else {

        /* check if session id is the one stored in cache */
        if (src.len != sizeof(self->id))
            return PTLS_ERROR_SESSION_NOT_FOUND;
        if (memcmp(self->id, src.base, sizeof(self->id)) != 0)
            return PTLS_ERROR_SESSION_NOT_FOUND;

        /* return the cached value */
        if ((ret = ptls_buffer_reserve(dst, self->data.len)) != 0)
            return ret;
        memcpy(dst->base + dst->off, self->data.base, self->data.len);
        dst->off += self->data.len;
    }

    return 0;
}

static inline void setup_session_cache(ptls_context_t *ctx)
{
    static struct st_util_session_cache_t sc;

    sc.super.cb = encrypt_ticket_cb;

    ctx->ticket_lifetime = 86400;
    ctx->max_early_data_size = 8192;
    ctx->encrypt_ticket = &sc.super;
}

static struct {
    ptls_iovec_t config_list;
    struct {
        struct {
            ptls_hpke_kem_t *kem;
            ptls_key_exchange_context_t *ctx;
        } list[16];
        size_t count;
    } keyex;
    struct {
        ptls_iovec_t configs;
        char *fn;
    } retry;
} ech;

static ptls_aead_context_t *ech_create_opener(ptls_ech_create_opener_t *self, ptls_hpke_kem_t **kem,
                                              ptls_hpke_cipher_suite_t **cipher, ptls_t *tls, uint8_t config_id,
                                              ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc, ptls_iovec_t info_prefix)
{
    const uint8_t *src = ech.config_list.base, *const end = src + ech.config_list.len;
    size_t index = 0;
    int ret = 0;

    /* look for the cipher implementation; this should better be specific to each ECHConfig (as each of them may advertise different
     * set of values) */
    *cipher = NULL;
    for (size_t i = 0; ptls_openssl_hpke_cipher_suites[i] != NULL; ++i) {
        if (ptls_openssl_hpke_cipher_suites[i]->id.kdf == cipher_id.kdf &&
            ptls_openssl_hpke_cipher_suites[i]->id.aead == cipher_id.aead) {
            *cipher = ptls_openssl_hpke_cipher_suites[i];
            break;
        }
    }
    if (*cipher == NULL)
        goto Exit;

    ptls_decode_open_block(src, end, 2, {
        uint16_t version;
        if ((ret = ptls_decode16(&version, &src, end)) != 0)
            goto Exit;
        do {
            ptls_decode_open_block(src, end, 2, {
                if (src == end) {
                    ret = PTLS_ALERT_DECODE_ERROR;
                    goto Exit;
                }
                if (*src == config_id) {
                    /* this is the ECHConfig that we have been looking for */
                    if (index >= ech.keyex.count) {
                        fprintf(stderr, "ECH key missing for config %zu\n", index);
                        return NULL;
                    }
                    uint8_t *info = malloc(info_prefix.len + end - (src - 4));
                    memcpy(info, info_prefix.base, info_prefix.len);
                    memcpy(info + info_prefix.len, src - 4, end - (src - 4));
                    ptls_aead_context_t *aead;
                    ptls_hpke_setup_base_r(ech.keyex.list[index].kem, *cipher, ech.keyex.list[index].ctx, &aead, enc,
                                           ptls_iovec_init(info, info_prefix.len + end - (src - 4)));
                    free(info);
                    *kem = ech.keyex.list[index].kem;
                    return aead;
                }
                ++index;
                src = end;
            });
        } while (src != end);
    });

Exit:
    if (ret != 0)
        fprintf(stderr, "ECH decode error:%d\n", ret);
    return NULL;
}

static void ech_save_retry_configs(void)
{
    if (ech.retry.configs.base == NULL)
        return;

    FILE *fp;
    if ((fp = fopen(ech.retry.fn, "wt")) == NULL) {
        fprintf(stderr, "failed to write to ECH config file:%s:%s\n", ech.retry.fn, strerror(errno));
        exit(1);
    }
    fwrite(ech.retry.configs.base, 1, ech.retry.configs.len, fp);
    fclose(fp);
}

static ptls_iovec_t load_file(const char *fn)
{
    FILE *fp;
    ptls_iovec_t buf;

    if ((fp = fopen(fn, "rt")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    buf.len = 65536;
    if ((buf.base = malloc(buf.len)) == NULL) {
        fprintf(stderr, "no memory\n");
        abort();
    }
    buf.len = fread(buf.base, 1, buf.len, fp);
    fclose(fp);

    return buf;
}

static void ech_setup_configs(const char *fn)
{
    ech.config_list = load_file(fn);
    ech.retry.fn = strdup(fn);
}

static void ech_setup_key(ptls_context_t *ctx, const char *fn)
{
    FILE *fp;
    EVP_PKEY *pkey;
    int ret;

    if ((fp = fopen(fn, "rt")) == NULL) {
        fprintf(stderr, "failed to open ECH private key file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "failed to load private key from file:%s\n", fn);
        exit(1);
    }
    if ((ret = ptls_openssl_create_key_exchange(&ech.keyex.list[ech.keyex.count].ctx, pkey)) != 0) {
        fprintf(stderr, "failed to load private key from file:%s:picotls-error:%d", fn, ret);
        exit(1);
    }
    EVP_PKEY_free(pkey);
    fclose(fp);

    for (size_t i = 0; ptls_openssl_hpke_kems[i] != NULL; ++i) {
        if (ptls_openssl_hpke_kems[i]->keyex == ech.keyex.list[ech.keyex.count].ctx->algo) {
            ech.keyex.list[ech.keyex.count].kem = ptls_openssl_hpke_kems[i];
            break;
        }
    }
    if (ech.keyex.list[ech.keyex.count].kem == NULL) {
        fprintf(stderr, "kem unknown for private key:%s\n", fn);
        exit(1);
    }

    ++ech.keyex.count;

    static ptls_ech_create_opener_t opener = {.cb = ech_create_opener};
    ctx->ech.server.create_opener = &opener;
}

static inline int resolve_address(struct sockaddr *sa, socklen_t *salen, const char *host, const char *port, int family, int type,
                                  int proto)
{
    struct addrinfo hints, *res;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((err = getaddrinfo(host, port, &hints, &res)) != 0 || res == NULL) {
        fprintf(stderr, "failed to resolve address:%s:%s:%s\n", host, port,
                err != 0 ? gai_strerror(err) : "getaddrinfo returned NULL");
        return -1;
    }

    memcpy(sa, res->ai_addr, res->ai_addrlen);
    *salen = res->ai_addrlen;

    freeaddrinfo(res);
    return 0;
}

static inline int normalize_txt(uint8_t *p, size_t len)
{
    uint8_t *const end = p + len, *dst = p;

    if (p == end)
        return 0;

    do {
        size_t block_len = *p++;
        if (end - p < block_len)
            return 0;
        memmove(dst, p, block_len);
        dst += block_len;
        p += block_len;
    } while (p != end);
    *dst = '\0';

    return 1;
}

/* The ptls_repeat_while_eintr macro will repeat a function call (block) if it is interrupted (EINTR) before completion. If failing
 * for other reason, the macro executes the exit block, such as either { break; } or { goto Fail; }.
 */
#ifdef _WINDOWS
#define repeat_while_eintr(expr, exit_block)                                                                                       \
    while ((expr) < 0) {                                                                                                           \
        exit_block;                                                                                                                \
    }
#else
#define repeat_while_eintr(expr, exit_block)                                                                                       \
    while ((expr) < 0) {                                                                                                           \
        if (errno == EINTR)                                                                                                        \
            continue;                                                                                                              \
        exit_block;                                                                                                                \
    }
#endif

#endif
