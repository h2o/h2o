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
#include <openssl/pem.h>
#include "picotls/openssl.h"

static inline void load_certificate_chain(ptls_context_t *ctx, const char *fn)
{
    if (ptls_load_certificates(ctx, (char *)fn) != 0) {
        fprintf(stderr, "failed to load certificate:%s:%s\n", fn, strerror(errno));
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

static int save_ticket_cb(ptls_save_ticket_t *_self, ptls_t *tls, ptls_iovec_t src)
{
    struct st_util_save_ticket_t *self = (void *)_self;
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
    st.super.cb = save_ticket_cb;
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

static inline void setup_verify_certificate(ptls_context_t *ctx)
{
    static ptls_openssl_verify_certificate_t vc;
    ptls_openssl_init_verify_certificate(&vc, NULL);
    ctx->verify_certificate = &vc.super;
}

struct st_util_log_secret_t {
    ptls_log_secret_t super;
    FILE *fp;
};

static void fprinthex(FILE *fp, ptls_iovec_t vec)
{
    size_t i;
    for (i = 0; i != vec.len; ++i)
        fprintf(fp, "%02x", vec.base[i]);
}

static void log_secret_cb(ptls_log_secret_t *_self, ptls_t *tls, const char *label, ptls_iovec_t secret)
{
    struct st_util_log_secret_t *self = (void *)_self;

    fprintf(self->fp, "%s ", label);
    fprinthex(self->fp, ptls_get_client_random(tls));
    fprintf(self->fp, " ");
    fprinthex(self->fp, secret);
    fprintf(self->fp, "\n");
    fflush(self->fp);
}

static inline void setup_log_secret(ptls_context_t *ctx, const char *fn)
{
    static struct st_util_log_secret_t ls;

    if ((ls.fp = fopen(fn, "at")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        exit(1);
    }
    ls.super.cb = log_secret_cb;
    ctx->log_secret = &ls.super;
}

/* single-entry session cache */
struct st_util_session_cache_t {
    ptls_encrypt_ticket_t super;
    uint8_t id[32];
    ptls_iovec_t data;
};

static int encrypt_ticket_cb(ptls_encrypt_ticket_t *_self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    struct st_util_session_cache_t *self = (void *)_self;
    int ret;

    if (is_encrypt) {

        /* replace the cached entry along with a newly generated session id */
        free(self->data.base);
        if ((self->data.base = malloc(src.len)) == NULL)
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

#endif
