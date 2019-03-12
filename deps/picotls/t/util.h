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

static inline void setup_verify_certificate(ptls_context_t *ctx)
{
    static ptls_openssl_verify_certificate_t vc;
    ptls_openssl_init_verify_certificate(&vc, NULL);
    ctx->verify_certificate = &vc.super;
}

static inline void setup_esni(ptls_context_t *ctx, const char *esni_fn, ptls_key_exchange_context_t **key_exchanges)
{
    uint8_t esnikeys[65536];
    size_t esnikeys_len;
    int ret = 0;

    { /* read esnikeys */
        FILE *fp;
        if ((fp = fopen(esni_fn, "rb")) == NULL) {
            fprintf(stderr, "failed to open file:%s:%s\n", esni_fn, strerror(errno));
            exit(1);
        }
        esnikeys_len = fread(esnikeys, 1, sizeof(esnikeys), fp);
        if (esnikeys_len == 0 || !feof(fp)) {
            fprintf(stderr, "failed to load ESNI data from file:%s\n", esni_fn);
            exit(1);
        }
        fclose(fp);
    }

    if ((ctx->esni = malloc(sizeof(*ctx->esni) * 2)) == NULL || (*ctx->esni = malloc(sizeof(**ctx->esni))) == NULL) {
        fprintf(stderr, "no memory\n");
        exit(1);
    }

    if ((ret = ptls_esni_init_context(ctx, ctx->esni[0], ptls_iovec_init(esnikeys, esnikeys_len), key_exchanges)) != 0) {
        fprintf(stderr, "failed to parse ESNI data of file:%s:error=%d\n", esni_fn, ret);
        exit(1);
    }
}

struct st_util_log_event_t {
    ptls_log_event_t super;
    FILE *fp;
};

static void log_event_cb(ptls_log_event_t *_self, ptls_t *tls, const char *type, const char *fmt, ...)
{
    struct st_util_log_event_t *self = (void *)_self;
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

static inline ptls_iovec_t resolve_esni_keys(const char *server_name)
{
    char esni_name[256], *base64;
    uint8_t answer[1024];
    ns_msg msg;
    ns_rr rr;
    ptls_buffer_t decode_buf;
    ptls_base64_decode_state_t ds;
    int answer_len;

    ptls_buffer_init(&decode_buf, "", 0);

    if (snprintf(esni_name, sizeof(esni_name), "_esni.%s", server_name) > sizeof(esni_name) - 1)
        goto Error;
    if ((answer_len = res_query(esni_name, ns_c_in, ns_t_txt, answer, sizeof(answer))) <= 0)
        goto Error;
    if (ns_initparse(answer, answer_len, &msg) != 0)
        goto Error;
    if (ns_msg_count(msg, ns_s_an) < 1)
        goto Error;
    if (ns_parserr(&msg, ns_s_an, 0, &rr) != 0)
        goto Error;
    base64 = (void *)ns_rr_rdata(rr);
    if (!normalize_txt((void *)base64, ns_rr_rdlen(rr)))
        goto Error;

    ptls_base64_decode_init(&ds);
    if (ptls_base64_decode(base64, &ds, &decode_buf) != 0)
        goto Error;
    assert(decode_buf.is_allocated);

    return ptls_iovec_init(decode_buf.base, decode_buf.off);
Error:
    ptls_buffer_dispose(&decode_buf);
    return ptls_iovec_init(NULL, 0);
}

#endif
