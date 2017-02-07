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
#include <assert.h>
#include <string.h>
#include "picotls.h"
#include "../deps/picotest/picotest.h"
#include "../lib/picotls.c"
#include "test.h"

ptls_context_t *ctx, *ctx_peer;

static ptls_cipher_suite_t *find_aes128gcmsha256(ptls_context_t *ctx)
{
    ptls_cipher_suite_t **cs;
    for (cs = ctx->cipher_suites; *cs != NULL; ++cs)
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            return *cs;
    assert(!"FIXME");
}

static void test_hmac_sha256(void)
{
    /* test vector from RFC 4231 */
    const char *secret = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", *message = "Hi There";
    uint8_t digest[32];

    ptls_hash_context_t *hctx = ptls_hmac_create(find_aes128gcmsha256(ctx)->hash, secret, strlen(secret));
    hctx->update(hctx, message, strlen(message));
    hctx->final(hctx, digest, 0);

    ok(memcmp(digest, "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37"
                      "\x6c\x2e\x32\xcf\xf7",
              32) == 0);
}

static void test_hkdf(void)
{
    ptls_hash_algorithm_t *sha256 = find_aes128gcmsha256(ctx)->hash;
    const char salt[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    const char ikm[] = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    const char info[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";
    uint8_t prk[PTLS_MAX_DIGEST_SIZE];
    uint8_t okm[42];

    ptls_hkdf_extract(sha256, prk, ptls_iovec_init(salt, sizeof(salt) - 1), ptls_iovec_init(ikm, sizeof(ikm) - 1));
    ok(memcmp(prk, "\x07\x77\x09\x36\x2c\x2e\x32\xdf\x0d\xdc\x3f\x0d\xc4\x7b\xba\x63\x90\xb6\xc7\x3b\xb5\x0f\x9c\x31\x22\xec\x84"
                   "\x4a\xd7\xc2\xb3\xe5",
              32) == 0);

    ptls_hkdf_expand(sha256, okm, sizeof(okm), ptls_iovec_init(prk, sha256->digest_size), ptls_iovec_init(info, sizeof(info) - 1));
    ok(memcmp(okm, "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d"
                   "\x56\xec\xc4\xc5\xbf\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65",
              sizeof(okm)) == 0);
}

static void test_ciphersuite(ptls_cipher_suite_t *cs1, ptls_cipher_suite_t *cs2)
{
    const char *traffic_secret = "01234567890123456789012345678901", *src1 = "hello world", *src2 = "good bye, all";
    ptls_aead_context_t *c;
    char enc1[256], enc2[256], dec1[256], dec2[256];
    size_t enc1len, enc2len, dec1len, dec2len;
    int ret;

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret);
    assert(c != NULL);
    ret = ptls_aead_transform(c, enc1, &enc1len, src1, strlen(src1), 0);
    ok(ret == 0);
    ret = ptls_aead_transform(c, enc2, &enc2len, src2, strlen(src2), 0);
    ok(ret == 0);
    ptls_aead_free(c);

    /* decrypt */
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret);
    assert(c != NULL);
    ret = ptls_aead_transform(c, dec1, &dec1len, enc1, enc1len, 0);
    ok(ret == 0);
    ret = ptls_aead_transform(c, dec2, &dec2len, enc2, enc2len, 0);
    ok(ret == 0);
    ptls_aead_free(c);

    /* compare */
    ok(strlen(src1) + 1 == dec1len);
    ok(memcmp(src1, dec1, dec1len) == 0);
    ok(strlen(src2) + 1 == dec2len);
    ok(memcmp(src2, dec2, dec2len) == 0);

    /* alter and decrypt to detect failure */
    enc1[0] ^= 1;
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret);
    assert(c != NULL);
    ret = ptls_aead_transform(c, dec1, &dec1len, enc1, enc1len, 0);
    ok(ret == PTLS_ALERT_BAD_RECORD_MAC);
    ptls_aead_free(c);
}

static void test_aes128gcm(void)
{
    test_ciphersuite(find_aes128gcmsha256(ctx), find_aes128gcmsha256(ctx_peer));
}

static void test_handshake(ptls_iovec_t ticket, int use_resumption, int use_early_data)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{ticket}};
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed, max_early_data_size = 0;
    int ret;
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n";

    client = ptls_new(ctx, "example.com");
    server = ptls_new(ctx_peer, NULL);
    ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
    ptls_buffer_init(&sbuf, sbuf_small, sizeof(sbuf_small));
    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    if (use_early_data) {
        assert(ctx_peer->max_early_data_size != 0);
        client_hs_prop.client.max_early_data_size = &max_early_data_size;
    }
    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    ok(ret == PTLS_ERROR_HANDSHAKE_IN_PROGRESS);
    ok(cbuf.off != 0);

    if (use_early_data) {
        ok(max_early_data_size == ctx_peer->max_early_data_size);
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);
    }

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(sbuf.off != 0);

    if (use_early_data) {
        ok(consumed < cbuf.off);
        memmove(cbuf.base, cbuf.base + consumed, cbuf.off - consumed);
        cbuf.off -= consumed;

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, decbuf.off) == 0);
        ok(ptls_is_early_data(server));
        cbuf.off = 0;
        decbuf.off = 0;

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        ok(ret == 0);
    } else {
        ok(consumed == cbuf.off);
        cbuf.off = 0;
    }

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(cbuf.off != 0);

    if (use_resumption) {
        ok(consumed < sbuf.off);
        memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
        sbuf.off -= consumed;
    } else {
        ok(consumed == sbuf.off);
        sbuf.off = 0;
    }

    if (!use_early_data) {
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, strlen(req)) == 0);
        ok(!ptls_is_early_data(server));
        decbuf.off = 0;

        ret = ptls_send(server, &sbuf, resp, strlen(resp));
        ok(ret == 0);
    }

    consumed = sbuf.off;
    ret = ptls_receive(client, &decbuf, sbuf.base, &consumed);
    ok(ret == 0);
    ok(consumed == sbuf.off);
    ok(decbuf.off == strlen(resp));
    ok(memcmp(decbuf.base, resp, strlen(resp)) == 0);
    ok(!ptls_is_early_data(client));
    decbuf.off = 0;

    if (use_early_data) {
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(cbuf.off == consumed);
        ok(decbuf.off == 0);
        ok(!ptls_is_early_data(client));
    }

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    ptls_free(server);
}

static ptls_lookup_certificate_t *lc_orig;
size_t lc_callcnt;

static int lookup_certificate(ptls_lookup_certificate_t *self, ptls_t *tls, uint16_t *sign_algorithm,
                              int (**signer)(void *sign_ctx, ptls_buffer_t *outbuf, ptls_iovec_t input), void **signer_data,
                              ptls_iovec_t **certs, size_t *num_certs, const char *server_name,
                              const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
    ++lc_callcnt;
    return lc_orig->cb(lc_orig, tls, sign_algorithm, signer, signer_data, certs, num_certs, server_name, signature_algorithms,
                       num_signature_algorithms);
}

static void test_full_handshake(void)
{
    lc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), 0, 0);
    ok(lc_callcnt == 1);
    test_handshake(ptls_iovec_init(NULL, 0), 0, 0);
    ok(lc_callcnt == 2);
}

static int copy_ticket(ptls_encrypt_ticket_t *self, ptls_t *tls, ptls_buffer_t *dst, ptls_iovec_t src)
{
    int ret;

    if ((ret = ptls_buffer_reserve(dst, src.len)) != 0)
        return ret;
    memcpy(dst->base + dst->off, src.base, src.len);
    dst->off += src.len;

    return 0;
}

static ptls_iovec_t saved_ticket = {NULL};

static int save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t src)
{
    saved_ticket.base = malloc(src.len);
    memcpy(saved_ticket.base, src.base, src.len);
    saved_ticket.len = src.len;
    return 0;
}

static void test_resumption(void)
{
    ptls_encrypt_ticket_t et = {copy_ticket};
    ptls_save_ticket_t st = {save_ticket};

    assert(ctx_peer->ticket_lifetime == 0);
    assert(ctx_peer->max_early_data_size == 0);
    assert(ctx_peer->encrypt_ticket == NULL);
    assert(ctx_peer->decrypt_ticket == NULL);
    assert(ctx_peer->save_ticket == NULL);
    saved_ticket = ptls_iovec_init(NULL, 0);

    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;
    ctx_peer->encrypt_ticket = &et;
    ctx_peer->decrypt_ticket = &et;
    ctx->save_ticket = &st;

    lc_callcnt = 0;
    test_handshake(saved_ticket, 1, 0);
    ok(lc_callcnt == 1);
    ok(saved_ticket.base != NULL);

    /* psk using saved ticket */
    test_handshake(saved_ticket, 1, 0);
    ok(lc_callcnt == 1);

    /* psk-dhe using saved ticket */
    ctx->require_dhe_on_psk = 1;
    test_handshake(saved_ticket, 1, 0);
    ok(lc_callcnt == 1);
    ctx->require_dhe_on_psk = 0;

    /* 0-rtt psk using saved ticket */
    test_handshake(saved_ticket, 1, 1);

    ctx_peer->ticket_lifetime = 0;
    ctx_peer->max_early_data_size = 0;
    ctx_peer->encrypt_ticket = NULL;
    ctx_peer->decrypt_ticket = NULL;
    ctx->save_ticket = NULL;
}

void test_picotls(void)
{
    subtest("hmac-sha256", test_hmac_sha256);
    subtest("hkdf", test_hkdf);
    subtest("aead-aes128gcm", test_aes128gcm);

    ptls_lookup_certificate_t lc = {lookup_certificate};
    lc_orig = ctx_peer->lookup_certificate;
    ctx_peer->lookup_certificate = &lc;

    subtest("full-handshake", test_full_handshake);
    subtest("resumption", test_resumption);

    ctx_peer->lookup_certificate = lc_orig;
}

void test_key_exchange(ptls_key_exchange_algorithm_t *algo)
{
    ptls_key_exchange_context_t *ctx;
    ptls_iovec_t client_pubkey, client_secret, server_pubkey, server_secret;
    int ret;

    /* fail */
    ret = algo->exchange(&server_pubkey, &server_secret, (ptls_iovec_t){NULL});
    ok(ret != 0);

    /* perform ecdh */
    ret = algo->create(&ctx, &client_pubkey);
    ok(ret == 0);
    ret = algo->exchange(&server_pubkey, &server_secret, client_pubkey);
    ok(ret == 0);
    ret = ctx->on_exchange(&ctx, &client_secret, server_pubkey);
    ok(ret == 0);
    ok(client_secret.len == server_secret.len);
    ok(memcmp(client_secret.base, server_secret.base, client_secret.len) == 0);

    free(client_secret.base);
    free(server_pubkey.base);
    free(server_secret.base);
}
