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

static ptls_cipher_suite_t *find_cipher(ptls_context_t *ctx, uint16_t id)
{
    ptls_cipher_suite_t **cs;
    for (cs = ctx->cipher_suites; *cs != NULL; ++cs)
        if ((*cs)->id == id)
            return *cs;
    return NULL;
}

static void test_hmac_sha256(void)
{
    /* test vector from RFC 4231 */
    const char *secret = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", *message = "Hi There";
    uint8_t digest[32];

    ptls_hash_context_t *hctx =
        ptls_hmac_create(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->hash, secret, strlen(secret));
    hctx->update(hctx, message, strlen(message));
    hctx->final(hctx, digest, 0);

    ok(memcmp(digest, "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37"
                      "\x6c\x2e\x32\xcf\xf7",
              32) == 0);
}

static void test_hkdf(void)
{
    ptls_hash_algorithm_t *sha256 = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->hash;
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

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret);
    assert(c != NULL);
    ptls_aead_encrypt_init(c, 0, NULL, 0);
    enc1len = ptls_aead_encrypt_update(c, enc1, src1, strlen(src1));
    enc1len += ptls_aead_encrypt_final(c, enc1 + enc1len);
    ptls_aead_encrypt_init(c, 1, NULL, 0);
    enc2len = ptls_aead_encrypt_update(c, enc2, src2, strlen(src2));
    enc2len += ptls_aead_encrypt_final(c, enc2 + enc2len);
    ptls_aead_free(c);

    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret);
    assert(c != NULL);

    /* decrypt and compare */
    dec1len = ptls_aead_decrypt(c, dec1, enc1, enc1len, 0, NULL, 0);
    ok(dec1len != SIZE_MAX);
    dec2len = ptls_aead_decrypt(c, dec2, enc2, enc2len, 1, NULL, 0);
    ok(dec2len != SIZE_MAX);
    ok(strlen(src1) == dec1len);
    ok(memcmp(src1, dec1, dec1len) == 0);
    ok(strlen(src2) == dec2len);
    ok(memcmp(src2, dec2, dec2len - 1) == 0);

    /* alter and decrypt to detect failure */
    enc1[0] ^= 1;
    dec1len = ptls_aead_decrypt(c, dec1, enc1, enc1len, 0, NULL, 0);
    ok(dec1len == SIZE_MAX);

    ptls_aead_free(c);
}

static void test_aad_ciphersuite(ptls_cipher_suite_t *cs1, ptls_cipher_suite_t *cs2)
{
    const char *traffic_secret = "01234567890123456789012345678901", *src = "hello world", *aad = "my true aad";
    ptls_aead_context_t *c;
    char enc[256], dec[256];
    size_t enclen, declen;

    /* encrypt */
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret);
    assert(c != NULL);
    ptls_aead_encrypt_init(c, 123, aad, strlen(aad));
    enclen = ptls_aead_encrypt_update(c, enc, src, strlen(src));
    enclen += ptls_aead_encrypt_final(c, enc + enclen);
    ptls_aead_free(c);

    /* decrypt */
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret);
    assert(c != NULL);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, aad, strlen(aad));
    ok(declen == strlen(src));
    ok(memcmp(src, dec, declen) == 0);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, "my fake aad", strlen(aad));
    ok(declen == SIZE_MAX);
    ptls_aead_free(c);
}

static void test_aes128gcm(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    test_ciphersuite(cs, cs_peer);
    test_aad_ciphersuite(cs, cs_peer);
}

static void test_chacha20poly1305(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
    }
}

static struct {
    struct {
        uint8_t buf[32];
        size_t len;
        int is_end_of_record;
    } vec[16];
    size_t count;
} test_fragmented_message_queue = {{{{0}}}};

static int test_fragmented_message_record(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message, int is_end_of_record,
                                          ptls_handshake_properties_t *properties)
{
    memcpy(test_fragmented_message_queue.vec[test_fragmented_message_queue.count].buf, message.base, message.len);
    test_fragmented_message_queue.vec[test_fragmented_message_queue.count].len = message.len;
    test_fragmented_message_queue.vec[test_fragmented_message_queue.count].is_end_of_record = is_end_of_record;
    ++test_fragmented_message_queue.count;

    return 0;
}

static void test_fragmented_message(void)
{
    ptls_t tls = {NULL};
    struct st_ptls_record_t rec = {PTLS_CONTENT_TYPE_HANDSHAKE, 0x0301};
    int ret;

#define SET_RECORD(lit)                                                                                                            \
    do {                                                                                                                           \
        rec.length = sizeof(lit) - 1;                                                                                              \
        rec.fragment = (const uint8_t *)(lit);                                                                                     \
    } while (0)

    /* not fragmented */
    test_fragmented_message_queue.count = 0;
    SET_RECORD("\x01\x00\x00\x03"
               "abc");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == 0);
    ok(test_fragmented_message_queue.count == 1);
    ok(test_fragmented_message_queue.vec[0].len == rec.length);
    ok(memcmp(test_fragmented_message_queue.vec[0].buf, rec.fragment, rec.length) == 0);
    ok(test_fragmented_message_queue.vec[0].is_end_of_record);
    ok(tls.recvbuf.mess.base == NULL);

    /* fragmented */
    test_fragmented_message_queue.count = 0;
    SET_RECORD("\x01\x00\x00\x03"
               "a");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == 0);
    ok(tls.recvbuf.mess.base != NULL);
    ok(test_fragmented_message_queue.count == 0);
    SET_RECORD("bc\x02\x00\x00\x02"
               "de"
               "\x03");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == 0);
    ok(test_fragmented_message_queue.count == 2);
    ok(test_fragmented_message_queue.vec[0].len == 7);
    ok(memcmp(test_fragmented_message_queue.vec[0].buf, "\x01\x00\x00\x03"
                                                        "abc",
              7) == 0);
    ok(!test_fragmented_message_queue.vec[0].is_end_of_record);
    ok(test_fragmented_message_queue.vec[1].len == 6);
    ok(memcmp(test_fragmented_message_queue.vec[1].buf, "\x02\x00\x00\x02"
                                                        "de",
              6) == 0);
    ok(!test_fragmented_message_queue.vec[1].is_end_of_record);
    SET_RECORD("\x00\x00\x03"
               "end");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == 0);
    ok(tls.recvbuf.mess.base == NULL);
    ok(test_fragmented_message_queue.count == 3);
    ok(test_fragmented_message_queue.vec[2].len == 7);
    ok(memcmp(test_fragmented_message_queue.vec[2].buf, "\x03\x00\x00\x03"
                                                        "end",
              7) == 0);
    ok(test_fragmented_message_queue.vec[2].is_end_of_record);

#undef SET_RECORD
}

static int save_client_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_iovec_t server_name, const ptls_iovec_t *protocols,
                             size_t num_protocols, const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
    ptls_set_server_name(tls, (const char *)server_name.base, server_name.len);
    ptls_set_negotiated_protocol(tls, (const char *)protocols[0].base, protocols[0].len);
    return 0;
}

enum { TEST_HANDSHAKE_FULL, TEST_HANDSHAKE_HRR, TEST_HANDSHAKE_RESUME, TEST_HANDSHAKE_EARLY_DATA };

static void test_handshake(ptls_iovec_t ticket, int mode, int check_ch)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ticket}}};
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed, max_early_data_size = 0;
    int ret;
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    const char *resp = "HTTP/1.0 200 OK\r\n\r\nhello world\n";

    client = ptls_new(ctx, 0);
    server = ptls_new(ctx_peer, 1);
    ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
    ptls_buffer_init(&sbuf, sbuf_small, sizeof(sbuf_small));
    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    if (check_ch) {
        static ptls_on_client_hello_t cb = {save_client_hello};
        ctx_peer->on_client_hello = &cb;
        static const ptls_iovec_t protocols[] = {{(uint8_t *)"h2", 2}, {(uint8_t *)"http/1.1", 8}};
        client_hs_prop.client.negotiated_protocols.list = protocols;
        client_hs_prop.client.negotiated_protocols.count = sizeof(protocols) / sizeof(protocols[0]);
        ptls_set_server_name(client, "example.com", 0);
    }

    switch (mode) {
    case TEST_HANDSHAKE_HRR:
        client_hs_prop.client.negotiate_before_key_exchange = 1;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        assert(ctx_peer->max_early_data_size != 0);
        client_hs_prop.client.max_early_data_size = &max_early_data_size;
        break;
    }

    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);

    if (mode == TEST_HANDSHAKE_HRR) {
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(cbuf.off == consumed);
        ok(sbuf.off != 0);
        cbuf.off = 0;
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_hs_prop);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(sbuf.off == consumed);
        ok(cbuf.off != 0);
        sbuf.off = 0;
    }

    if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        ok(max_early_data_size == ctx_peer->max_early_data_size);
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);
    }

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(sbuf.off != 0);
    if (check_ch) {
        ok(ptls_get_server_name(server) != NULL);
        ok(strcmp(ptls_get_server_name(server), "example.com") == 0);
        ok(ptls_get_negotiated_protocol(server) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(server), "h2") == 0);
    } else {
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        ok(consumed < cbuf.off);
        memmove(cbuf.base, cbuf.base + consumed, cbuf.off - consumed);
        cbuf.off -= consumed;

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, decbuf.off) == 0);
        ok(!ptls_handshake_is_complete(server));
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
    if (check_ch) {
        ok(ptls_get_server_name(client) != NULL);
        ok(strcmp(ptls_get_server_name(client), "example.com") == 0);
        ok(ptls_get_negotiated_protocol(client) != NULL);
        ok(strcmp(ptls_get_negotiated_protocol(client), "h2") == 0);
    } else {
        ok(ptls_get_server_name(server) == NULL);
        ok(ptls_get_negotiated_protocol(server) == NULL);
    }

    if (mode >= TEST_HANDSHAKE_RESUME) {
        ok(consumed < sbuf.off);
        memmove(sbuf.base, sbuf.base + consumed, sbuf.off - consumed);
        sbuf.off -= consumed;
    } else {
        ok(consumed == sbuf.off);
        sbuf.off = 0;
    }

    if (mode != TEST_HANDSHAKE_EARLY_DATA) {
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);

        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(consumed == cbuf.off);
        ok(decbuf.off == strlen(req));
        ok(memcmp(decbuf.base, req, strlen(req)) == 0);
        ok(ptls_handshake_is_complete(server));
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
    ok(ptls_handshake_is_complete(client));
    decbuf.off = 0;

    if (mode == TEST_HANDSHAKE_EARLY_DATA) {
        consumed = cbuf.off;
        ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
        ok(ret == 0);
        ok(cbuf.off == consumed);
        ok(decbuf.off == 0);
        ok(ptls_handshake_is_complete(client));
    }

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
    ptls_free(client);
    ptls_free(server);

    if (check_ch)
        ctx_peer->on_client_hello = NULL;
}

static ptls_sign_certificate_t *sc_orig;
size_t sc_callcnt;

static int sign_certificate(ptls_sign_certificate_t *self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *output,
                            ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ++sc_callcnt;
    return sc_orig->cb(sc_orig, tls, selected_algorithm, output, input, algorithms, num_algorithms);
}

static void test_full_handshake(void)
{
    sc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_FULL, 0);
    ok(sc_callcnt == 1);
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_FULL, 0);
    ok(sc_callcnt == 2);
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_FULL, 1);
    ok(sc_callcnt == 3);
}

static void test_hrr_handshake(void)
{
    sc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR, 0);
    ok(sc_callcnt == 1);
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

    sc_callcnt = 0;
    test_handshake(saved_ticket, TEST_HANDSHAKE_RESUME, 0);
    ok(sc_callcnt == 1);
    ok(saved_ticket.base != NULL);

    /* psk using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_RESUME, 0);
    ok(sc_callcnt == 1);

    /* psk-dhe using saved ticket */
    ctx->require_dhe_on_psk = 1;
    test_handshake(saved_ticket, TEST_HANDSHAKE_RESUME, 0);
    ok(sc_callcnt == 1);
    ctx->require_dhe_on_psk = 0;

    /* 0-rtt psk using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_EARLY_DATA, 0);

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
    subtest("aes128gcm", test_aes128gcm);
    subtest("chacha20poly1305", test_chacha20poly1305);

    subtest("fragmented-message", test_fragmented_message);

    ptls_sign_certificate_t sc = {sign_certificate};
    sc_orig = ctx_peer->sign_certificate;
    ctx_peer->sign_certificate = &sc;

    subtest("full-handshake", test_full_handshake);
    subtest("hrr-handshake", test_hrr_handshake);
    subtest("resumption", test_resumption);

    ctx_peer->sign_certificate = sc_orig;
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
