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
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "picotls/minicrypto.h"
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

static void test_hash(ptls_hash_algorithm_t *hash)
{
    ptls_hash_context_t *hctx = hash->create();
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];

    hctx->final(hctx, digest, PTLS_HASH_FINAL_MODE_FREE);
    ok(memcmp(digest, hash->empty_digest, hash->digest_size) == 0);
}

static void test_sha256(void)
{
    test_hash(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)->hash);
}

static void test_sha384(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);
    if (cs != NULL)
        test_hash(cs->hash);
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
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret, NULL);
    assert(c != NULL);
    ptls_aead_encrypt_init(c, 0, NULL, 0);
    enc1len = ptls_aead_encrypt_update(c, enc1, src1, strlen(src1));
    enc1len += ptls_aead_encrypt_final(c, enc1 + enc1len);
    ptls_aead_encrypt_init(c, 1, NULL, 0);
    enc2len = ptls_aead_encrypt_update(c, enc2, src2, strlen(src2));
    enc2len += ptls_aead_encrypt_final(c, enc2 + enc2len);
    ptls_aead_free(c);

    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret, NULL);
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
    c = ptls_aead_new(cs1->aead, cs1->hash, 1, traffic_secret, NULL);
    assert(c != NULL);
    ptls_aead_encrypt_init(c, 123, aad, strlen(aad));
    enclen = ptls_aead_encrypt_update(c, enc, src, strlen(src));
    enclen += ptls_aead_encrypt_final(c, enc + enclen);
    ptls_aead_free(c);

    /* decrypt */
    c = ptls_aead_new(cs2->aead, cs2->hash, 0, traffic_secret, NULL);
    assert(c != NULL);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, aad, strlen(aad));
    ok(declen == strlen(src));
    ok(memcmp(src, dec, declen) == 0);
    declen = ptls_aead_decrypt(c, dec, enc, enclen, 123, "my fake aad", strlen(aad));
    ok(declen == SIZE_MAX);
    ptls_aead_free(c);
}

static void test_ctr(ptls_cipher_suite_t *cs, const uint8_t *key, size_t key_len, const void *iv, size_t iv_len,
                     const void *expected, size_t expected_len)
{
    static uint8_t zeroes[64] = {0};

    if (cs == NULL)
        return;

    ptls_cipher_algorithm_t *algo = cs->aead->ctr_cipher;
    uint8_t buf[sizeof(zeroes)];

    assert(expected_len <= sizeof(zeroes));
    ok(algo->key_size == key_len);
    ok(algo->iv_size == iv_len);

    ptls_cipher_context_t *ctx = ptls_cipher_new(algo, 1, key);
    assert(ctx != NULL);
    ptls_cipher_init(ctx, iv);
    ptls_cipher_encrypt(ctx, buf, zeroes, expected_len);
    ptls_cipher_free(ctx);

    ok(memcmp(buf, expected, expected_len) == 0);
}

static void test_aes128ctr(void)
{
    static const uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
                         iv[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
                         expected[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                                       0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};

    test_ctr(find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256), key, sizeof(key), iv, sizeof(iv), expected, sizeof(expected));
}

static void test_chacha20(void)
{
    static const uint8_t key[] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                  16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
                         iv[] = {1, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0},
                         expected[] = {0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd,
                                       0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
                                       0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e};

    test_ctr(find_cipher(ctx, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256), key, sizeof(key), iv, sizeof(iv), expected,
             sizeof(expected));
}

static void test_aes128gcm(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256);

    test_ciphersuite(cs, cs_peer);
    test_aad_ciphersuite(cs, cs_peer);
}

static void test_aes256gcm(void)
{
    ptls_cipher_suite_t *cs = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384),
                        *cs_peer = find_cipher(ctx, PTLS_CIPHER_SUITE_AES_256_GCM_SHA384);

    if (cs != NULL && cs_peer != NULL) {
        test_ciphersuite(cs, cs_peer);
        test_aad_ciphersuite(cs, cs_peer);
    }
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
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(tls.recvbuf.mess.base != NULL);
    ok(test_fragmented_message_queue.count == 0);
    SET_RECORD("bc\x02\x00\x00\x02"
               "de"
               "\x03");
    ret = handle_handshake_record(&tls, test_fragmented_message_record, NULL, &rec, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
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

enum { TEST_HANDSHAKE_1RTT, TEST_HANDSHAKE_2RTT, TEST_HANDSHAKE_HRR, TEST_HANDSHAKE_HRR_STATELESS, TEST_HANDSHAKE_EARLY_DATA };

static void test_handshake(ptls_iovec_t ticket, int mode, int expect_ticket, int check_ch)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ticket}}}, server_hs_prop = {{{{NULL}}}};
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
    case TEST_HANDSHAKE_HRR_STATELESS:
        client_hs_prop.client.negotiate_before_key_exchange = 1;
        server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef";
        server_hs_prop.server.retry_uses_cookie = 1;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        assert(ctx_peer->max_early_data_size != 0);
        client_hs_prop.client.max_early_data_size = &max_early_data_size;
        break;
    }

    ret = ptls_handshake(client, &cbuf, NULL, NULL, &client_hs_prop);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);

    switch (mode) {
    case TEST_HANDSHAKE_2RTT:
    case TEST_HANDSHAKE_HRR:
    case TEST_HANDSHAKE_HRR_STATELESS:
        consumed = cbuf.off;
        ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
        if (mode == TEST_HANDSHAKE_HRR_STATELESS) {
            ok(ret == PTLS_ERROR_STATELESS_RETRY);
            ptls_free(server);
            server = ptls_new(ctx_peer, 1);
        } else {
            ok(ret == PTLS_ERROR_IN_PROGRESS);
        }
        ok(cbuf.off == consumed);
        ok(sbuf.off != 0);
        cbuf.off = 0;
        consumed = sbuf.off;
        ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, &client_hs_prop);
        ok(ret == PTLS_ERROR_IN_PROGRESS);
        ok(sbuf.off == consumed);
        ok(cbuf.off != 0);
        sbuf.off = 0;
        break;
    case TEST_HANDSHAKE_EARLY_DATA:
        ok(max_early_data_size == ctx_peer->max_early_data_size);
        ret = ptls_send(client, &cbuf, req, strlen(req));
        ok(ret == 0);
        break;
    }

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
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

    if (expect_ticket) {
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
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0);
    ok(sc_callcnt == 1);
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 0);
    ok(sc_callcnt == 2);
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_1RTT, 0, 1);
    ok(sc_callcnt == 3);
}

static void test_hrr_handshake(void)
{
    sc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR, 0, 0);
    ok(sc_callcnt == 1);
}

static void test_hrr_stateless_handshake(void)
{
    sc_callcnt = 0;
    test_handshake(ptls_iovec_init(NULL, 0), TEST_HANDSHAKE_HRR_STATELESS, 0, 0);
    ok(sc_callcnt == 1);
}

static int copy_ticket(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
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

static void do_test_resumption(int different_preferred_key_share)
{
    assert(ctx->key_exchanges[0]->id == ctx_peer->key_exchanges[0]->id);
    assert(ctx->key_exchanges[1] == NULL);
    assert(ctx_peer->key_exchanges[1] == NULL);
    assert(ctx->key_exchanges[0]->id != ptls_minicrypto_x25519.id);
    ptls_key_exchange_algorithm_t *different_key_exchanges[] = {&ptls_minicrypto_x25519, ctx->key_exchanges[0], NULL},
                                  **key_exchanges_orig = ctx->key_exchanges;

    if (different_preferred_key_share)
        ctx->key_exchanges = different_key_exchanges;

    ptls_encrypt_ticket_t et = {copy_ticket};
    ptls_save_ticket_t st = {save_ticket};

    assert(ctx_peer->ticket_lifetime == 0);
    assert(ctx_peer->max_early_data_size == 0);
    assert(ctx_peer->encrypt_ticket == NULL);
    assert(ctx_peer->save_ticket == NULL);
    saved_ticket = ptls_iovec_init(NULL, 0);

    ctx_peer->ticket_lifetime = 86400;
    ctx_peer->max_early_data_size = 8192;
    ctx_peer->encrypt_ticket = &et;
    ctx->save_ticket = &st;

    sc_callcnt = 0;
    test_handshake(saved_ticket, different_preferred_key_share ? TEST_HANDSHAKE_2RTT : TEST_HANDSHAKE_1RTT, 1, 0);
    ok(sc_callcnt == 1);
    ok(saved_ticket.base != NULL);

    /* psk using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_1RTT, 1, 0);
    ok(sc_callcnt == 1);

    /* 0-rtt psk using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_EARLY_DATA, 1, 0);
    ok(sc_callcnt == 1);

    ctx->require_dhe_on_psk = 1;

    /* psk-dhe using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_1RTT, 1, 0);
    ok(sc_callcnt == 1);

    /* 0-rtt psk-dhe using saved ticket */
    test_handshake(saved_ticket, TEST_HANDSHAKE_EARLY_DATA, 1, 0);
    ok(sc_callcnt == 1);

    ctx->require_dhe_on_psk = 0;
    ctx_peer->ticket_lifetime = 0;
    ctx_peer->max_early_data_size = 0;
    ctx_peer->encrypt_ticket = NULL;
    ctx->save_ticket = NULL;
    ctx->key_exchanges = key_exchanges_orig;
}

static void test_resumption(void)
{
    do_test_resumption(0);
}

static void test_resumption_different_preferred_key_share(void)
{
    if (ctx == ctx_peer)
        return;
    do_test_resumption(1);
}

static void test_enforce_retry(int use_cookie)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};
    ptls_buffer_t cbuf, sbuf, decbuf;
    size_t consumed;
    int ret;

    server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef";
    server_hs_prop.server.cookie.additional_data = ptls_iovec_init("1.2.3.4:1234", 12);
    server_hs_prop.server.enforce_retry = 1;
    server_hs_prop.server.retry_uses_cookie = use_cookie;

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(&sbuf, "", 0);
    ptls_buffer_init(&decbuf, "", 0);

    client = ptls_new(ctx, 0);

    ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(cbuf.off != 0);

    server = ptls_new(ctx, 1);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    cbuf.off = 0;

    if (use_cookie) {
        ok(ret == PTLS_ERROR_STATELESS_RETRY);
        ptls_free(server);
        server = ptls_new(ctx, 1);
    } else {
        ok(ret == PTLS_ERROR_IN_PROGRESS);
    }

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(sbuf.off == consumed);
    sbuf.off = 0;

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    ok(ret == 0);
    ok(cbuf.off == consumed);
    cbuf.off = 0;

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(sbuf.off == consumed);
    sbuf.off = 0;

    ret = ptls_send(client, &cbuf, "hello world", 11);
    ok(ret == 0);

    consumed = cbuf.off;
    ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
    ok(ret == 0);
    ok(cbuf.off == consumed);
    cbuf.off = 0;

    ok(decbuf.off == 11);
    ok(memcmp(decbuf.base, "hello world", 11) == 0);
    decbuf.off = 0;

    ptls_free(client);
    ptls_free(server);

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&decbuf);
}

static void test_enforce_retry_stateful(void)
{
    test_enforce_retry(0);
}

static void test_enforce_retry_stateless(void)
{
    test_enforce_retry(1);
}

static ptls_t *stateless_hrr_prepare(ptls_buffer_t *sbuf, ptls_handshake_properties_t *server_hs_prop)
{
    ptls_t *client = ptls_new(ctx, 0), *server = ptls_new(ctx_peer, 1);
    ptls_buffer_t cbuf;
    size_t consumed;
    int ret;

    ptls_buffer_init(&cbuf, "", 0);
    ptls_buffer_init(sbuf, "", 0);

    ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);

    consumed = cbuf.off;
    ret = ptls_handshake(server, sbuf, cbuf.base, &consumed, server_hs_prop);
    ok(ret == PTLS_ERROR_STATELESS_RETRY);

    ptls_buffer_dispose(&cbuf);
    ptls_free(server);

    return client;
}

static void test_stateless_hrr_aad_change(void)
{
    ptls_t *client, *server;
    ptls_handshake_properties_t server_hs_prop = {{{{NULL}}}};
    ptls_buffer_t cbuf, sbuf;
    size_t consumed;
    int ret;

    server_hs_prop.server.cookie.key = "0123456789abcdef0123456789abcdef";
    server_hs_prop.server.cookie.additional_data = ptls_iovec_init("1.2.3.4:1234", 12);
    server_hs_prop.server.enforce_retry = 1;
    server_hs_prop.server.retry_uses_cookie = 1;

    client = stateless_hrr_prepare(&sbuf, &server_hs_prop);
    ptls_buffer_init(&cbuf, "", 0);

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(sbuf.off == consumed);
    sbuf.off = 0;

    server = ptls_new(ctx_peer, 1);
    server_hs_prop.server.cookie.additional_data = ptls_iovec_init("1.2.3.4:4321", 12);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, &server_hs_prop);
    ok(ret == PTLS_ALERT_HANDSHAKE_FAILURE);

    ptls_free(client);
    ptls_free(server);

    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
}

void test_picotls(void)
{
    subtest("sha256", test_sha256);
    subtest("sha384", test_sha384);
    subtest("hmac-sha256", test_hmac_sha256);
    subtest("hkdf", test_hkdf);
    subtest("aes128gcm", test_aes128gcm);
    subtest("aes256gcm", test_aes256gcm);
    subtest("chacha20poly1305", test_chacha20poly1305);
    subtest("aes128ctr", test_aes128ctr);
    subtest("chacha20", test_chacha20);

    subtest("fragmented-message", test_fragmented_message);

    ptls_sign_certificate_t sc = {sign_certificate};
    sc_orig = ctx_peer->sign_certificate;
    ctx_peer->sign_certificate = &sc;

    subtest("full-handshake", test_full_handshake);
    subtest("hrr-handshake", test_hrr_handshake);
    subtest("hrr-stateless-handshake", test_hrr_stateless_handshake);
    subtest("resumption", test_resumption);
    subtest("resumption-different-preferred-key-share", test_resumption_different_preferred_key_share);

    subtest("enforce-retry-stateful", test_enforce_retry_stateful);
    subtest("enforce-retry-stateless", test_enforce_retry_stateless);

    subtest("stateless-hrr-aad-change", test_stateless_hrr_aad_change);

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
