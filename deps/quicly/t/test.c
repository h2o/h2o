/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "../lib/quicly.c"
#include "test.h"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEowIBAAKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6\n"                                                           \
    "A/Z+bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9\n"                                                           \
    "C7WcNcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7\n"                                                           \
    "ntPW/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDy\n"                                                           \
    "OxiNkLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MI\n"                                                           \
    "uDo7Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABAoIBAQCWcUv1wjR/2+Nw\n"                                                           \
    "B+Swp267R9bt8pdxyK6f5yKrskGErremiFygMrFtVBQYjws9CsRjISehSkN4GqjE\n"                                                           \
    "CweygJZVJeL++YvUmQnvFJSzgCjXU6GEStbOKD/A7T5sa0fmzMhOE907V+kpAT3x\n"                                                           \
    "E1rNRaP/ImJ1X1GjuefVb0rOPiK/dehFQWfsUkOvh+J3PU76wcnexxzJgxhVxdfX\n"                                                           \
    "qNa7UDsWzTImUjcHIfnhXc1K/oSKk6HjImQi/oE4lgoJUCEDaUbq0nXNrM0EmTTv\n"                                                           \
    "OQ5TVP5Lds9p8UDEa55eZllGXam0zKjhDKtkQ/5UfnxsAv2adY5cuH+XN0ExfKD8\n"                                                           \
    "wIZ5qINtAoGBAPRbQGZZkP/HOYA4YZ9HYAUQwFS9IZrQ8Y7C/UbL01Xli13nKalH\n"                                                           \
    "xXdG6Zv6Yv0FCJKA3N945lEof9rwriwhuZbyrA1TcKok/s7HR8Bhcsm2DzRD5OiC\n"                                                           \
    "3HK+Xy+6fBaMebffqBPp3Lfj/lSPNt0w/8DdrKBTw/cAy40g0n1zEu07AoGBAPHJ\n"                                                           \
    "V4IfQBiblCqDh77FfQRUNR4hVbbl00Gviigiw563nk7sxdrOJ1edTyTOUBHtM3zg\n"                                                           \
    "AT9sYz2CUXvsyEPqzMDANWMb9e2R//NcP6aM4k7WQRnwkZkp0WOIH95U2o1MHCYc\n"                                                           \
    "5meAHVf2UMl+64xU2ZfY3rjMmPLjWMt0hKYsOmtvAoGAClIQVkJSLXtsok2/Ucrh\n"                                                           \
    "81TRysJyOOe6TB1QNT1Gn8oiKMUqrUuqu27zTvM0WxtrUUTAD3A7yhG71LN1p8eE\n"                                                           \
    "3ytAuQ9dItKNMI6aKTX0czCNU9fKQ0fDp9UCkDGALDOisHFx1+V4vQuUIl4qIw1+\n"                                                           \
    "v9adA+iFzljqP/uy6DmEAyECgYAyWCgecf9YoFxzlbuYH2rukdIVmf9M/AHG9ZQg\n"                                                           \
    "00xEKhuOd4KjErXiamDmWwcVFHzaDZJ08E6hqhbpZN42Nhe4Ms1q+5FzjCjtNVIT\n"                                                           \
    "jdY5cCdSDWNjru9oeBmao7R2I1jhHrdi6awyeplLu1+0cp50HbYSaJeYS3pbssFE\n"                                                           \
    "EIWBhQKBgG3xleD4Sg9rG2OWQz5IrvLFg/Hy7YWyushVez61kZeLDnt9iM2um76k\n"                                                           \
    "/xFNIW0a+eL2VxRTCbXr9z86hjc/6CeSJHKYFQl4zsSAZkaIJ0+HbrhDNBAYh9b2\n"                                                           \
    "mRdX+OMdZ7Z5J3Glt8ENFRqe8RlESMpAKxjR+dID0bjwAjVr2KCh\n"                                                                       \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIICqDCCAZACCQDI5jeEvExN+TANBgkqhkiG9w0BAQUFADAWMRQwEgYDVQQDEwtl\n"                                                           \
    "eGFtcGxlLmNvbTAeFw0xNjA5MzAwMzQ0NTFaFw0yNjA5MjgwMzQ0NTFaMBYxFDAS\n"                                                           \
    "BgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"                                                           \
    "AQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+bViFlfEg\n"                                                           \
    "L37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7WcNcshpSdm\n"                                                           \
    "2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW/XCchVf+\n"                                                           \
    "ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiNkLFLvUdT\n"                                                           \
    "4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7Vhkq5+TC\n"                                                           \
    "qXsIFNbjy0taOoPRvUbPsbqFlQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAwZQsG\n"                                                           \
    "E/3DQFBOnmBITFsaIVJVXU0fbfIjy3p1r6O9z2zvrfB1i8AMxOORAVjE5wHstGnK\n"                                                           \
    "3sLMjkMYXqu1XEfQbStQN+Bsi8m+nE/x9MmuLthpzJHXUmPYZ4TKs0KJmFPLTXYi\n"                                                           \
    "j0OrP0a5BNcyGj/B4Z33aaU9N3z0TWBwx4OPjJoK3iInBx80sC1Ig2PE6mDBxLOg\n"                                                           \
    "5Ohm/XU/43MrtH8SgYkxr3OyzXTm8J0RFMWhYlo1uqR+pWV3TgacixNnUq5w5h4m\n"                                                           \
    "sqXcikh+j8ReNXsKnMOAfFo+HbRqyKWNE3DekCIiiQ5ds4A4SfT7pYyGAmBkAxht\n"                                                           \
    "sS919x2o8l97kaYf\n"                                                                                                           \
    "-----END CERTIFICATE-----\n"

static int64_t get_now(quicly_context_t *ctx);

int64_t quic_now;
quicly_context_t quic_ctx;

static int64_t get_now(quicly_context_t *ctx)
{
    return quic_now;
}

static void test_pne(void)
{
    static const uint8_t cid[] = {0x69, 0xbd, 0xdf, 0xea, 0xac, 0x2c, 0xff, 0xd7},
                         iv[] = {0x43, 0xd2, 0xad, 0x97, 0x34, 0x40, 0xe2, 0xd6, 0xae, 0xd2, 0x0c, 0xc9, 0xc9, 0x2c, 0x6f, 0x23},
                         encrypted_pn[] = {0x16, 0x08, 0x67, 0x062}, expected_pn[] = {0xc0, 0x00, 0x00, 0x00};
    struct st_quicly_cipher_context_t ingress, egress;
    uint8_t pn[sizeof(encrypted_pn)];
    int ret;

    ret = setup_initial_encryption(&ingress, &egress, ptls_openssl_cipher_suites, ptls_iovec_init(cid, sizeof(cid)), 0);
    ok(ret == 0);
    ptls_cipher_init(ingress.pne, iv);
    ptls_cipher_encrypt(ingress.pne, pn, encrypted_pn, sizeof(encrypted_pn));
    ok(memcmp(pn, expected_pn, sizeof(expected_pn)) == 0);

    dispose_cipher(&ingress);
    dispose_cipher(&egress);
}

void free_packets(quicly_datagram_t **packets, size_t cnt)
{
    size_t i;
    for (i = 0; i != cnt; ++i)
        quicly_default_free_packet(&quic_ctx, packets[i]);
}

size_t decode_packets(quicly_decoded_packet_t *decoded, quicly_datagram_t **raw, size_t cnt, size_t host_cidl)
{
    size_t ri, dc = 0;

    for (ri = 0; ri != cnt; ++ri) {
        size_t off = 0;
        do {
            size_t dl = quicly_decode_packet(decoded + dc, raw[ri]->data.base + off, raw[ri]->data.len - off, host_cidl);
            assert(dl != SIZE_MAX);
            ++dc;
            off += dl;
        } while (off != raw[ri]->data.len);
    }

    return dc;
}

int on_update_noop(quicly_stream_t *stream)
{
    return 0;
}

int on_stream_open_buffering(quicly_stream_t *stream)
{
    stream->on_update = on_update_noop;
    return 0;
}

int recvbuf_is(quicly_recvbuf_t *buf, const char *s)
{
    for (; *s != '\0'; ++s) {
        ptls_iovec_t input = quicly_recvbuf_get(buf);
        if (input.len == 0)
            return 0;
        if (*s != input.base[0])
            return 0;
        quicly_recvbuf_shift(buf, 1);
    }

    return 1;
}

size_t transmit(quicly_conn_t *src, quicly_conn_t *dst)
{
    quicly_datagram_t *datagrams[32];
    size_t num_datagrams, i;
    quicly_decoded_packet_t decoded[32];
    int ret;

    num_datagrams = sizeof(datagrams) / sizeof(datagrams[0]);
    ret = quicly_send(src, datagrams, &num_datagrams);
    ok(ret == 0);

    if (num_datagrams != 0) {
        size_t num_packets = decode_packets(decoded, datagrams, num_datagrams, quicly_is_client(dst) ? 0 : 8);
        for (i = 0; i != num_packets; ++i) {
            ret = quicly_receive(dst, decoded + i);
            ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
        }
        free_packets(datagrams, num_datagrams);
    }

    return num_datagrams;
}

int max_data_is_equal(quicly_conn_t *client, quicly_conn_t *server)
{
    uint64_t client_sent, client_consumed;
    uint64_t server_sent, server_consumed;

    quicly_get_max_data(client, NULL, &client_sent, &client_consumed);
    quicly_get_max_data(server, NULL, &server_sent, &server_consumed);

    if (client_sent != server_consumed)
        return 0;
    if (server_sent != client_consumed)
        return 0;

    return 1;
}

static void test_next_packet_number(void)
{
    /* prefer lower in case the distance in both directions are equal; see https://github.com/quicwg/base-drafts/issues/674 */
    uint64_t n = quicly_determine_packet_number(0xc0, 0xff, 0x140);
    ok(n == 0xc0);
    n = quicly_determine_packet_number(0xc0, 0xff, 0x141);
    ok(n == 0x1c0);
}

int main(int argc, char **argv)
{
    static ptls_iovec_t cert;
    static ptls_openssl_sign_certificate_t cert_signer;
    static ptls_context_t tlsctx = {ptls_openssl_random_bytes,
                                    &ptls_get_time,
                                    ptls_openssl_key_exchanges,
                                    ptls_openssl_cipher_suites,
                                    {&cert, 1},
                                    NULL,
                                    NULL,
                                    &cert_signer.super,
                                    NULL,
                                    0,
                                    0,
                                    NULL,
                                    1};
    quic_ctx = quicly_default_context;
    quic_ctx.tls = &tlsctx;
    quic_ctx.max_streams_bidi = 10;
    quic_ctx.on_stream_open = on_stream_open_buffering;
    quic_ctx.now = get_now;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    {
        BIO *bio = BIO_new_mem_buf(RSA_CERTIFICATE, strlen(RSA_CERTIFICATE));
        X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        assert(x509 != NULL || !!"failed to load certificate");
        BIO_free(bio);
        cert.len = i2d_X509(x509, &cert.base);
        X509_free(x509);
    }

    {
        BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, strlen(RSA_PRIVATE_KEY));
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        assert(pkey != NULL || !"failed to load private key");
        BIO_free(bio);
        ptls_openssl_init_sign_certificate(&cert_signer, pkey);
        EVP_PKEY_free(pkey);
    }

    quicly_amend_ptls_context(quic_ctx.tls);

    subtest("next-packet-number", test_next_packet_number);
    subtest("ranges", test_ranges);
    subtest("frame", test_frame);
    subtest("maxsender", test_maxsender);
    subtest("ack", test_ack);
    subtest("pne", test_pne);
    subtest("simple", test_simple);
    subtest("stream-concurrency", test_stream_concurrency);
    subtest("loss", test_loss);

    return done_testing();
}
