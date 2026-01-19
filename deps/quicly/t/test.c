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
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#include "quicly/streambuf.h"
#include "../lib/quicly.c"
#include "test.h"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEpAIBAAKCAQEA7zZheZ4ph98JaedBNv9kqsVA9CSmhd69kBc9ZAfVFMA4VQwp\n"                                                           \
    "rOj3ZGrxf20HB3FkvqGvew9ZogUF6NjbPumeiUObGpP21Y5wcYlPL4aojlrwMB/e\n"                                                           \
    "OxOCpuRyQTRSSe1hDPvdJABQdmshDP5ZSEBLdUSgrNn4KWhIDjFj1AHXIMqeqTXe\n"                                                           \
    "tFuRgNzHdtbXQx+UWBis2B6qZJuqSArb2msVOC8D5gNznPPlQw7FbdPCaLNXSb6G\n"                                                           \
    "nI0E0uj6QmYlAw9s6nkgP/zxjfFldqPNUprGcEqTwmAb8VVtd7XbANYrzubZ4Nn6\n"                                                           \
    "/WXrCrVxWUmh/7Spgdwa/I4Nr1JHv9HHyL2z/wIDAQABAoIBAEVPf2zKrAPnVwXt\n"                                                           \
    "cJLr6xIj908GM43EXS6b3TjXoCDUFT5nOMgV9GCPMAwY3hmE/IjTtlG0v+bXB8BQ\n"                                                           \
    "3S3caQgio5VO3A1CqUfsXhpKLRqaNM/s2+pIG+oZdRV5gIJVGnK1o3yj7qxxG/F0\n"                                                           \
    "3Q+3OWXwDZIn0eTFh2M9YkxygA/KtkREZWv8Q8qZpdOpJSBYZyGE97Jqy/yGc+DQ\n"                                                           \
    "Vpoa9B8WwnIdUn47TkZfsbzqGIYZxatJQDC1j7Y+F8So7zBbUhpz7YqATQwf5Efm\n"                                                           \
    "K2xwvlwfdwykq6ffEr2M/Xna0220G2JZlGq3Cs2X9GT9Pt9OS86Bz+EL46ELo0tZ\n"                                                           \
    "yfHQe/kCgYEA+zh4k2be6fhQG+ChiG3Ue5K/kH2prqyGBus61wHnt8XZavqBevEy\n"                                                           \
    "4pdmvJ6Q1Ta9Z2YCIqqNmlTdjZ6B35lvAK8YFITGy0MVV6K5NFYVfhALWCQC2r3B\n"                                                           \
    "6uH39FQ0mDo3gS5ZjYlUzbu67LGFnyX+pyMr2oxlhI1fCY3VchXQAOsCgYEA88Nt\n"                                                           \
    "CwSOaZ1fWmyNAgXEAX1Jx4XLFYgjcA/YBXW9gfQ0AfufB346y53PsgjX1lB+Bbcg\n"                                                           \
    "cY/o5W7F0b3A0R4K5LShlPCq8iB2DC+VnpKwTgo8ylh+VZCPy2BmMK0jrrmyqWeg\n"                                                           \
    "PzwgP0lp+7l/qW8LDImeYi8nWoqd6f1ye4iJdD0CgYEAlIApJljk5EFYeWIrmk3y\n"                                                           \
    "EKoKewsNRqfNAkICoh4KL2PQxaAW8emqPq9ol47T5nVZOMnf8UYINnZ8EL7l3psA\n"                                                           \
    "NtNJ1Lc4G+cnsooKGJnaUo6BZjTDSzJocsPoopE0Fdgz/zS60yOe8Y5LTKcTaaQ4\n"                                                           \
    "B+yOe74KNHSs/STOS4YBUskCgYAIqaRBZPsOo8oUs5DbRostpl8t2QJblIf13opF\n"                                                           \
    "v2ZprN0ASQngwUqjm8sav5e0BQ5Fc7mSb5POO36KMp0ckV2/vO+VFGxuyFqJmlNN\n"                                                           \
    "3Fapn1GDu1tZ/RYvGxDmn/CJsA26WXVnaeKXfStoB7KSueCBpI5dXOGgJRbxjtE3\n"                                                           \
    "tKV13QKBgQCtmLtTJPJ0Z+9n85C8kBonk2MCnD9JTYWoDQzNMYGabthzSqJqcEek\n"                                                           \
    "dvhr82XkcHM+r6+cirjdQr4Qj7/2bfZesHl5XLvoJDB1YJIXnNJOELwbktrJrXLc\n"                                                           \
    "dJ+MMvPvBAMah/tqr2DqgTGfWLDt9PJiCJVsuN2kD9toWHV08pY0Og==\n"                                                                   \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIIDOjCCAiKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDEwtIMk8g\n"                                                           \
    "VGVzdCBDQTAeFw0xNDEyMTAxOTMzMDVaFw0yNDEyMDcxOTMzMDVaMBsxGTAXBgNV\n"                                                           \
    "BAMTEDEyNy4wLjAuMS54aXAuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"                                                           \
    "AoIBAQDvNmF5nimH3wlp50E2/2SqxUD0JKaF3r2QFz1kB9UUwDhVDCms6PdkavF/\n"                                                           \
    "bQcHcWS+oa97D1miBQXo2Ns+6Z6JQ5sak/bVjnBxiU8vhqiOWvAwH947E4Km5HJB\n"                                                           \
    "NFJJ7WEM+90kAFB2ayEM/llIQEt1RKCs2fgpaEgOMWPUAdcgyp6pNd60W5GA3Md2\n"                                                           \
    "1tdDH5RYGKzYHqpkm6pICtvaaxU4LwPmA3Oc8+VDDsVt08Jos1dJvoacjQTS6PpC\n"                                                           \
    "ZiUDD2zqeSA//PGN8WV2o81SmsZwSpPCYBvxVW13tdsA1ivO5tng2fr9ZesKtXFZ\n"                                                           \
    "SaH/tKmB3Br8jg2vUke/0cfIvbP/AgMBAAGjgY0wgYowCQYDVR0TBAIwADAsBglg\n"                                                           \
    "hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\n"                                                           \
    "BBYEFJXhddVQ68vtPvxoHWHsYkLnu3+4MDAGA1UdIwQpMCehGqQYMBYxFDASBgNV\n"                                                           \
    "BAMTC0gyTyBUZXN0IENBggkAmqS1V7DvzbYwDQYJKoZIhvcNAQELBQADggEBAJQ2\n"                                                           \
    "uvzL/lZnrsF4cvHhl/mg+s/RjHwvqFRrxOWUeWu2BQOGdd1Izqr8ZbF35pevPkXe\n"                                                           \
    "j3zQL4Nf8OxO/gx4w0165KL4dYxEW7EaxsDQUI2aXSW0JNSvK2UGugG4+E4aT+9y\n"                                                           \
    "cuBCtfWbL4/N6IMt2QW17B3DcigkreMoZavnnqRecQWkOx4nu0SmYg1g2QV4kRqT\n"                                                           \
    "nvLt29daSWjNhP3dkmLTxn19umx26/JH6rqcgokDfHHO8tlDbc9JfyxYH01ZP2Ps\n"                                                           \
    "esIiGa/LBXfKiPXxyHuNVQI+2cMmIWYf+Eu/1uNV3K55fA8806/FeklcQe/vvSCU\n"                                                           \
    "Vw6RN5S/14SQnMYWr7E=\n"                                                                                                       \
    "-----END CERTIFICATE-----\n"

static void on_destroy(quicly_stream_t *stream, quicly_error_t err);
static void on_egress_stop(quicly_stream_t *stream, quicly_error_t err);
static void on_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void on_ingress_reset(quicly_stream_t *stream, quicly_error_t err);

quicly_address_t fake_address;
int64_t quic_now = 1;
quicly_context_t quic_ctx;
quicly_stream_callbacks_t stream_callbacks = {
    on_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_egress_stop, on_ingress_receive, on_ingress_reset};
size_t on_destroy_callcnt;

static void test_error_codes(void)
{
    quicly_error_t a;

    a = QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0);

    a = QUICLY_ERROR_FROM_TRANSPORT_ERROR_CODE(0x3fffffffffffffff);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0x3fffffffffffffff);

    a = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0);

    a = QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(0x3fffffffffffffff);
    ok(QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(QUICLY_ERROR_IS_QUIC_APPLICATION(a));
    ok(QUICLY_ERROR_GET_ERROR_CODE(a) == 0x3fffffffffffffff);

    a = 0;
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = PTLS_ALERT_UNKNOWN_CA; /* arbitrary alert */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = 0x2ffff; /* max outside QUIC errors */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = (int64_t)0x8000000000030000; /* min outside QUIC errors */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));

    a = QUICLY_ERROR_PACKET_IGNORED; /* arbrary internal error */
    ok(!QUICLY_ERROR_IS_QUIC(a));
    ok(!QUICLY_ERROR_IS_QUIC_TRANSPORT(a));
    ok(!QUICLY_ERROR_IS_QUIC_APPLICATION(a));
}

static uint16_t test_enable_with_ratio255_random_value;

static void test_enable_with_ratio255_get_random(void *p, size_t len)
{
    assert(len == sizeof(test_enable_with_ratio255_random_value));
    memcpy(p, &test_enable_with_ratio255_random_value, sizeof(test_enable_with_ratio255_random_value));
}

static void test_enable_with_ratio255(void)
{
    test_enable_with_ratio255_random_value = 0;
    ok(!enable_with_ratio255(0, test_enable_with_ratio255_get_random));
    ok(enable_with_ratio255(255, test_enable_with_ratio255_get_random));

    test_enable_with_ratio255_random_value = 255;
    ok(!enable_with_ratio255(0, test_enable_with_ratio255_get_random));
    ok(enable_with_ratio255(255, test_enable_with_ratio255_get_random));

    size_t num_enabled = 0;
    for (test_enable_with_ratio255_random_value = 0; test_enable_with_ratio255_random_value < 0xffff;
         ++test_enable_with_ratio255_random_value)
        if (enable_with_ratio255(63, test_enable_with_ratio255_get_random))
            ++num_enabled;
    ok(num_enabled == 63 * (65535 / 255));
}

static void test_adjust_stream_frame_layout(void)
{
#define TEST(_is_crypto, _capacity, check)                                                                                         \
    do {                                                                                                                           \
        uint8_t buf[] = {0xff, 0x04, 'h', 'e', 'l', 'l', 'o', 0, 0, 0};                                                            \
        uint8_t *dst = buf + 2, *const dst_end = buf + _capacity, *frame_at = buf;                                                 \
        size_t len = 5;                                                                                                            \
        int wrote_all = 1;                                                                                                         \
        buf[0] = _is_crypto ? 0x06 : 0x08;                                                                                         \
        adjust_stream_frame_layout(&dst, dst_end, &len, &wrote_all, &frame_at);                                                    \
        do {                                                                                                                       \
            check                                                                                                                  \
        } while (0);                                                                                                               \
    } while (0);

    /* test CRYPTO frames that fit and don't when length is inserted */
    TEST(1, 10, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x06\x04\x05hello", 8) == 0);
    });
    TEST(1, 8, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x06\x04\x05hello", 8) == 0);
    });
    TEST(1, 7, {
        ok(dst == buf + 7);
        ok(len == 4);
        ok(!wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x06\x04\x04hell", 7) == 0);
    });

    /* test STREAM frames */
    TEST(0, 9, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x0a\x04\x05hello", 8) == 0);
    });
    TEST(0, 8, {
        ok(dst == buf + 8);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf + 1);
        ok(memcmp(buf, "\x00\x08\x04hello", 8) == 0);
    });
    TEST(0, 7, {
        ok(dst == buf + 7);
        ok(len == 5);
        ok(wrote_all);
        ok(frame_at == buf);
        ok(memcmp(buf, "\x08\x04hello", 7) == 0);
    });

#undef TEST
}

static int64_t get_now_cb(quicly_now_t *self)
{
    return quic_now;
}

static quicly_now_t get_now = {get_now_cb};

void on_destroy(quicly_stream_t *stream, quicly_error_t err)
{
    test_streambuf_t *sbuf = stream->data;
    sbuf->is_detached = 1;
    ++on_destroy_callcnt;
}

void on_egress_stop(quicly_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    test_streambuf_t *sbuf = stream->data;
    sbuf->error_received.stop_sending = err;
}

void on_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    quicly_streambuf_ingress_receive(stream, off, src, len);
}

void on_ingress_reset(quicly_stream_t *stream, quicly_error_t err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    test_streambuf_t *sbuf = stream->data;
    sbuf->error_received.reset_stream = err;
}

const quicly_cid_plaintext_t *new_master_id(void)
{
    static quicly_cid_plaintext_t master = {UINT32_MAX};
    ++master.master_id;
    return &master;
}

static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    test_streambuf_t *sbuf;
    int ret;

    ret = quicly_streambuf_create(stream, sizeof(*sbuf));
    assert(ret == 0);
    sbuf = stream->data;
    sbuf->error_received.stop_sending = -1;
    sbuf->error_received.reset_stream = -1;
    stream->callbacks = &stream_callbacks;

    return 0;
}

quicly_stream_open_t stream_open = {on_stream_open};

static void test_vector(void)
{
    static const uint8_t expected_payload[] = {
        0x06, 0x00, 0x40, 0xc4, 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0x66, 0x60, 0x26, 0x1f, 0xf9, 0x47, 0xce, 0xa4, 0x9c, 0xce,
        0x6c, 0xfa, 0xd6, 0x87, 0xf4, 0x57, 0xcf, 0x1b, 0x14, 0x53, 0x1b, 0xa1, 0x41, 0x31, 0xa0, 0xe8, 0xf3, 0x09, 0xa1, 0xd0,
        0xb9, 0xc4, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00,
        0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00,
        0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x4c, 0xfd, 0xfc, 0xd1, 0x78, 0xb7, 0x84,
        0xbf, 0x32, 0x8c, 0xae, 0x79, 0x3b, 0x13, 0x6f, 0x2a, 0xed, 0xce, 0x00, 0x5f, 0xf1, 0x83, 0xd7, 0xbb, 0x14, 0x95, 0x20,
        0x72, 0x36, 0x64, 0x70, 0x37, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01,
        0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01};
    uint8_t datagram[] = {
        0xc5, 0xff, 0x00, 0x00, 0x1d, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x4a, 0x95,
        0x24, 0x5b, 0xfb, 0x66, 0xbc, 0x5f, 0x93, 0x03, 0x2b, 0x7d, 0xdd, 0x89, 0xfe, 0x0f, 0xf1, 0x5d, 0x9c, 0x4f, 0x70, 0x50,
        0xfc, 0xcd, 0xb7, 0x1c, 0x1c, 0xd8, 0x05, 0x12, 0xd4, 0x43, 0x16, 0x43, 0xa5, 0x3a, 0xaf, 0xa1, 0xb0, 0xb5, 0x18, 0xb4,
        0x49, 0x68, 0xb1, 0x8b, 0x8d, 0x3e, 0x7a, 0x4d, 0x04, 0xc3, 0x0b, 0x3e, 0xd9, 0x41, 0x03, 0x25, 0xb2, 0xab, 0xb2, 0xda,
        0xfb, 0x1c, 0x12, 0xf8, 0xb7, 0x04, 0x79, 0xeb, 0x8d, 0xf9, 0x8a, 0xbc, 0xaf, 0x95, 0xdd, 0x8f, 0x3d, 0x1c, 0x78, 0x66,
        0x0f, 0xbc, 0x71, 0x9f, 0x88, 0xb2, 0x3c, 0x8a, 0xef, 0x67, 0x71, 0xf3, 0xd5, 0x0e, 0x10, 0xfd, 0xfb, 0x4c, 0x9d, 0x92,
        0x38, 0x6d, 0x44, 0x48, 0x1b, 0x6c, 0x52, 0xd5, 0x9e, 0x55, 0x38, 0xd3, 0xd3, 0x94, 0x2d, 0xe9, 0xf1, 0x3a, 0x7f, 0x8b,
        0x70, 0x2d, 0xc3, 0x17, 0x24, 0x18, 0x0d, 0xa9, 0xdf, 0x22, 0x71, 0x4d, 0x01, 0x00, 0x3f, 0xc5, 0xe3, 0xd1, 0x65, 0xc9,
        0x50, 0xe6, 0x30, 0xb8, 0x54, 0x0f, 0xbd, 0x81, 0xc9, 0xdf, 0x0e, 0xe6, 0x3f, 0x94, 0x99, 0x70, 0x26, 0xc4, 0xf2, 0xe1,
        0x88, 0x7a, 0x2d, 0xef, 0x79, 0x05, 0x0a, 0xc2, 0xd8, 0x6b, 0xa3, 0x18, 0xe0, 0xb3, 0xad, 0xc4, 0xc5, 0xaa, 0x18, 0xbc,
        0xf6, 0x3c, 0x7c, 0xf8, 0xe8, 0x5f, 0x56, 0x92, 0x49, 0x81, 0x3a, 0x22, 0x36, 0xa7, 0xe7, 0x22, 0x69, 0x44, 0x7c, 0xd1,
        0xc7, 0x55, 0xe4, 0x51, 0xf5, 0xe7, 0x74, 0x70, 0xeb, 0x3d, 0xe6, 0x4c, 0x88, 0x49, 0xd2, 0x92, 0x82, 0x06, 0x98, 0x02,
        0x9c, 0xfa, 0x18, 0xe5, 0xd6, 0x61, 0x76, 0xfe, 0x6e, 0x5b, 0xa4, 0xed, 0x18, 0x02, 0x6f, 0x90, 0x90, 0x0a, 0x5b, 0x49,
        0x80, 0xe2, 0xf5, 0x8e, 0x39, 0x15, 0x1d, 0x5c, 0xd6, 0x85, 0xb1, 0x09, 0x29, 0x63, 0x6d, 0x4f, 0x02, 0xe7, 0xfa, 0xd2,
        0xa5, 0xa4, 0x58, 0x24, 0x9f, 0x5c, 0x02, 0x98, 0xa6, 0xd5, 0x3a, 0xcb, 0xe4, 0x1a, 0x7f, 0xc8, 0x3f, 0xa7, 0xcc, 0x01,
        0x97, 0x3f, 0x7a, 0x74, 0xd1, 0x23, 0x7a, 0x51, 0x97, 0x4e, 0x09, 0x76, 0x36, 0xb6, 0x20, 0x39, 0x97, 0xf9, 0x21, 0xd0,
        0x7b, 0xc1, 0x94, 0x0a, 0x6f, 0x2d, 0x0d, 0xe9, 0xf5, 0xa1, 0x14, 0x32, 0x94, 0x61, 0x59, 0xed, 0x6c, 0xc2, 0x1d, 0xf6,
        0x5c, 0x4d, 0xdd, 0x11, 0x15, 0xf8, 0x64, 0x27, 0x25, 0x9a, 0x19, 0x6c, 0x71, 0x48, 0xb2, 0x5b, 0x64, 0x78, 0xb0, 0xdc,
        0x77, 0x66, 0xe1, 0xc4, 0xd1, 0xb1, 0xf5, 0x15, 0x9f, 0x90, 0xea, 0xbc, 0x61, 0x63, 0x62, 0x26, 0x24, 0x46, 0x42, 0xee,
        0x14, 0x8b, 0x46, 0x4c, 0x9e, 0x61, 0x9e, 0xe5, 0x0a, 0x5e, 0x3d, 0xdc, 0x83, 0x62, 0x27, 0xca, 0xd9, 0x38, 0x98, 0x7c,
        0x4e, 0xa3, 0xc1, 0xfa, 0x7c, 0x75, 0xbb, 0xf8, 0x8d, 0x89, 0xe9, 0xad, 0xa6, 0x42, 0xb2, 0xb8, 0x8f, 0xe8, 0x10, 0x7b,
        0x7e, 0xa3, 0x75, 0xb1, 0xb6, 0x48, 0x89, 0xa4, 0xe9, 0xe5, 0xc3, 0x8a, 0x1c, 0x89, 0x6c, 0xe2, 0x75, 0xa5, 0x65, 0x8d,
        0x25, 0x0e, 0x2d, 0x76, 0xe1, 0xed, 0x3a, 0x34, 0xce, 0x7e, 0x3a, 0x3f, 0x38, 0x3d, 0x0c, 0x99, 0x6d, 0x0b, 0xed, 0x10,
        0x6c, 0x28, 0x99, 0xca, 0x6f, 0xc2, 0x63, 0xef, 0x04, 0x55, 0xe7, 0x4b, 0xb6, 0xac, 0x16, 0x40, 0xea, 0x7b, 0xfe, 0xdc,
        0x59, 0xf0, 0x3f, 0xee, 0x0e, 0x17, 0x25, 0xea, 0x15, 0x0f, 0xf4, 0xd6, 0x9a, 0x76, 0x60, 0xc5, 0x54, 0x21, 0x19, 0xc7,
        0x1d, 0xe2, 0x70, 0xae, 0x7c, 0x3e, 0xcf, 0xd1, 0xaf, 0x2c, 0x4c, 0xe5, 0x51, 0x98, 0x69, 0x49, 0xcc, 0x34, 0xa6, 0x6b,
        0x3e, 0x21, 0x6b, 0xfe, 0x18, 0xb3, 0x47, 0xe6, 0xc0, 0x5f, 0xd0, 0x50, 0xf8, 0x59, 0x12, 0xdb, 0x30, 0x3a, 0x8f, 0x05,
        0x4e, 0xc2, 0x3e, 0x38, 0xf4, 0x4d, 0x1c, 0x72, 0x5a, 0xb6, 0x41, 0xae, 0x92, 0x9f, 0xec, 0xc8, 0xe3, 0xce, 0xfa, 0x56,
        0x19, 0xdf, 0x42, 0x31, 0xf5, 0xb4, 0xc0, 0x09, 0xfa, 0x0c, 0x0b, 0xbc, 0x60, 0xbc, 0x75, 0xf7, 0x6d, 0x06, 0xef, 0x15,
        0x4f, 0xc8, 0x57, 0x70, 0x77, 0xd9, 0xd6, 0xa1, 0xd2, 0xbd, 0x9b, 0xf0, 0x81, 0xdc, 0x78, 0x3e, 0xce, 0x60, 0x11, 0x1b,
        0xea, 0x7d, 0xa9, 0xe5, 0xa9, 0x74, 0x80, 0x69, 0xd0, 0x78, 0xb2, 0xbe, 0xf4, 0x8d, 0xe0, 0x4c, 0xab, 0xe3, 0x75, 0x5b,
        0x19, 0x7d, 0x52, 0xb3, 0x20, 0x46, 0x94, 0x9e, 0xca, 0xa3, 0x10, 0x27, 0x4b, 0x4a, 0xac, 0x0d, 0x00, 0x8b, 0x19, 0x48,
        0xc1, 0x08, 0x2c, 0xdf, 0xe2, 0x08, 0x3e, 0x38, 0x6d, 0x4f, 0xd8, 0x4c, 0x0e, 0xd0, 0x66, 0x6d, 0x3e, 0xe2, 0x6c, 0x45,
        0x15, 0xc4, 0xfe, 0xe7, 0x34, 0x33, 0xac, 0x70, 0x3b, 0x69, 0x0a, 0x9f, 0x7b, 0xf2, 0x78, 0xa7, 0x74, 0x86, 0xac, 0xe4,
        0x4c, 0x48, 0x9a, 0x0c, 0x7a, 0xc8, 0xdf, 0xe4, 0xd1, 0xa5, 0x8f, 0xb3, 0xa7, 0x30, 0xb9, 0x93, 0xff, 0x0f, 0x0d, 0x61,
        0xb4, 0xd8, 0x95, 0x57, 0x83, 0x1e, 0xb4, 0xc7, 0x52, 0xff, 0xd3, 0x9c, 0x10, 0xf6, 0xb9, 0xf4, 0x6d, 0x8d, 0xb2, 0x78,
        0xda, 0x62, 0x4f, 0xd8, 0x00, 0xe4, 0xaf, 0x85, 0x54, 0x8a, 0x29, 0x4c, 0x15, 0x18, 0x89, 0x3a, 0x87, 0x78, 0xc4, 0xf6,
        0xd6, 0xd7, 0x3c, 0x93, 0xdf, 0x20, 0x09, 0x60, 0x10, 0x4e, 0x06, 0x2b, 0x38, 0x8e, 0xa9, 0x7d, 0xcf, 0x40, 0x16, 0xbc,
        0xed, 0x7f, 0x62, 0xb4, 0xf0, 0x62, 0xcb, 0x6c, 0x04, 0xc2, 0x06, 0x93, 0xd9, 0xa0, 0xe3, 0xb7, 0x4b, 0xa8, 0xfe, 0x74,
        0xcc, 0x01, 0x23, 0x78, 0x84, 0xf4, 0x0d, 0x76, 0x5a, 0xe5, 0x6a, 0x51, 0x68, 0x8d, 0x98, 0x5c, 0xf0, 0xce, 0xae, 0xf4,
        0x30, 0x45, 0xed, 0x8c, 0x3f, 0x0c, 0x33, 0xbc, 0xed, 0x08, 0x53, 0x7f, 0x68, 0x82, 0x61, 0x3a, 0xcd, 0x3b, 0x08, 0xd6,
        0x65, 0xfc, 0xe9, 0xdd, 0x8a, 0xa7, 0x31, 0x71, 0xe2, 0xd3, 0x77, 0x1a, 0x61, 0xdb, 0xa2, 0x79, 0x0e, 0x49, 0x1d, 0x41,
        0x3d, 0x93, 0xd9, 0x87, 0xe2, 0x74, 0x5a, 0xf2, 0x94, 0x18, 0xe4, 0x28, 0xbe, 0x34, 0x94, 0x14, 0x85, 0xc9, 0x34, 0x47,
        0x52, 0x0f, 0xfe, 0x23, 0x1d, 0xa2, 0x30, 0x4d, 0x6a, 0x0f, 0xd5, 0xd0, 0x7d, 0x08, 0x37, 0x22, 0x02, 0x36, 0x96, 0x61,
        0x59, 0xbe, 0xf3, 0xcf, 0x90, 0x4d, 0x72, 0x23, 0x24, 0xdd, 0x85, 0x25, 0x13, 0xdf, 0x39, 0xae, 0x03, 0x0d, 0x81, 0x73,
        0x90, 0x8d, 0xa6, 0x36, 0x47, 0x86, 0xd3, 0xc1, 0xbf, 0xcb, 0x19, 0xea, 0x77, 0xa6, 0x3b, 0x25, 0xf1, 0xe7, 0xfc, 0x66,
        0x1d, 0xef, 0x48, 0x0c, 0x5d, 0x00, 0xd4, 0x44, 0x56, 0x26, 0x9e, 0xbd, 0x84, 0xef, 0xd8, 0xe3, 0xa8, 0xb2, 0xc2, 0x57,
        0xee, 0xc7, 0x60, 0x60, 0x68, 0x28, 0x48, 0xcb, 0xf5, 0x19, 0x4b, 0xc9, 0x9e, 0x49, 0xee, 0x75, 0xe4, 0xd0, 0xd2, 0x54,
        0xba, 0xd4, 0xbf, 0xd7, 0x49, 0x70, 0xc3, 0x0e, 0x44, 0xb6, 0x55, 0x11, 0xd4, 0xad, 0x0e, 0x6e, 0xc7, 0x39, 0x8e, 0x08,
        0xe0, 0x13, 0x07, 0xee, 0xee, 0xa1, 0x4e, 0x46, 0xcc, 0xd8, 0x7c, 0xf3, 0x6b, 0x28, 0x52, 0x21, 0x25, 0x4d, 0x8f, 0xc6,
        0xa6, 0x76, 0x5c, 0x52, 0x4d, 0xed, 0x00, 0x85, 0xdc, 0xa5, 0xbd, 0x68, 0x8d, 0xdf, 0x72, 0x2e, 0x2c, 0x0f, 0xaf, 0x9d,
        0x0f, 0xb2, 0xce, 0x7a, 0x0c, 0x3f, 0x2c, 0xee, 0x19, 0xca, 0x0f, 0xfb, 0xa4, 0x61, 0xca, 0x8d, 0xc5, 0xd2, 0xc8, 0x17,
        0x8b, 0x07, 0x62, 0xcf, 0x67, 0x13, 0x55, 0x58, 0x49, 0x4d, 0x2a, 0x96, 0xf1, 0xa1, 0x39, 0xf0, 0xed, 0xb4, 0x2d, 0x2a,
        0xf8, 0x9a, 0x9c, 0x91, 0x22, 0xb0, 0x7a, 0xcb, 0xc2, 0x9e, 0x5e, 0x72, 0x2d, 0xf8, 0x61, 0x5c, 0x34, 0x37, 0x02, 0x49,
        0x10, 0x98, 0x47, 0x8a, 0x38, 0x9c, 0x98, 0x72, 0xa1, 0x0b, 0x0c, 0x98, 0x75, 0x12, 0x5e, 0x25, 0x7c, 0x7b, 0xfd, 0xf2,
        0x7e, 0xef, 0x40, 0x60, 0xbd, 0x3d, 0x00, 0xf4, 0xc1, 0x4f, 0xd3, 0xe3, 0x49, 0x6c, 0x38, 0xd3, 0xc5, 0xd1, 0xa5, 0x66,
        0x8c, 0x39, 0x35, 0x0e, 0xff, 0xbc, 0x2d, 0x16, 0xca, 0x17, 0xbe, 0x4c, 0xe2, 0x9f, 0x02, 0xed, 0x96, 0x95, 0x04, 0xdd,
        0xa2, 0xa8, 0xc6, 0xb9, 0xff, 0x91, 0x9e, 0x69, 0x3e, 0xe7, 0x9e, 0x09, 0x08, 0x93, 0x16, 0xe7, 0xd1, 0xd8, 0x9e, 0xc0,
        0x99, 0xdb, 0x3b, 0x2b, 0x26, 0x87, 0x25, 0xd8, 0x88, 0x53, 0x6a, 0x4b, 0x8b, 0xf9, 0xae, 0xe8, 0xfb, 0x43, 0xe8, 0x2a,
        0x4d, 0x91, 0x9d, 0x48, 0x43, 0xb1, 0xca, 0x70, 0xa2, 0xd8, 0xd3, 0xf7, 0x25, 0xea, 0xd1, 0x39, 0x13, 0x77, 0xdc, 0xc0};
    quicly_decoded_packet_t packet;
    struct st_quicly_cipher_context_t ingress, egress;
    uint64_t pn, next_expected_pn = 0;
    ptls_iovec_t payload;
    int ret;

    /* decode */
    size_t off = 0;
    ok(quicly_decode_packet(&quic_ctx, &packet, datagram, sizeof(datagram), &off) == sizeof(datagram));
    ok(off == sizeof(datagram));

    /* decrypt */
    const quicly_salt_t *salt = quicly_get_salt(QUICLY_PROTOCOL_VERSION_DRAFT29);
    ret = setup_initial_encryption(&ptls_openssl_aes128gcmsha256, &ingress, &egress, packet.cid.dest.encrypted, 0,
                                   ptls_iovec_init(salt->initial, sizeof(salt->initial)), NULL);
    ok(ret == 0);
    ok(decrypt_packet(ingress.header_protection, aead_decrypt_fixed_key, ingress.aead, &next_expected_pn, &packet, &pn, &payload) ==
       0);
    ok(pn == 2);
    ok(sizeof(expected_payload) <= payload.len);
    ok(memcmp(expected_payload, payload.base, sizeof(expected_payload)) == 0);

    dispose_cipher(&ingress);
    dispose_cipher(&egress);
}

static void test_retry_aead(void)
{
    quicly_cid_t odcid = {{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}, 8};
    uint8_t packet_bytes[] = {0xff, 0xff, 0x00, 0x00, 0x1d, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
                              0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0xd1, 0x69, 0x26, 0xd8,
                              0x1f, 0x6f, 0x9c, 0xa2, 0x95, 0x3a, 0x8a, 0xa4, 0x57, 0x5e, 0x1e, 0x49};

    /* decode (see `test_vector` for the rationale of overwriting the version) */
    quicly_decoded_packet_t decoded;
    size_t off = 0, decoded_len = quicly_decode_packet(&quic_ctx, &decoded, packet_bytes, sizeof(packet_bytes), &off);
    ok(decoded_len == sizeof(packet_bytes));
    ok(off == sizeof(packet_bytes));

    /* decrypt */
    ptls_aead_context_t *retry_aead = create_retry_aead(&quic_ctx, QUICLY_PROTOCOL_VERSION_DRAFT29, 0);
    ok(validate_retry_tag(&decoded, &odcid, retry_aead));
    ptls_aead_free(retry_aead);
}

static void test_transport_parameters(void)
{
    quicly_transport_parameters_t decoded;

    static const uint8_t valid_bytes[] = {0x05, 0x04, 0x80, 0x10, 0x00, 0x00, 0x06, 0x04, 0x80, 0x10, 0x00, 0x00,
                                          0x07, 0x04, 0x80, 0x10, 0x00, 0x00, 0x04, 0x04, 0x81, 0x00, 0x00, 0x00,
                                          0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x08, 0x01, 0x0a, 0x0a, 0x01, 0x0a};
    memset(&decoded, 0x55, sizeof(decoded));
    ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, valid_bytes, valid_bytes + sizeof(valid_bytes)) ==
       0);
    ok(decoded.max_stream_data.bidi_local = 0x100000);
    ok(decoded.max_stream_data.bidi_remote = 0x100000);
    ok(decoded.max_stream_data.uni = 0x100000);
    ok(decoded.max_data == 0x1000000);
    ok(decoded.max_idle_timeout == 30000);
    ok(decoded.max_streams_bidi == 10);
    ok(decoded.max_streams_uni == 0);
    ok(decoded.ack_delay_exponent == 10);
    ok(decoded.max_ack_delay == 25);
    ok(!decoded.disable_active_migration);

    static const uint8_t dup_bytes[] = {0x05, 0x04, 0x80, 0x10, 0x00, 0x00, 0x05, 0x04, 0x80, 0x10, 0x00, 0x00};
    memset(&decoded, 0x55, sizeof(decoded));
    ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, dup_bytes, dup_bytes + sizeof(dup_bytes)) ==
       QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER);
}

size_t decode_packets(quicly_decoded_packet_t *decoded, struct iovec *raw, size_t cnt)
{
    size_t ri, dc = 0;

    for (ri = 0; ri != cnt; ++ri) {
        size_t off = 0;
        do {
            size_t dl = quicly_decode_packet(&quic_ctx, decoded + dc, raw[ri].iov_base, raw[ri].iov_len, &off);
            assert(dl != SIZE_MAX);
            ++dc;
        } while (off != raw[ri].iov_len);
    }

    return dc;
}

int buffer_is(ptls_buffer_t *buf, const char *s)
{
    return buf->off == strlen(s) && memcmp(buf->base, s, buf->off) == 0;
}

size_t transmit(quicly_conn_t *src, quicly_conn_t *dst)
{
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[32];
    uint8_t datagramsbuf[PTLS_ELEMENTSOF(datagrams) * quicly_get_context(src)->transport_params.max_udp_payload_size];
    size_t num_datagrams, i;
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 2];
    quicly_error_t ret;

    num_datagrams = PTLS_ELEMENTSOF(datagrams);
    ret = quicly_send(src, &destaddr, &srcaddr, datagrams, &num_datagrams, datagramsbuf, sizeof(datagramsbuf));
    ok(ret == 0);

    if (num_datagrams != 0) {
        size_t num_packets = decode_packets(decoded, datagrams, num_datagrams);
        for (i = 0; i != num_packets; ++i) {
            ret = quicly_receive(dst, NULL, &fake_address.sa, decoded + i);
            ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
        }
    }

    return num_datagrams;
}

static void exchange_until_idle(quicly_conn_t *c1, quicly_conn_t *c2)
{
    while (1) {
        int64_t t1 = quicly_get_first_timeout(c1), t2 = quicly_get_first_timeout(c2), tmin = t1 <= t2 ? t1 : t2;
        if (tmin > quic_now) {
            if (tmin - quic_now > QUICLY_DEFAULT_MAX_ACK_DELAY)
                break;
            quic_now = tmin;
        }
        if (t1 <= t2) {
            transmit(c1, c2);
        } else {
            transmit(c2, c1);
        }
    }
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
    uint64_t n = quicly_determine_packet_number(0xc0, 8, 0x139);
    ok(n == 0xc0);
    n = quicly_determine_packet_number(0xc0, 8, 0x140);
    ok(n == 0x1c0);
    n = quicly_determine_packet_number(0x9b32, 16, 0xa82f30eb);
    ok(n == 0xa82f9b32);

    n = quicly_determine_packet_number(31, 16, 65259);
    ok(n == 65567);
}

static void test_address_token_codec_decode(ptls_aead_context_t *dec, const void *encrypted, size_t encrypted_len)
{
    quicly_address_token_plaintext_t output;
    const char *err_desc;

    ptls_openssl_random_bytes(&output, sizeof(output));

    ok(quicly_decrypt_address_token(dec, &output, encrypted, encrypted_len, 0, &err_desc) == 0);
    ok(output.type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY);
    ok(output.issued_at == 234);
    ok(output.remote.sa.sa_family == AF_INET);
    ok(output.remote.sin.sin_addr.s_addr == htonl(0x7f000001));
    ok(output.remote.sin.sin_port == htons(443));
    ok(quicly_cid_is_equal(&output.retry.original_dcid, ptls_iovec_init("abcdefgh", 8)));
    ok(quicly_cid_is_equal(&output.retry.client_cid, ptls_iovec_init("01234", 5)));
    ok(quicly_cid_is_equal(&output.retry.server_cid, ptls_iovec_init("abcdef0123456789", 16)));
    ok(output.appdata.len == 11);
    ok(memcmp(output.appdata.bytes, "hello world", 11) == 0);
}

static void test_address_token_codec(void)
{
    static const uint8_t zero_key[PTLS_MAX_SECRET_SIZE] = {0};
    ptls_aead_context_t *enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, zero_key, ""),
                        *dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, zero_key, "");

    quicly_address_token_plaintext_t input, output;
    ptls_buffer_t buf;
    const char *err_desc;

    { /* test hard-coded sample */
        static const uint8_t sample[] = {0x00, 0x39, 0xef, 0x13, 0x9a, 0xe1, 0xaa, 0x28, 0x51, 0x62, 0xf6, 0xd8, 0xc8, 0x93, 0x6a,
                                         0xdf, 0xd1, 0xbe, 0xa4, 0xb5, 0x99, 0xb9, 0xd7, 0x99, 0x02, 0xe3, 0x9e, 0xf2, 0xd0, 0x30,
                                         0x0b, 0x80, 0xcf, 0x66, 0xc4, 0x69, 0xc3, 0x86, 0x69, 0x92, 0xef, 0x3f, 0xd9, 0x64, 0x4b,
                                         0x6e, 0x9e, 0x16, 0x3a, 0x4d, 0xb6, 0x2c, 0xfc, 0x99, 0xe4, 0x46, 0x88, 0x7a, 0x73, 0x0d,
                                         0x69, 0x0e, 0xfb, 0xbf, 0x0e, 0x7c, 0xe3, 0x2d, 0x78, 0xf3, 0x90, 0xf6, 0xfd, 0xa4, 0x5e,
                                         0x71, 0x23, 0x3a, 0x15, 0xf2, 0x5f, 0xa6, 0x9e, 0x36, 0x13, 0x69, 0x53, 0xc1};
        test_address_token_codec_decode(dec, sample, sizeof(sample));
    }

    /* encrypt and decrypt */
    input = (quicly_address_token_plaintext_t){QUICLY_ADDRESS_TOKEN_TYPE_RETRY, 234};
    input.remote.sin.sin_family = AF_INET;
    input.remote.sin.sin_addr.s_addr = htonl(0x7f000001);
    input.remote.sin.sin_port = htons(443);
    quicly_set_cid(&input.retry.original_dcid, ptls_iovec_init("abcdefgh", 8));
    quicly_set_cid(&input.retry.client_cid, ptls_iovec_init("01234", 5));
    quicly_set_cid(&input.retry.server_cid, ptls_iovec_init("abcdef0123456789", 16));
    strcpy((char *)input.appdata.bytes, "hello world");
    input.appdata.len = strlen((char *)input.appdata.bytes);
    ptls_buffer_init(&buf, "", 0);
    ok(quicly_encrypt_address_token(ptls_openssl_random_bytes, enc, &buf, 0, &input) == 0);
    test_address_token_codec_decode(dec, buf.base, buf.off);

    /* failure to decrypt a Retry token is a hard error */
    ptls_openssl_random_bytes(&output, sizeof(output));
    buf.base[buf.off - 1] ^= 0x80;
    ok(quicly_decrypt_address_token(dec, &output, buf.base, buf.off, 0, &err_desc) == QUICLY_TRANSPORT_ERROR_INVALID_TOKEN);
    buf.base[buf.off - 1] ^= 0x80;

    /* failure to decrypt a token that is not a Retry is a soft error */
    ptls_openssl_random_bytes(&output, sizeof(output));
    buf.base[0] ^= 0x80;
    ok(quicly_decrypt_address_token(dec, &output, buf.base, buf.off, 0, &err_desc) == PTLS_ALERT_DECODE_ERROR);
    buf.base[0] ^= 0x80;

    ptls_buffer_dispose(&buf);
    ptls_aead_free(enc);
    ptls_aead_free(dec);
}

static void do_test_record_receipt(size_t epoch)
{
    struct st_quicly_pn_space_t *space =
        alloc_pn_space(sizeof(*space), epoch == QUICLY_EPOCH_1RTT ? QUICLY_DEFAULT_PACKET_TOLERANCE : 1);
    uint64_t pn = 0, out_of_order_cnt = 0;
    int64_t now = 12345, send_ack_at = INT64_MAX;

    if (epoch == QUICLY_EPOCH_1RTT) {
        /* 2nd packet triggers an ack */
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now + QUICLY_DELAYED_ACK_TIMEOUT);
        now += 1;
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now);
        now += 1;
    } else {
        /* every packet triggers an ack */
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now);
        now += 1;
    }

    /* reset */
    space->unacked_count = 0;
    send_ack_at = INT64_MAX;

    /* ack-only packets do not elicit an ack */
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    pn++; /* gap */
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    ok(record_receipt(space, pn++, 0, 1, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;

    /* gap triggers an ack */
    pn += 1; /* gap */
    ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
    ok(send_ack_at == now);
    now += 1;

    /* reset */
    space->unacked_count = 0;
    send_ack_at = INT64_MAX;

    /* if 1-RTT, test ignore-order */
    if (epoch == QUICLY_EPOCH_1RTT) {
        space->reordering_threshold = 0;
        pn++; /* gap */
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now + QUICLY_DELAYED_ACK_TIMEOUT);
        now += 1;
        ok(record_receipt(space, pn++, 0, 0, now, &send_ack_at, &out_of_order_cnt) == 0);
        ok(send_ack_at == now);
        now += 1;
    }

    do_free_pn_space(space);
}

static void do_test_ack_frequency_ack_logic()
{
    struct st_case_row_t {
        uint64_t packet_number;
        uint8_t send_ack;
        uint64_t expected_smallest_unreported_missing_after_receipt;
        int is_ack_only;
        uint64_t advance_time_by;
    };

    struct st_test_case {
        const struct st_case_row_t *rows;
        size_t rows_count;
        uint8_t reordering_threshold;
        uint32_t packet_tolerance;
    };

    // From example 1 at https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-11#section-6.2.1
    // clang-format off
    const struct st_case_row_t example1_rows[] = {
        {0,  0, 1,  0, 1},
        {1,  0, 2,  0, 1},
        {3,  0, 2,  0, 1},
        {4,  0, 2,  0, 1},
        {5,  1, 6,  0, 1},
        {8,  0, 6,  0, 1},
        {9,  1, 7,  0, 1},
        {10, 1, 11, 0, 1},
    };
    // clang-format on
    const struct st_test_case example1 = {
        .rows = example1_rows,
        .rows_count = PTLS_ELEMENTSOF(example1_rows),
        .reordering_threshold = 3,
        .packet_tolerance = 100,
    };

    // From example 1 at https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-11#section-6.2.1
    // clang-format off
    const struct st_case_row_t example2_rows[] = {
        {0, 0, 1,  0, 1},
        {1, 0, 2,  0, 1},
        {3, 0, 2,  0, 1},
        {5, 0, 2,  0, 1},
        {6, 0, 2,  0, 1},
        {7, 1, 4,  0, 1},
        {8, 0, 4,  0, 1},
        {9, 1, 10, 0, 1},
    };
    // clang-format on
    const struct st_test_case example2 = {
        .rows = example2_rows,
        .rows_count = PTLS_ELEMENTSOF(example2_rows),
        .reordering_threshold = 5,
        .packet_tolerance = 100,
    };

    // Disable reorder threshold, test packet tolerance
    // clang-format off
    const struct st_case_row_t test_case_1_rows[] = {
        // smallest unreported is n+1 because reordering threshold is set to 0
        {1,  0, 2,  0, 1},  // No ack yet (reordering_threshold = 0, so no immediate ack for reordering)
        {2,  1, 3,  0, 1},  // Ack because we've seen 2 packets
        {3,  0, 4,  0, 1},  // No ack yet
        {4,  1, 5,  0, 1},  // Ack because we've seen 2 packets
        {5,  0, 6,  0, 1},  // ...
        {6,  1, 7,  0, 1},
        {7,  0, 8,  0, 1},
        {8,  1, 9,  0, 1},
        {9,  0, 10, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_1 = {
        .rows = test_case_1_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_1_rows),
        .reordering_threshold = 0,
        .packet_tolerance = 2,
    };

    // Test reordered packets
    // clang-format off
    const struct st_case_row_t test_case_2_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 1, 2, 0, 1}, // Ack because we've seen 3 packets
        {2, 0, 4, 0, 1}, // No ack because 2 was never considered lost
        {4, 0, 5, 0, 1},
        {5, 1, 6, 0, 1}, // Ack because we've seen 3 more packets
    };
    // clang-format on
    const struct st_test_case test_case_2 = {
        .rows = test_case_2_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_2_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 3,
    };

    // Test a declared lost packet is received
    // clang-format off
    const struct st_case_row_t test_case_3_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 1, 2, 0, 1}, // Ack because we've seen 3 packets
        {4, 1, 5, 0, 1}, // Ack because 2 is now declared lost
        {2, 1, 5, 0, 1}, // Ack because 2 was received (change outside the reordering window)
        {5, 0, 6, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_3 = {
        .rows = test_case_3_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_3_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 3,
    };

    // Test 0 is lost
    // clang-format off
    const struct st_case_row_t test_case_4_rows[] = {
        {1, 0, 0, 0, 1},
        {2, 0, 0, 0, 1},
        {3, 1, 4, 0, 1}, // Ack because 0 is now declared lost
        {0, 1, 4, 0, 1}, // Ack because 0 was received (change outside the reordering window)
    };
    // clang-format on
    const struct st_test_case test_case_4 = {
        .rows = test_case_4_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_4_rows),
        .reordering_threshold = 3,
        .packet_tolerance = 100,
    };

    // Test larget packet tolerance and reordering threshold
    // Skipped 0
    // clang-format off
    const struct st_case_row_t test_case_5_rows[] = {
        {1, 0, 0, 0, 1},
        {2, 0, 0, 0, 1},
        {3, 0, 0, 0, 1},
        {4, 0, 0, 0, 1},
        {5, 0, 0, 0, 1},
        {6, 0, 0, 0, 1},
        {7, 0, 0, 0, 1},
        {8, 0, 0, 0, 1},
        {9, 0, 0, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_5 = {
        .rows = test_case_5_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_5_rows),
        .reordering_threshold = 20,
        .packet_tolerance = 20,
    };

    // ack every packet
    // clang-format off
    const struct st_case_row_t test_case_6_rows[] = {
        {0, 1, 1,  0, 1},
        {1, 1, 2,  0, 1},
        {2, 1, 3,  0, 1},
        {3, 1, 4,  0, 1},
        {4, 1, 5,  0, 1},
        {5, 1, 6,  0, 1},
        {6, 1, 7,  0, 1},
        {7, 1, 8,  0, 1},
        {8, 1, 9,  0, 1},
        {9, 1, 10, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_6 = {
        .rows = test_case_6_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_6_rows),
        .reordering_threshold = 0,
        .packet_tolerance = 0,
    };

    // Send packets ack-eliciting packets [0,1,3]. Then send non-ack eliciting
    // packets [4..7] with `QUICLY_DELAYED_ACK_TIMEOUT` amount of time between.
    //
    // After we send an ack for PN 4, PN 2 is declared lost, and the next
    // smallest unreported missing PN is 5.
    //
    // clang-format off
    const struct st_case_row_t test_case_7_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 0, 2, 0, 1},
        {4, 0, 5, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {5, 0, 6, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {6, 0, 7, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {7, 0, 8, 1, QUICLY_DELAYED_ACK_TIMEOUT},
    };
    // clang-format on
    const struct st_test_case test_case_7 = {
        .rows = test_case_7_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_7_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 20,
    };

    // Send packets ack-eliciting packets [0,1,3]. Then send non-ack eliciting
    // packets [4] with `QUICLY_DELAYED_ACK_TIMEOUT` amount of time between.
    //
    // After we send an ack for PN 4, PN 2 is declared lost, and the next
    // smallest unreported missing PN is 5.
    //
    // Then send packet 2 as ack-eliciting packet. This should be reported right
    // away to detect spurious losses.
    //
    // clang-format off
    const struct st_case_row_t test_case_8_rows[] = {
        {0, 0, 1, 0, 1},
        {1, 0, 2, 0, 1},
        {3, 0, 2, 0, 1},
        {4, 0, 5, 1, QUICLY_DELAYED_ACK_TIMEOUT},
        {2, 1, 5, 0, 1},
    };
    // clang-format on
    const struct st_test_case test_case_8 = {
        .rows = test_case_8_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_8_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 20,
    };

    // Same as the above test case, but packet 2 is non-ack-eliciting, so we
    // should not trigger and ack
    const struct st_case_row_t test_case_9_rows[] = {
        {0, 0, 1, 0, 1}, {1, 0, 2, 0, 1}, {3, 0, 2, 0, 1}, {4, 0, 5, 1, QUICLY_DELAYED_ACK_TIMEOUT}, {2, 0, 5, 1, 1},
    };
    // clang-format on
    const struct st_test_case test_case_9 = {
        .rows = test_case_9_rows,
        .rows_count = PTLS_ELEMENTSOF(test_case_9_rows),
        .reordering_threshold = 2,
        .packet_tolerance = 20,
    };

    // clang-format off
    struct st_test_case test_cases[] = {
        example1,
        example2,
        test_case_1,
        test_case_2,
        test_case_3,
        test_case_4,
        test_case_5,
        test_case_6,
        test_case_7,
        test_case_8,
        test_case_9,
    };
    // clang-format on

    for (int i = 0; i < PTLS_ELEMENTSOF(test_cases); ++i) {
        int64_t now = 12345;
        uint64_t out_of_order_cnt = 0;
        int64_t send_ack_at = INT64_MAX;

        struct st_quicly_pn_space_t *space = alloc_pn_space(sizeof(*space), QUICLY_DEFAULT_PACKET_TOLERANCE);
        space->reordering_threshold = test_cases[i].reordering_threshold;
        space->packet_tolerance = test_cases[i].packet_tolerance;

        for (int row_idx = 0; row_idx < test_cases[i].rows_count; ++row_idx) {
            struct st_case_row_t row = test_cases[i].rows[row_idx];

            ok(record_receipt(space, row.packet_number, 0, row.is_ack_only, now, &send_ack_at, &out_of_order_cnt) == 0);
            ok(row.send_ack ? send_ack_at == now : send_ack_at > now);
            now += row.advance_time_by;
            if (send_ack_at <= now && space->ack_queue.num_ranges > 0) {
                send_ack_at = INT64_MAX;
                space->unacked_count = 0;
                update_smallest_unreported_missing_on_send_ack(&space->ack_queue, &space->largest_acked_unacked,
                                                               &space->smallest_unreported_missing, space->reordering_threshold);
            }

            ok(row.expected_smallest_unreported_missing_after_receipt == space->smallest_unreported_missing);
        }

        do_free_pn_space(space);
    }
}

static void test_record_receipt(void)
{
    do_test_record_receipt(QUICLY_EPOCH_INITIAL);
    do_test_record_receipt(QUICLY_EPOCH_1RTT);
    do_test_ack_frequency_ack_logic();
}

static void test_ack_frequency(void)
{
    quicly_conn_t *client, *server;
    quicly_stream_t *client_stream, *server_stream;
    quicly_error_t ret;

    quicly_context_t ctx = quic_ctx;
    ctx.ack_frequency = 1024; // every rtt

    { /* connect */
        quicly_address_t dest, src;
        struct iovec raw;
        uint8_t rawbuf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &dest, &src, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        ok(decode_packets(&decoded, &raw, 1) == 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL);
        ok(ret == 0);
        transmit(server, client);
    }

    ret = quicly_open_stream(client, &client_stream, 0);
    assert(ret == 0);
    ret = quicly_streambuf_egress_write(client_stream, "hello", 5);
    assert(ret == 0);

    transmit(client, server);
    transmit(server, client);

    /* reset one stream in both directions and close on the client-side */
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);

    // Set some losses to trigger ack frequency path
    server->egress.cc.num_loss_episodes = 5;
    client->egress.cc.num_loss_episodes = 5;

    ok(server->application->super.reordering_threshold == 1);
    ok(client->application->super.reordering_threshold == 1);

    const char *testdata = "hello";
    const int testdata_len = strlen(testdata);

    const int steps = 80;
    for (int i = 0; i < steps; i++) {
        quicly_stream_t *s = server_stream;
        if (i > steps / 2)
            s = client_stream;

        ret = quicly_streambuf_egress_write(s, testdata, testdata_len);
        assert(ret == 0);

        ptls_iovec_t buf = quicly_streambuf_ingress_get(s);
        quicly_streambuf_ingress_shift(s, buf.len);

        transmit(server, client);
        transmit(client, server);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    }

    // Both sides have updated their reordering thresholds
    ok(server->application->super.reordering_threshold == 3);
    ok(client->application->super.reordering_threshold == 3);

    quicly_free(client);
    quicly_free(server);
}

static void test_cid(void)
{
    subtest("received cid", test_received_cid);
    subtest("local cid", test_local_cid);
}

/**
 * test if quicly_accept correctly rejects a non-decryptable Initial packet with QUICLY_ERROR_DECRYPTION_FAILED
 */
static void test_nondecryptable_initial(void)
{
#define PACKET_LEN 1280
#define HEADER_LEN 18
#define LEN_HIGH (((PACKET_LEN - HEADER_LEN) & 0xff00) >> 8)
#define LEN_LOW ((PACKET_LEN - HEADER_LEN) & 0xff)
    uint8_t header[HEADER_LEN] = {
        /* first byte for Initial: 0b1100???? */
        0xc5,
        /* version (29) */
        0xff,
        0x00,
        0x00,
        0x1d,
        /* DCID len */
        0x08,
        /* DCID */
        0x83,
        0x94,
        0xc8,
        0xf0,
        0x3e,
        0x51,
        0x57,
        0x08,
        /* SCID len */
        0x00,
        /* SCID does not appear */
        /* token length */
        0x00,
        /* token does not appear */
        /* length */
        (0x40 | LEN_HIGH),
        LEN_LOW,
    };
    quicly_conn_t *server;
    uint8_t packetbuf[PACKET_LEN];
    struct iovec packet = {.iov_base = packetbuf, .iov_len = sizeof(packetbuf)};
    size_t num_decoded;
    quicly_decoded_packet_t decoded;
    quicly_error_t ret;

    /* create an Initial packet, with its payload all set to zero */
    memcpy(packetbuf, header, sizeof(header));
    memset(packetbuf + sizeof(header), 0, sizeof(packetbuf) - sizeof(header));
    num_decoded = decode_packets(&decoded, &packet, 1);
    ok(num_decoded == 1);

    /* decryption should fail */
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL);
    ok(ret == QUICLY_ERROR_DECRYPTION_FAILED);
#undef PACKET_LEN
#undef HEADER_LEN
#undef LEN_HIGH
#undef LEN_LOW
}

static void test_set_cc(void)
{
    quicly_conn_t *conn;
    quicly_error_t ret;

    ret = quicly_connect(&conn, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL, NULL);
    ok(ret == 0);

    quicly_stats_t stats;

    // init CC with pico
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // pico to pico
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // reno to pico
    quicly_set_cc(conn, &quicly_cc_type_reno);
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // cubic to pico
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    quicly_set_cc(conn, &quicly_cc_type_pico);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "pico") == 0);

    // pico to reno
    quicly_set_cc(conn, &quicly_cc_type_pico);
    quicly_set_cc(conn, &quicly_cc_type_reno);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "reno") == 0);

    // pico to cubic
    quicly_set_cc(conn, &quicly_cc_type_pico);
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "cubic") == 0);

    // reno to cubic
    quicly_set_cc(conn, &quicly_cc_type_reno);
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "cubic") == 0);

    // cubic to reno
    quicly_set_cc(conn, &quicly_cc_type_cubic);
    quicly_set_cc(conn, &quicly_cc_type_reno);
    ret = quicly_get_stats(conn, &stats);
    ok(ret == 0);
    ok(strcmp(stats.cc.type->name, "reno") == 0);
}

void test_ecn_index_from_bits(void)
{
    ok(get_ecn_index_from_bits(1) == 1);
    ok(get_ecn_index_from_bits(2) == 0);
    ok(get_ecn_index_from_bits(3) == 2);
}

static void test_jumpstart_cwnd(void)
{
    quicly_context_t unbounded_max = {
        .max_jumpstart_cwnd_packets = UINT32_MAX,
        .transport_params.max_udp_payload_size = 1200,
    };
    ok(derive_jumpstart_cwnd(&unbounded_max, 250, 1000000, 250) == 250000);
    ok(derive_jumpstart_cwnd(&unbounded_max, 250, 1000000, 400) == 250000); /* if RTT increases, CWND stays same */
    ok(derive_jumpstart_cwnd(&unbounded_max, 250, 1000000, 125) == 125000); /* if RTT decreses, CWND is reduced proportionally */

    quicly_context_t bounded_max = {
        .max_jumpstart_cwnd_packets = 64,
        .transport_params.max_udp_payload_size = 1250,
    };
    ok(derive_jumpstart_cwnd(&bounded_max, 250, 1000000, 250) == 80000);
}

static void test_setup_connected_peers(quicly_conn_t **client, quicly_conn_t **server)
{
    quicly_address_t dest, src;
    struct iovec datagrams[8];
    uint8_t packetsbuf[PTLS_ELEMENTSOF(datagrams) * quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(datagrams) * 4];
    size_t num_datagrams, num_decoded;
    quicly_error_t ret;

    ret = quicly_connect(client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL, NULL);
    ok(ret == 0);
    num_datagrams = sizeof(datagrams);
    ret = quicly_send(*client, &dest, &src, datagrams, &num_datagrams, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    num_decoded = decode_packets(decoded, datagrams, 1);
    ok(num_decoded == 1);
    ret = quicly_accept(server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL, NULL);
    ok(ret == 0);
    num_datagrams = transmit(*server, *client);
    ok(num_datagrams > 0);
    ok(quicly_get_state(*client) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_state(*server) == QUICLY_STATE_CONNECTED);
    exchange_until_idle(*client, *server);
}

static void test_setup_send_context(quicly_conn_t *conn, quicly_send_context_t *s, struct iovec *datagram, void *buf,
                                    size_t bufsize)
{
    assert(conn->application != NULL);

    *s = (quicly_send_context_t){
        .current.first_byte = -1,
        .datagrams = datagram,
        .max_datagrams = 1,
        .payload_buf = {.datagram = buf, .end = (uint8_t *)buf + bufsize},
        .send_window = bufsize,
        .dcid = get_dcid(conn, 0 /* path_index */),
    };
    lock_now(conn, 0);
    setup_send_space(conn, QUICLY_EPOCH_1RTT, s);
}

static struct {
    quicly_conn_t *conn;
    quicly_error_t err;
    char reason[64];
} test_state_exhaustion_closed_by_remote;

static void test_state_exhaustion_on_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, quicly_error_t err,
                                                      uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (test_state_exhaustion_closed_by_remote.conn == NULL) {
        test_state_exhaustion_closed_by_remote.conn = conn;
        test_state_exhaustion_closed_by_remote.err = err;
        memcpy(test_state_exhaustion_closed_by_remote.reason, reason, reason_len);
        test_state_exhaustion_closed_by_remote.reason[reason_len] = '\0';
    }
}

/**
 * This test checks STATE_EXHAUSTION error is correctly returned to the application, and if the application supplies the error code
 * to quicly, quicly sends a PROTCOL_VIOLATION error with the special reason phrase.
 */
static void test_state_exhaustion(void)
{
    static quicly_closed_by_remote_t closed_by_remote = {test_state_exhaustion_on_closed_by_remote};

    assert(quic_ctx.closed_by_remote == NULL);
    quic_ctx.closed_by_remote = &closed_by_remote;
    memset(&test_state_exhaustion_closed_by_remote, 0, sizeof(test_state_exhaustion_closed_by_remote));
    uint64_t orig_max_stream_data_bidi_remote = quic_ctx.transport_params.max_stream_data.bidi_remote;
    quic_ctx.transport_params.max_stream_data.bidi_remote = 65536; /* shrink to reduce # of gaps permitted */

    quicly_conn_t *client, *server;
    quicly_send_context_t s;
    struct iovec datagram;
    uint8_t buf[quic_ctx.transport_params.max_udp_payload_size];
    quicly_decoded_packet_t decoded;
    size_t num_datagrams, num_decoded;
    quicly_address_t dest, src;
    quicly_error_t ret = 0;

    test_setup_connected_peers(&client, &server);

    /* send up to 200 packets with stream frame having gaps and check that the receiver raises state exhaustion */
    for (size_t i = 0; i < 200; ++i) {
        test_setup_send_context(client, &s, &datagram, buf, sizeof(buf));
        do_allocate_frame(client, &s, 100, ALLOCATE_FRAME_TYPE_ACK_ELICITING);
        *s.dst++ = QUICLY_FRAME_TYPE_STREAM_BASE | QUICLY_FRAME_TYPE_STREAM_BIT_OFF | QUICLY_FRAME_TYPE_STREAM_BIT_LEN;
        s.dst = quicly_encodev(s.dst, 0);     /* stream id */
        s.dst = quicly_encodev(s.dst, i * 2); /* off */
        s.dst = quicly_encodev(s.dst, 1);     /* len */
        *s.dst++ = (uint8_t)('a' + (i * 2) % 26);
        commit_send_packet(client, &s, 0);
        unlock_now(client);

        num_decoded = decode_packets(&decoded, &datagram, 1);
        ok(num_decoded == 1);
        if ((ret = quicly_receive(server, NULL, &fake_address.sa, &decoded)) != 0)
            break;
    }
    ok(ret == QUICLY_ERROR_STATE_EXHAUSTION);

    /* upon state exhaustion, the receiving endpoint MAY send CONNECTION_CLOSE (in this test, state-exhaustion is sent) */
    quicly_close(server, ret, NULL);
    num_datagrams = 1;
    ret = quicly_send(server, &dest, &src, &datagram, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    num_decoded = decode_packets(&decoded, &datagram, 1);
    ret = quicly_receive(client, NULL, &fake_address.sa, &decoded);
    ok(ret == 0);
    ok(quicly_get_state(client) == QUICLY_STATE_DRAINING);

    /* sender should have received PROTOCOL_VIOLATION with the special reason phrase */
    ok(test_state_exhaustion_closed_by_remote.conn == client);
    ok(test_state_exhaustion_closed_by_remote.err == QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
    ok(strcmp(test_state_exhaustion_closed_by_remote.reason, "state exhaustion") == 0);

    quicly_free(client);
    quicly_free(server);

    quic_ctx.closed_by_remote = NULL;
    quic_ctx.transport_params.max_stream_data.bidi_remote = orig_max_stream_data_bidi_remote;
}

static void do_test_migration_during_handshake(int second_flight_from_orig_address)
{
    quicly_conn_t *client, *server;
    const struct sockaddr_in serveraddr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001), .sin_port = htons(12345)},
                             clientaddr1 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000002), .sin_port = htons(12345)},
                             clientaddr2 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000003), .sin_port = htons(12345)};
    quicly_address_t destaddr, srcaddr;
    struct iovec datagrams[10];
    uint8_t buf[quic_ctx.transport_params.max_udp_payload_size * 10];
    quicly_decoded_packet_t packets[40];
    size_t num_datagrams, num_packets;
    quicly_error_t ret;

    /* client send first flight */
    ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)&serveraddr, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                         NULL, NULL, NULL);
    ok(ret == 0);
    num_datagrams = 10;
    ret = quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    ok(num_datagrams > 0);

    /* server accepts and responds, but the packets are dropped */
    num_packets = decode_packets(packets, datagrams, num_datagrams);
    ok(num_packets == 1);
    ret = quicly_accept(&server, &quic_ctx, &destaddr.sa, (void *)&clientaddr1, packets, NULL, new_master_id(), NULL, NULL);
    ok(ret == 0);
    num_datagrams = 10;
    ret = quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
    ok(ret == 0);
    ok(num_datagrams > 0);

    /* loop until timeout */
    const struct sockaddr_in *clientaddr = second_flight_from_orig_address ? &clientaddr1 : &clientaddr2;
    while (1) {
        int64_t client_timeout = quicly_get_first_timeout(client), server_timeout = quicly_get_first_timeout(server),
                smaller_timeout = client_timeout < server_timeout ? client_timeout : server_timeout;
        if (quic_now < smaller_timeout)
            quic_now = smaller_timeout;

        /* when client times out, it resends Initials but from a different address and the server drops them */
        if (quic_now >= client_timeout) {
            num_datagrams = 10;
            ret = quicly_send(client, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
            if (ret == QUICLY_ERROR_FREE_CONNECTION)
                break;
            ok(ret == 0);
            ok(num_datagrams > 0);
            num_packets = decode_packets(packets, datagrams, num_datagrams);
            ok(num_packets > 0);
            for (size_t i = 0; i < num_packets; ++i) {
                ret = quicly_receive(server, (void *)&serveraddr, (void *)clientaddr, &packets[i]);
                if (clientaddr == &clientaddr1) {
                    ok(ret == 0);
                } else {
                    ok(ret == QUICLY_ERROR_PACKET_IGNORED);
                }
            }
            clientaddr = &clientaddr2;
        }

        /* when server times out it resends packets to the old client address */
        if (quic_now >= server_timeout) {
            num_datagrams = 10;
            ret = quicly_send(server, &destaddr, &srcaddr, datagrams, &num_datagrams, buf, sizeof(buf));
            if (ret == QUICLY_ERROR_FREE_CONNECTION)
                break;
            ok(ret == 0);
            ok(num_datagrams > 0);
            ok(destaddr.sin.sin_family == AF_INET);
            ok(destaddr.sin.sin_addr.s_addr == clientaddr1.sin_addr.s_addr);
        }
    }

    quicly_free(client);
    quicly_free(server);
}

static void test_migration_during_handshake(void)
{
    subtest("migrate-before-2nd", do_test_migration_during_handshake, 0);
    subtest("migrate-before-3nd", do_test_migration_during_handshake, 1);
}

static size_t test_stats_foreach_next_off;

static void test_stats_foreach_field(size_t off, size_t size)
{
    ok(test_stats_foreach_next_off == off);

    /* Due to alignment, padding might exist between two fields when their types are different. The `gaps` list calls out the ones
     * that "might" have such padding on some architectures. */
    static const size_t gaps[] = {
#define GAP(after, before) offsetof(quicly_stats_t, after), offsetof(quicly_stats_t, before)
        GAP(jumpstart.cwnd, token_sent.at),
        GAP(token_sent.rtt, rtt.minimum),
        GAP(loss_thresholds.use_packet_based, loss_thresholds.time_based_percentile),
        GAP(loss_thresholds.time_based_percentile, cc.cwnd),
        GAP(cc.ssthresh, cc.cwnd_initial),
        GAP(cc.num_ecn_loss_episodes, delivery_rate.latest),
#undef GAP
        SIZE_MAX};
    for (size_t i = 0; gaps[i] != SIZE_MAX; i += 2) {
        if (test_stats_foreach_next_off == gaps[i]) {
            test_stats_foreach_next_off = gaps[i + 1];
            return;
        }
    }

    /* otherwise, it is right after the current field */
    test_stats_foreach_next_off += size;
}

static void test_stats_foreach(void)
{
#define CHECK(fld, name)                                                                                                           \
    subtest(name, test_stats_foreach_field, offsetof(quicly_stats_t, fld), sizeof(((quicly_stats_t *)NULL)->fld));

    /* check QUICLY_STATS_FOREACH touches all fields, in the correct order */
    test_stats_foreach_next_off = 0;
    QUICLY_STATS_FOREACH(CHECK);
    ok(test_stats_foreach_next_off == sizeof(quicly_stats_t));

    /* check QUICLY_STATS_FOREACH_COUNTERS only check the counters */
    struct counters_only {
        QUICLY_STATS_PREBUILT_COUNTERS;
    };
    test_stats_foreach_next_off = 0;
    QUICLY_STATS_FOREACH_COUNTERS(CHECK);
    ok(test_stats_foreach_next_off == sizeof(struct counters_only));

#undef CHECK
}

int main(int argc, char **argv)
{
    static ptls_iovec_t cert;
    static ptls_openssl_sign_certificate_t cert_signer;
    static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .certificates = {&cert, 1},
                                    .sign_certificate = &cert_signer.super,
                                    .require_dhe_on_psk = 1};
    quic_ctx = quicly_spec_context;
    quic_ctx.tls = &tlsctx;
    quic_ctx.transport_params.max_streams_bidi = 10;
    quic_ctx.stream_open = &stream_open;
    quic_ctx.now = &get_now;

    fake_address.sa.sa_family = AF_INET;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* Explicitly load the legacy provider in addition to default, as we test Blowfish in one of the tests. */
    (void)OSSL_PROVIDER_load(NULL, "legacy");
    (void)OSSL_PROVIDER_load(NULL, "default");
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

    subtest("ack_frequency_handling", test_ack_frequency);
    subtest("error-codes", test_error_codes);
    subtest("enable_with_ratio255", test_enable_with_ratio255);
    subtest("next-packet-number", test_next_packet_number);
    subtest("address-token-codec", test_address_token_codec);
    subtest("ranges", test_ranges);
    subtest("rate", test_rate);
    subtest("record-receipt", test_record_receipt);
    subtest("frame", test_frame);
    subtest("maxsender", test_maxsender);
    subtest("pacer", test_pacer);
    subtest("sentmap", test_sentmap);
    subtest("loss", test_loss);
    subtest("adjust-stream-frame-layout", test_adjust_stream_frame_layout);
    subtest("test-vector", test_vector);
    subtest("test-retry-aead", test_retry_aead);
    subtest("transport-parameters", test_transport_parameters);
    subtest("cid", test_cid);
    subtest("simple", test_simple);
    subtest("stream-concurrency", test_stream_concurrency);
    subtest("lossy", test_lossy);
    subtest("test-nondecryptable-initial", test_nondecryptable_initial);
    subtest("set_cc", test_set_cc);
    subtest("ecn-index-from-bits", test_ecn_index_from_bits);
    subtest("jumpstart-cwnd", test_jumpstart_cwnd);
    subtest("jumpstart", test_jumpstart);
    subtest("cc", test_cc);

    subtest("state-exhaustion", test_state_exhaustion);
    subtest("migration-during-handshake", test_migration_during_handshake);

    subtest("stats-foreach", test_stats_foreach);

    return done_testing();
}
