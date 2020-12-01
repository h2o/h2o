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

static void on_destroy(quicly_stream_t *stream, int err);
static void on_egress_stop(quicly_stream_t *stream, int err);
static void on_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len);
static void on_ingress_reset(quicly_stream_t *stream, int err);

quicly_address_t fake_address;
int64_t quic_now = 1;
quicly_context_t quic_ctx;
quicly_stream_callbacks_t stream_callbacks = {
    on_destroy, quicly_streambuf_egress_shift, quicly_streambuf_egress_emit, on_egress_stop, on_ingress_receive, on_ingress_reset};
size_t on_destroy_callcnt;

static int64_t get_now_cb(quicly_now_t *self)
{
    return quic_now;
}

static quicly_now_t get_now = {get_now_cb};

void on_destroy(quicly_stream_t *stream, int err)
{
    test_streambuf_t *sbuf = stream->data;
    sbuf->is_detached = 1;
    ++on_destroy_callcnt;
}

void on_egress_stop(quicly_stream_t *stream, int err)
{
    assert(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    test_streambuf_t *sbuf = stream->data;
    sbuf->error_received.stop_sending = err;
}

void on_ingress_receive(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    quicly_streambuf_ingress_receive(stream, off, src, len);
}

void on_ingress_reset(quicly_stream_t *stream, int err)
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

static int on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream)
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
    const struct st_ptls_salt_t *salt = get_salt(QUICLY_PROTOCOL_VERSION_CURRENT);
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
    ptls_aead_context_t *retry_aead = create_retry_aead(&quic_ctx, QUICLY_PROTOCOL_VERSION_CURRENT, 0);
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
    ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, valid_bytes, valid_bytes + sizeof(valid_bytes),
                                              1) == 0);
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
    ok(quicly_decode_transport_parameter_list(&decoded, NULL, NULL, NULL, NULL, dup_bytes, dup_bytes + sizeof(dup_bytes), 1) ==
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
    int ret;

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

static void test_address_token_codec(void)
{
    static const uint8_t zero_key[PTLS_MAX_SECRET_SIZE] = {0};
    ptls_aead_context_t *enc = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 1, zero_key, ""),
                        *dec = ptls_aead_new(&ptls_openssl_aes128gcm, &ptls_openssl_sha256, 0, zero_key, "");
    quicly_address_token_plaintext_t input, output;
    ptls_buffer_t buf;
    const char *err_desc;

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

    /* check that the output is ok */
    ptls_openssl_random_bytes(&output, sizeof(output));
    ok(quicly_decrypt_address_token(dec, &output, buf.base, buf.off, 0, &err_desc) == 0);
    ok(input.type == output.type);
    ok(input.issued_at == output.issued_at);
    ok(input.remote.sa.sa_family == output.remote.sa.sa_family);
    ok(input.remote.sin.sin_addr.s_addr == output.remote.sin.sin_addr.s_addr);
    ok(input.remote.sin.sin_port == output.remote.sin.sin_port);
    ok(quicly_cid_is_equal(&output.retry.original_dcid,
                           ptls_iovec_init(input.retry.original_dcid.cid, input.retry.original_dcid.len)));
    ok(quicly_cid_is_equal(&output.retry.client_cid, ptls_iovec_init(input.retry.client_cid.cid, input.retry.client_cid.len)));
    ok(quicly_cid_is_equal(&output.retry.server_cid, ptls_iovec_init(input.retry.server_cid.cid, input.retry.server_cid.len)));
    ok(input.appdata.len == output.appdata.len);
    ok(memcmp(input.appdata.bytes, output.appdata.bytes, input.appdata.len) == 0);

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
    uint64_t pn = 0;
    int64_t now = 12345, send_ack_at = INT64_MAX;

    if (epoch == QUICLY_EPOCH_1RTT) {
        /* 2nd packet triggers an ack */
        ok(record_receipt(space, pn++, 0, now, &send_ack_at) == 0);
        ok(send_ack_at == now + QUICLY_DELAYED_ACK_TIMEOUT);
        now += 1;
        ok(record_receipt(space, pn++, 0, now, &send_ack_at) == 0);
        ok(send_ack_at == now);
        now += 1;
    } else {
        /* every packet triggers an ack */
        ok(record_receipt(space, pn++, 0, now, &send_ack_at) == 0);
        ok(send_ack_at == now);
        now += 1;
    }

    /* reset */
    space->unacked_count = 0;
    send_ack_at = INT64_MAX;

    /* ack-only packets do not elicit an ack */
    ok(record_receipt(space, pn++, 1, now, &send_ack_at) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    ok(record_receipt(space, pn++, 1, now, &send_ack_at) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    pn++; /* gap */
    ok(record_receipt(space, pn++, 1, now, &send_ack_at) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;
    ok(record_receipt(space, pn++, 1, now, &send_ack_at) == 0);
    ok(send_ack_at == INT64_MAX);
    now += 1;

    /* gap triggers an ack */
    pn += 1; /* gap */
    ok(record_receipt(space, pn++, 0, now, &send_ack_at) == 0);
    ok(send_ack_at == now);
    now += 1;

    /* reset */
    space->unacked_count = 0;
    send_ack_at = INT64_MAX;

    /* if 1-RTT, test ignore-order */
    if (epoch == QUICLY_EPOCH_1RTT) {
        space->ignore_order = 1;
        pn++; /* gap */
        ok(record_receipt(space, pn++, 0, now, &send_ack_at) == 0);
        ok(send_ack_at == now + QUICLY_DELAYED_ACK_TIMEOUT);
        now += 1;
        ok(record_receipt(space, pn++, 0, now, &send_ack_at) == 0);
        ok(send_ack_at == now);
        now += 1;
    }

    do_free_pn_space(space);
}

static void test_record_receipt(void)
{
    do_test_record_receipt(QUICLY_EPOCH_INITIAL);
    do_test_record_receipt(QUICLY_EPOCH_1RTT);
}

static void test_cid(void)
{
    subtest("received cid", test_received_cid);
    subtest("local cid", test_local_cid);
    subtest("retire cid", test_retire_cid);
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
    int ret;

    /* create an Initial packet, with its payload all set to zero */
    memcpy(packetbuf, header, sizeof(header));
    memset(packetbuf + sizeof(header), 0, sizeof(packetbuf) - sizeof(header));
    num_decoded = decode_packets(&decoded, &packet, 1);
    ok(num_decoded == 1);

    /* decryption should fail */
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
    ok(ret == QUICLY_ERROR_DECRYPTION_FAILED);
#undef PACKET_LEN
#undef HEADER_LEN
#undef LEN_HIGH
#undef LEN_LOW
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
                                    NULL,
                                    &cert_signer.super,
                                    NULL,
                                    0,
                                    0,
                                    0,
                                    NULL,
                                    1};
    quic_ctx = quicly_spec_context;
    quic_ctx.tls = &tlsctx;
    quic_ctx.transport_params.max_streams_bidi = 10;
    quic_ctx.stream_open = &stream_open;
    quic_ctx.now = &get_now;

    fake_address.sa.sa_family = AF_INET;

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
    subtest("address-token-codec", test_address_token_codec);
    subtest("ranges", test_ranges);
    subtest("record-receipt", test_record_receipt);
    subtest("frame", test_frame);
    subtest("maxsender", test_maxsender);
    subtest("sentmap", test_sentmap);
    subtest("loss", test_loss);
    subtest("test-vector", test_vector);
    subtest("test-retry-aead", test_retry_aead);
    subtest("transport-parameters", test_transport_parameters);
    subtest("cid", test_cid);
    subtest("simple", test_simple);
    subtest("stream-concurrency", test_stream_concurrency);
    subtest("lossy", test_lossy);
    subtest("test-nondecryptable-initial", test_nondecryptable_initial);

    return done_testing();
}
