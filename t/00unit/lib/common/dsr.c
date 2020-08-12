/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
#include "picotls/openssl.h"
#include "quicly/defaults.h"
#include "../../test.h"
#include "../../../../lib/common/dsr.c"

static void test_parse_req(void)
{
    h2o_dsr_req_t req;

    memset(&req, 0x55, sizeof(req));

    ok(h2o_dsr_parse_req(&req, H2O_STRLIT("quic=4278190109, cipher=4865, address=\"127.0.0.1\""), 443));
    ok(req.quic_version == 0xff00001d);
    ok(req.cipher == 0x1301);
    ok(req.address.sa.sa_family == AF_INET);
    ok(req.address.sin.sin_addr.s_addr == htonl(0x7f000001));
    ok(req.address.sin.sin_port == htons(443));

    ok(h2o_dsr_parse_req(&req, H2O_STRLIT("quic=4278190109, cipher=4865, address=\"[2001:db8:85a3::8a2e:370:7334]:8443\""), 443));
    ok(req.quic_version == 0xff00001d);
    ok(req.cipher == 0x1301);
    ok(req.address.sa.sa_family == AF_INET6);
    ok(memcmp(&req.address.sin6.sin6_addr, "\x20\x01\x0d\xb8\x85\xa3\x00\x00\x00\x00\x8a\x2e\x03\x70\x73\x34", 16) == 0);
    ok(req.address.sin6.sin6_port == htons(8443));

    ok(!h2o_dsr_parse_req(&req, H2O_STRLIT(""), 443));
    ok(!h2o_dsr_parse_req(&req, H2O_STRLIT("quic=\"abc\", cipher=4865, address=\"127.0.0.1:8443\""), 443));
    ok(!h2o_dsr_parse_req(&req, H2O_STRLIT("protocol=4278190109, cipher=444865, address=\"127.0.0.1:8443\""), 443));
    ok(!h2o_dsr_parse_req(&req, H2O_STRLIT("protocol=4278190109, cipher=a, address=\"127.0.0.1:8443\""), 443));
}

static void test_encdec(void)
{
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(0x11223344);
    dest_addr.sin_port = htons(0x1234);

    static const unsigned char prefix[] = "\x40"
                                          "dcid"
                                          "\x00\x00"
                                          "\x08\x00";
    quicly_detached_send_packet_t detached = {
        .cipher = &ptls_openssl_aes256gcmsha384,
        .header_protection_secret = "0123456789abcdef0123456789abcdef0123456789abcdef",
        .aead_secret = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF0123456789abcdef",
        .datagram = prefix,
        .first_byte_at = 0,
        .payload_from = 7,
        .packet_number = 0,
    };

    /* encode instructions */
    h2o_dsr_instruction_builder_t builder = {.sock = (void *)"fake"};
    h2o_linklist_t anchor;
    h2o_dsr_decoded_instruction_t inst;
    ssize_t inst_len;

    h2o_linklist_init_anchor(&anchor);

    /* encode a group consisting of one instruction */
    ok(h2o_dsr_add_instruction(&builder, &anchor, (struct sockaddr *)&dest_addr, &detached, sizeof(prefix) - 1, 0, 256));
    ok(!h2o_linklist_is_empty(&anchor));

    /* decode  */
    inst_len = h2o_dsr_decode_instruction(&inst, (const uint8_t *)builder.buf->bytes, builder.buf->size);
    ok(inst_len > 0);
    ok(inst.type == H2O_DSR_DECODED_INSTRUCTION_SET_CONTEXT);
    h2o_buffer_consume(&builder.buf, inst_len);
    inst_len = h2o_dsr_decode_instruction(&inst, (const uint8_t *)builder.buf->bytes, builder.buf->size);
    ok(inst_len > 0);
    ok(inst.type == H2O_DSR_DECODED_INSTRUCTION_SEND_PACKET);
    h2o_buffer_consume(&builder.buf, inst_len);
    ok(builder.buf->size == 0);

    h2o_buffer_dispose(&builder.buf);
}

void test_lib__common__dsr_c(void)
{
    subtest("parse-req", test_parse_req);
    subtest("enc-dec", test_encdec);
}
