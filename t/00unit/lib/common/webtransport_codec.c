/*
 * Copyright (c) 2026 Fastly, Inc.
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
#include "../../test.h"
#include "../../../../lib/common/webtransport_codec.c"

static void test_stream_prefix(void)
{
    static const struct {
        uint8_t wire[10];
        size_t len;
        uint64_t id;
    } vectors[] = {
        {{0x40, 0x54, 0x00}, 3, 0},
        {{0x40, 0x54, 0x04}, 3, 4},
        {{0x40, 0x54, 0x3c}, 3, 60},
        {{0x40, 0x54, 0x40, 0x40}, 4, 64},
        {{0x40, 0x54, 0x7f, 0xfc}, 4, 16380},
        {{0x40, 0x54, 0x80, 0x00, 0x40, 0x00}, 6, 16384},
        {{0x40, 0x54, 0xbf, 0xff, 0xff, 0xfc}, 6, UINT64_C(0x3ffffffc)},
        {{0x40, 0x54, 0xc0, 0, 0, 0, 0x40, 0, 0, 0}, 10, UINT64_C(0x40000000)},
        {{0x40, 0x54, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc}, 10, H2O_WEBTRANSPORT_H3_MAX_SESSION_ID},
    };

    for (size_t d = 0; d != 2; ++d) {
        uint64_t type = d == 0 ? H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI : H2O_WEBTRANSPORT_H3_SIGNAL_BIDI;
        for (size_t i = 0; i != PTLS_ELEMENTSOF(vectors); ++i) {
            uint8_t wire[10], buf[H2O_WEBTRANSPORT_H3_MAX_STREAM_PREFIX_SIZE];
            memcpy(wire, vectors[i].wire, sizeof(wire));
            wire[1] = (uint8_t)type;
            uint8_t *end = h2o_webtransport_encode_stream_prefix(buf, type, vectors[i].id);
            ok(end - buf == vectors[i].len && memcmp(buf, wire, vectors[i].len) == 0);
            const uint8_t *src = wire;
            uint64_t id = 12345;
            ok(h2o_webtransport_decode_stream_prefix(&src, wire + vectors[i].len, type, &id) == 0);
            ok(src == wire + vectors[i].len && id == vectors[i].id);
            /* every truncation is incomplete, and leaves the cursor untouched */
            for (size_t len = 0; len != vectors[i].len; ++len) {
                src = wire;
                ok(h2o_webtransport_decode_stream_prefix(&src, wire + len, type, &id) == H2O_WEBTRANSPORT_DECODE_INCOMPLETE);
                ok(src == wire);
            }
            /* type mismatch */
            src = wire;
            ok(h2o_webtransport_decode_stream_prefix(&src, wire + vectors[i].len,
                                                     type == H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI
                                                         ? H2O_WEBTRANSPORT_H3_SIGNAL_BIDI
                                                         : H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI,
                                                     &id) == H2O_WEBTRANSPORT_DECODE_INVALID);
            ok(src == wire);
        }
    }

    /* non-minimal encodings are accepted */
    {
        static const uint8_t wire[] = {0x80, 0x00, 0x00, 0x41, 0xc0, 0, 0, 0, 0, 0, 0, 0x08};
        const uint8_t *src = wire;
        uint64_t id;
        ok(h2o_webtransport_decode_stream_prefix(&src, wire + sizeof(wire), H2O_WEBTRANSPORT_H3_SIGNAL_BIDI, &id) == 0);
        ok(src == wire + sizeof(wire) && id == 8);
    }

    /* session IDs must be client-initiated bidi stream IDs */
    static const uint8_t bad_ids[][3] = {{0x40, 0x54, 0x01}, {0x40, 0x54, 0x02}, {0x40, 0x54, 0x03}, {0x40, 0x54, 0x3d}};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(bad_ids); ++i) {
        const uint8_t *src = bad_ids[i];
        uint64_t id;
        ok(h2o_webtransport_decode_stream_prefix(&src, src + 3, H2O_WEBTRANSPORT_H3_STREAM_TYPE_UNI, &id) ==
           H2O_WEBTRANSPORT_DECODE_INVALID);
        ok(src == bad_ids[i]);
    }
}

static void test_datagram(void)
{
    uint8_t buf[16], *end;
    uint64_t qsid;
    h2o_iovec_t payload;

    end = h2o_webtransport_encode_datagram_prefix(buf, 1);
    ok(end - buf == 1 && buf[0] == 1);
    memcpy(end, "hello", 5);
    ok(h2o_webtransport_decode_datagram(h2o_iovec_init(buf, end + 5 - buf), &qsid, &payload) == 0);
    ok(qsid == 1 && h2o_memis(payload.base, payload.len, H2O_STRLIT("hello")));

    /* empty payload */
    ok(h2o_webtransport_decode_datagram(h2o_iovec_init(buf, 1), &qsid, &payload) == 0);
    ok(qsid == 1 && payload.len == 0);

    /* largest quarter stream ID */
    end = h2o_webtransport_encode_datagram_prefix(buf, H2O_WEBTRANSPORT_H3_MAX_QUARTER_STREAM_ID);
    ok(end - buf == 8);
    ok(h2o_webtransport_decode_datagram(h2o_iovec_init(buf, end - buf), &qsid, &payload) == 0);
    ok(qsid == H2O_WEBTRANSPORT_H3_MAX_QUARTER_STREAM_ID && payload.len == 0);

    /* out of range, truncated, empty */
    end = ptls_encode_quicint(buf, H2O_WEBTRANSPORT_H3_MAX_QUARTER_STREAM_ID + 1);
    ok(h2o_webtransport_decode_datagram(h2o_iovec_init(buf, end - buf), &qsid, &payload) == H2O_WEBTRANSPORT_DECODE_INVALID);
    ok(h2o_webtransport_decode_datagram(h2o_iovec_init(buf, 3), &qsid, &payload) == H2O_WEBTRANSPORT_DECODE_INVALID);
    ok(h2o_webtransport_decode_datagram(h2o_iovec_init(buf, 0), &qsid, &payload) == H2O_WEBTRANSPORT_DECODE_INVALID);
}

static void test_error_mapping(void)
{
    static const struct {
        uint32_t app;
        uint64_t h3;
    } vectors[] = {
        {0, UINT64_C(0x52e4a40fa8db)},
        {1, UINT64_C(0x52e4a40fa8dc)},
        {29, UINT64_C(0x52e4a40fa8f8)},
        {30, UINT64_C(0x52e4a40fa8fa)},
        {59, UINT64_C(0x52e4a40fa917)},
        {60, UINT64_C(0x52e4a40fa919)},
        {UINT32_MAX, H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_LAST},
    };
    uint32_t app;

    for (size_t i = 0; i != PTLS_ELEMENTSOF(vectors); ++i) {
        ok(h2o_webtransport_h3_error_from_application(vectors[i].app) == vectors[i].h3);
        ok(h2o_webtransport_h3_error_to_application(vectors[i].h3, &app) == 0 && app == vectors[i].app);
    }

    /* the mapping is a bijection between the application codes and the non-reserved codes of the range */
    uint32_t expected = 0;
    size_t num_errors = 0;
    for (uint64_t h3 = H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST; h3 < H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST + 65536;
         ++h3) {
        if ((h3 - 0x21) % 0x1f == 0) {
            if (h2o_webtransport_h3_error_to_application(h3, &app) != -1)
                ++num_errors;
        } else {
            if (!(h2o_webtransport_h3_error_to_application(h3, &app) == 0 && app == expected &&
                  h2o_webtransport_h3_error_from_application(app) == h3))
                ++num_errors;
            ++expected;
        }
    }
    ok(num_errors == 0);

    /* outside of the range, or reserved */
    static const uint64_t unmapped[] = {0,
                                        0x21,
                                        0x100,
                                        H2O_WEBTRANSPORT_H3_ERROR_SESSION_GONE,
                                        H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_FIRST - 1,
                                        UINT64_C(0x52e4a40fa8f9),
                                        H2O_WEBTRANSPORT_H3_ERROR_APPLICATION_LAST + 1,
                                        UINT64_MAX};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(unmapped); ++i) {
        app = 12345;
        ok(h2o_webtransport_h3_error_to_application(unmapped[i], &app) == -1 && app == 12345);
    }
}

static void test_utf8(void)
{
#define CHECK(s, expected) ok(h2o_webtransport_is_valid_utf8((const uint8_t *)(s), sizeof(s) - 1) == (expected))
    CHECK("", 1);
    CHECK("abc", 1);
    CHECK("\0", 1);
    CHECK("caf\xc3\xa9", 1);
    CHECK("\xe2\x82\xac", 1);
    CHECK("\xef\xbb\xbf", 1);     /* BOM */
    CHECK("\xf0\x9f\x98\x80", 1); /* U+1F600 */
    CHECK("\xf4\x8f\xbf\xbf", 1); /* U+10FFFF */
    CHECK("\xc0\x80", 0);         /* overlong */
    CHECK("\xc1\xbf", 0);         /* overlong */
    CHECK("\xe0\x80\x80", 0);     /* overlong */
    CHECK("\xf0\x80\x80\x80", 0); /* overlong */
    CHECK("\xed\xa0\x80", 0);     /* surrogate */
    CHECK("\xed\xbf\xbf", 0);     /* surrogate */
    CHECK("\xf4\x90\x80\x80", 0); /* above U+10FFFF */
    CHECK("\xf5\x80\x80\x80", 0); /* invalid lead */
    CHECK("\x80", 0);             /* stray continuation */
    CHECK("\xc3", 0);             /* truncated */
    CHECK("\xe2\x82", 0);         /* truncated */
    CHECK("\xe2\x28\xa1", 0);     /* bad continuation */
#undef CHECK
}

static void test_capsules(void)
{
    h2o_buffer_t *buf;
    const uint8_t *src, *end;
    uint64_t type, length, fields[3];

    h2o_buffer_init(&buf, &h2o_socket_buffer_prototype);

    /* WT_MAX_STREAM_DATA */
    h2o_webtransport_encode_varint_capsule(&buf, H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA, (uint64_t[]){4, 65536}, 2);
    ok(buf->size == 4 + 1 + 1 + 4);
    ok(memcmp(buf->bytes, "\x99\x0b\x4d\x3e\x05\x04\x80\x01\x00\x00", 10) == 0);
    src = (const uint8_t *)buf->bytes;
    end = src + buf->size;
    ok(h2o_webtransport_decode_capsule_header(&src, end, &type, &length) == 0);
    ok(type == H2O_WEBTRANSPORT_CAPSULE_MAX_STREAM_DATA && length == 5 && end - src == 5);
    ok(h2o_webtransport_decode_varint_capsule(h2o_iovec_init(src, length), fields, 2) == 0);
    ok(fields[0] == 4 && fields[1] == 65536);
    /* the number of fields must match exactly */
    ok(h2o_webtransport_decode_varint_capsule(h2o_iovec_init(src, length), fields, 1) == H2O_WEBTRANSPORT_DECODE_INVALID);
    ok(h2o_webtransport_decode_varint_capsule(h2o_iovec_init(src, length), fields, 3) == H2O_WEBTRANSPORT_DECODE_INVALID);
    /* every truncation of the header is incomplete, and leaves the cursor untouched */
    for (size_t len = 0; len != 5; ++len) {
        src = (const uint8_t *)buf->bytes;
        ok(h2o_webtransport_decode_capsule_header(&src, src + len, &type, &length) == H2O_WEBTRANSPORT_DECODE_INCOMPLETE);
        ok(src == (const uint8_t *)buf->bytes);
    }
    h2o_buffer_consume(&buf, buf->size);

    /* WT_DRAIN_SESSION */
    h2o_webtransport_encode_drain_session(&buf);
    ok(h2o_memis(buf->bytes, buf->size, H2O_STRLIT("\x80\x00\x78\xae\x00")));
    h2o_buffer_consume(&buf, buf->size);

    /* WT_CLOSE_SESSION */
    ok(h2o_webtransport_encode_close_session(&buf, 0x01020304, h2o_iovec_init(H2O_STRLIT("bye"))) == 0);
    ok(h2o_memis(buf->bytes, buf->size,
                 H2O_STRLIT("\x68\x43\x07\x01\x02\x03\x04"
                            "bye")));
    src = (const uint8_t *)buf->bytes;
    end = src + buf->size;
    ok(h2o_webtransport_decode_capsule_header(&src, end, &type, &length) == 0);
    ok(type == H2O_WEBTRANSPORT_CAPSULE_CLOSE_SESSION && length == 7);
    {
        uint32_t code;
        h2o_iovec_t reason;
        ok(h2o_webtransport_decode_close_session(h2o_iovec_init(src, length), &code, &reason) == 0);
        ok(code == 0x01020304 && h2o_memis(reason.base, reason.len, H2O_STRLIT("bye")));
        ok(h2o_webtransport_decode_close_session(h2o_iovec_init(src, 3), &code, &reason) == H2O_WEBTRANSPORT_DECODE_INVALID);
        ok(h2o_webtransport_decode_close_session(h2o_iovec_init("\0\0\0\0\xc3", 5), &code, &reason) ==
           H2O_WEBTRANSPORT_DECODE_INVALID);
    }
    h2o_buffer_consume(&buf, buf->size);

    /* empty reason, and the longest reason */
    {
        char reason[H2O_WEBTRANSPORT_MAX_CLOSE_REASON_SIZE + 1];
        uint32_t code;
        h2o_iovec_t decoded;
        memset(reason, 'x', sizeof(reason));
        ok(h2o_webtransport_encode_close_session(&buf, 0, h2o_iovec_init(NULL, 0)) == 0);
        ok(h2o_memis(buf->bytes, buf->size, H2O_STRLIT("\x68\x43\x04\x00\x00\x00\x00")));
        h2o_buffer_consume(&buf, buf->size);
        ok(h2o_webtransport_encode_close_session(&buf, 7, h2o_iovec_init(reason, sizeof(reason) - 1)) == 0);
        src = (const uint8_t *)buf->bytes;
        ok(h2o_webtransport_decode_capsule_header(&src, src + buf->size, &type, &length) == 0);
        ok(length == 4 + sizeof(reason) - 1);
        ok(h2o_webtransport_decode_close_session(h2o_iovec_init(src, length), &code, &decoded) == 0);
        ok(code == 7 && decoded.len == sizeof(reason) - 1);
        h2o_buffer_consume(&buf, buf->size);
        /* too long, or invalid UTF-8; the buffer is left untouched */
        ok(h2o_webtransport_encode_close_session(&buf, 0, h2o_iovec_init(reason, sizeof(reason))) == -1);
        ok(h2o_webtransport_encode_close_session(&buf, 0, h2o_iovec_init(H2O_STRLIT("\xed\xa0\x80"))) == -1);
        ok(buf->size == 0);
    }

    h2o_buffer_dispose(&buf);
}

static h2o_webtransport_protocol_selection_t select1(const char *field, size_t *selected)
{
    static const h2o_iovec_t supported[] = {{H2O_STRLIT("moqt-16")}, {H2O_STRLIT("a\"b\\c")}, {H2O_STRLIT("")}};
    h2o_iovec_t line = h2o_iovec_init(field, strlen(field));
    *selected = SIZE_MAX;
    return h2o_webtransport_select_protocol(&line, 1, supported, PTLS_ELEMENTSOF(supported), selected);
}

static void test_select_protocol(void)
{
    size_t selected;

    /* the first String offered by the client wins, not the server's order */
    ok(select1("\"x\", \"a\\\"b\\\\c\", \"moqt-16\"", &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 1);
    ok(select1("\"moqt-16\",\"a\\\"b\\\\c\"", &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 0);
    ok(select1("\"\"", &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 2);
    ok(select1("   \"moqt-16\"  \t", &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 0);
    ok(select1("\"moqt-15\" \t,\t \"moqt-16\"", &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 0);
    /* case-sensitive, exact after unescaping */
    ok(select1("\"MOQT-16\", \"moqt-16 \", \"moqt-1\", \"moqt-160\"", &selected) == H2O_WEBTRANSPORT_PROTOCOL_NONE &&
       selected == SIZE_MAX);
    ok(select1("", &selected) == H2O_WEBTRANSPORT_PROTOCOL_NONE && selected == SIZE_MAX);
    ok(select1("  ", &selected) == H2O_WEBTRANSPORT_PROTOCOL_NONE && selected == SIZE_MAX);

    /* parameters of every bare item type are skipped */
    static const char *const parameterized[] = {"\"moqt-16\";a",
                                                "\"moqt-16\";a=1;b=?0",
                                                "\"moqt-16\"; a=-12.345",
                                                "\"moqt-16\";*k-_.9=tok:en/x",
                                                "\"moqt-16\";a=\"s\\\\\"",
                                                "\"moqt-16\";a=:aGk=:",
                                                "\"moqt-16\";a=@-1",
                                                "\"moqt-16\";a=%\"%e2%82%ac x\"",
                                                "\"moqt-16\";a=123456789012345",
                                                "\"moqt-16\";a=123456789012.123"};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(parameterized); ++i)
        ok(select1(parameterized[i], &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 0);

    /* a match is not reported when some member invalidates the field */
    static const char *const invalid[] = {"moqt-16",
                                          "\"moqt-16\", moqt-16",
                                          "(\"moqt-16\")",
                                          "\"moqt-16\", 16",
                                          "\"moqt-16\", ?1",
                                          "\"moqt-16\",",
                                          "\"moqt-16\",,\"x\"",
                                          ",\"moqt-16\"",
                                          "\"moqt-16\" \"x\"",
                                          "\"moqt-16",
                                          "\"moqt-\\16\"",
                                          "\"caf\xc3\xa9\"",
                                          "\"tab\there\"",
                                          "\"moqt-16\";A=1",
                                          "\"moqt-16\";a=",
                                          "\"moqt-16\";a=1.",
                                          "\"moqt-16\";a=1.2345",
                                          "\"moqt-16\";a=1234567890123456",
                                          "\"moqt-16\";a=1234567890123.1",
                                          "\"moqt-16\";a=@1.5",
                                          "\"moqt-16\";a=?2",
                                          "\"moqt-16\";a=:a*:",
                                          "\"moqt-16\";a=:aGk=",
                                          "\"moqt-16\";a=%\"%C3%A9\"",
                                          "\"moqt-16\";a=%\"%c3\"",
                                          "\"moqt-16\";a=%\"%ed%a0%80\"",
                                          "\"moqt-16\";a=%\"%c0%80\"",
                                          "\"moqt-16\";a=%\"x",
                                          "\"moqt-16\";;a",
                                          "\t\"moqt-16\""};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(invalid); ++i) {
        ok(select1(invalid[i], &selected) == H2O_WEBTRANSPORT_PROTOCOL_INVALID);
        ok(selected == SIZE_MAX);
    }

    /* field lines constitute one List; an invalid line invalidates all of them */
    static const h2o_iovec_t supported[] = {{H2O_STRLIT("moqt-16")}};
    h2o_iovec_t lines[] = {{H2O_STRLIT("\"moqt-14\"")}, {H2O_STRLIT("")}, {H2O_STRLIT("\"moqt-16\"")}};
    ok(h2o_webtransport_select_protocol(lines, 3, supported, 1, &selected) == H2O_WEBTRANSPORT_PROTOCOL_SELECTED && selected == 0);
    lines[1] = h2o_iovec_init(H2O_STRLIT("token"));
    selected = SIZE_MAX;
    ok(h2o_webtransport_select_protocol(lines, 3, supported, 1, &selected) == H2O_WEBTRANSPORT_PROTOCOL_INVALID &&
       selected == SIZE_MAX);
    ok(h2o_webtransport_select_protocol(NULL, 0, supported, 1, &selected) == H2O_WEBTRANSPORT_PROTOCOL_NONE &&
       selected == SIZE_MAX);
    ok(h2o_webtransport_select_protocol(lines + 2, 1, NULL, 0, &selected) == H2O_WEBTRANSPORT_PROTOCOL_NONE &&
       selected == SIZE_MAX);

    /* WT-Protocol, as encoded by h2o_encode_sf_string, round-trips */
    {
        h2o_mem_pool_t pool;
        h2o_mem_init_pool(&pool);
        h2o_iovec_t encoded = h2o_encode_sf_string(&pool, H2O_STRLIT("a\"b\\c"));
        ok(h2o_memis(encoded.base, encoded.len, H2O_STRLIT("\"a\\\"b\\\\c\"")));
        ok(h2o_webtransport_select_protocol(&encoded, 1, (h2o_iovec_t[]){{H2O_STRLIT("a\"b\\c")}}, 1, &selected) ==
               H2O_WEBTRANSPORT_PROTOCOL_SELECTED &&
           selected == 0);
        h2o_mem_clear_pool(&pool);
    }
}

static int parse_init1(const char *field, h2o_webtransport_init_params_t *params)
{
    h2o_iovec_t line = h2o_iovec_init(field, strlen(field));
    *params = (h2o_webtransport_init_params_t){1, 2, 3};
    return h2o_webtransport_parse_init_header(&line, 1, params);
}

static void test_init_header(void)
{
    h2o_webtransport_init_params_t params;

    ok(parse_init1("u=100, bl=200, br=300", &params) == 0);
    ok(params.max_stream_data_uni == 100 && params.max_stream_data_bidi_local == 200 && params.max_stream_data_bidi_remote == 300);
    /* absent keys are left untouched */
    ok(parse_init1("bl=0", &params) == 0);
    ok(params.max_stream_data_uni == 1 && params.max_stream_data_bidi_local == 0 && params.max_stream_data_bidi_remote == 3);
    ok(parse_init1("", &params) == 0);
    ok(params.max_stream_data_uni == 1 && params.max_stream_data_bidi_local == 2 && params.max_stream_data_bidi_remote == 3);
    /* unknown keys are ignored, whatever their values are; parameters of known keys are ignored */
    ok(parse_init1("x=\"s\", y, z=(1 2);p=?1, w=1.5, u=999999999999999;q=1", &params) == 0);
    ok(params.max_stream_data_uni == 999999999999999 && params.max_stream_data_bidi_local == 2);
    /* the last value wins */
    ok(parse_init1("u=1, u=7", &params) == 0);
    ok(params.max_stream_data_uni == 7);

    /* the known keys must be non-negative Integers; nothing is updated upon error */
    static const char *const invalid[] = {"u=-1",   "u=1.5", "u",        "u=\"1\"", "u=(1)", "u=?1",
                                          "br=abc", "u=1,",  "u=1 bl=2", "U=1",     "u=",    "u=1234567890123456"};
    for (size_t i = 0; i != PTLS_ELEMENTSOF(invalid); ++i) {
        ok(parse_init1(invalid[i], &params) == -1);
        ok(params.max_stream_data_uni == 1 && params.max_stream_data_bidi_local == 2 && params.max_stream_data_bidi_remote == 3);
    }

    /* field lines constitute one Dictionary */
    h2o_iovec_t lines[] = {{H2O_STRLIT("u=10")}, {H2O_STRLIT("br=30, u=11")}};
    params = (h2o_webtransport_init_params_t){1, 2, 3};
    ok(h2o_webtransport_parse_init_header(lines, 2, &params) == 0);
    ok(params.max_stream_data_uni == 11 && params.max_stream_data_bidi_local == 2 && params.max_stream_data_bidi_remote == 30);
}

void test_lib__common__webtransport_codec_c(void)
{
    subtest("stream-prefix", test_stream_prefix);
    subtest("datagram", test_datagram);
    subtest("error-mapping", test_error_mapping);
    subtest("utf8", test_utf8);
    subtest("capsules", test_capsules);
    subtest("select-protocol", test_select_protocol);
    subtest("init-header", test_init_header);
}
