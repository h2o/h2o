/*
 * Copyright (c) 2021 Fastly, Kazuho Oku
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
#include "../../../../lib/handler/connect.c"

static void test_to_bitmask(void)
{
    ok(TO_BITMASK(uint32_t, 8) == 0xff000000);
    ok(TO_BITMASK(uint32_t, 15) == 0xfffe0000);
    ok(TO_BITMASK(uint32_t, 24) == 0xffffff00);
    ok(TO_BITMASK(uint32_t, 27) == 0xffffffe0);
    ok(TO_BITMASK(uint32_t, 32) == 0xffffffff);
    ok(TO_BITMASK(uint8_t, 1) == 0x80);
    ok(TO_BITMASK(uint8_t, 8) == 0xff);
}

static void test_acl(void)
{
    h2o_connect_acl_entry_t entries[5];

    ok(h2o_connect_parse_acl(entries + 0, "+127.0.0.1:25") == NULL);
    ok(entries[0].allow_);
    ok(entries[0].addr_family == H2O_CONNECT_ACL_ADDRESS_V4);
    ok(entries[0].addr.v4 == 0x7f000001);
    ok(entries[0].addr_mask == 32);
    ok(entries[0].port == 25);

    ok(h2o_connect_parse_acl(entries + 1, "-127.0.0.0/24") == NULL);
    ok(!entries[1].allow_);
    ok(entries[1].addr_family == H2O_CONNECT_ACL_ADDRESS_V4);
    ok(entries[1].addr.v4 == 0x7f000000);
    ok(entries[1].addr_mask == 24);
    ok(entries[1].port == 0);

    ok(h2o_connect_parse_acl(entries + 2, "-*:25") == NULL);
    ok(!entries[2].allow_);
    ok(entries[2].addr_family == H2O_CONNECT_ACL_ADDRESS_ANY);
    ok(entries[2].port == 25);

    ok(h2o_connect_parse_acl(entries + 3, "-[2001:db8::]/33") == NULL);
    ok(!entries[3].allow_);
    ok(entries[3].addr_family == H2O_CONNECT_ACL_ADDRESS_V6);
    ok(memcmp(entries[3].addr.v6,
              "\x20\x01\x0d\xb8"
              "\0\0\0\0"
              "\0\0\0\0"
              "\0\0\0\0",
              16) == 0);
    ok(entries[3].addr_mask == 33);
    ok(entries[3].port == 0);

    ok(h2o_connect_parse_acl(entries + 4, "+*") == NULL);
    ok(entries[4].allow_);
    ok(entries[4].addr_family == H2O_CONNECT_ACL_ADDRESS_ANY);
    ok(entries[4].port == 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001);
    sin.sin_port = htons(25);
    ok(h2o_connect_lookup_acl(entries, PTLS_ELEMENTSOF(entries), (void *)&sin));
    sin.sin_port = htons(443);
    ok(!h2o_connect_lookup_acl(entries, PTLS_ELEMENTSOF(entries), (void *)&sin));
    sin.sin_addr.s_addr = htonl(0x01020304);
    sin.sin_port = htons(25);
    ok(!h2o_connect_lookup_acl(entries, PTLS_ELEMENTSOF(entries), (void *)&sin));
    sin.sin_port = htons(443);
    ok(h2o_connect_lookup_acl(entries, PTLS_ELEMENTSOF(entries), (void *)&sin));

    struct sockaddr_in6 sin6;
    sin6.sin6_family = AF_INET6;
    memcpy(sin6.sin6_addr.s6_addr,
           "\x20\x01\x0d\xb8"
           "\0\0\0\0"
           "\0\0\0\0"
           "\0\0\0\1",
           16);
    sin6.sin6_port = 443;
    ok(!h2o_connect_lookup_acl(entries, PTLS_ELEMENTSOF(entries), (void *)&sin6));
    sin6.sin6_addr.s6_addr[4] |= 0x80;
    ok(h2o_connect_lookup_acl(entries, PTLS_ELEMENTSOF(entries), (void *)&sin6));
}

void test_lib__handler__connect_c()
{
    subtest("to_bitmask", test_to_bitmask);
    subtest("acl", test_acl);
}
