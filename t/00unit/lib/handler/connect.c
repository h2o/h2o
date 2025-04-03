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

static void test_masque_decode_hostport(void)
{
    h2o_mem_pool_t pool;
    h2o_iovec_t host;
    uint16_t port;

    h2o_mem_init_pool(&pool);

    ok(masque_decode_hostport(&pool, H2O_STRLIT("example.com/80/"), &host, &port));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("example.com")));
    ok(port == 80);

    ok(masque_decode_hostport(&pool, H2O_STRLIT("2001:db8:85a3::8a2e:370:7334/443/"), &host, &port));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("2001:db8:85a3::8a2e:370:7334")));
    ok(port == 443);

    ok(masque_decode_hostport(&pool, H2O_STRLIT("2001%3adb8%3a85a3%3a%3a8a2e%3a370%3a7334/443/"), &host, &port));
    ok(h2o_memis(host.base, host.len, H2O_STRLIT("2001:db8:85a3::8a2e:370:7334")));
    ok(port == 443);

    /* port must exist */
    ok(!masque_decode_hostport(&pool, H2O_STRLIT("example.com"), &host, &port));

    /* slash after port must exist */
    ok(!masque_decode_hostport(&pool, H2O_STRLIT("example.com/80"), &host, &port));

    h2o_mem_clear_pool(&pool);
}

static void add_ipv4_dest_addr(struct st_connect_generator_t *self, uint32_t ip, uint16_t port)
{
    struct st_server_address_t *addr = &self->server_addresses.list[self->server_addresses.size];
    self->server_addresses.size++;

    struct sockaddr_in *sa = h2o_mem_alloc(sizeof(*sa));
    *sa = (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = port,
        .sin_addr.s_addr = ip,
    };

    *addr = (struct st_server_address_t){
        .sa = (struct sockaddr *)sa,
        .salen = sizeof(*sa),
    };
}

static void add_ipv6_dest_addr(struct st_connect_generator_t *self, h2o_iovec_t ip, uint16_t port)
{
    struct st_server_address_t *addr = &self->server_addresses.list[self->server_addresses.size];
    self->server_addresses.size++;

    struct sockaddr_in6 *sa = h2o_mem_alloc(sizeof(*sa));
    *sa = (struct sockaddr_in6){
        .sin6_family = AF_INET6,
        .sin6_port = port,
    };
    assert(ip.len == sizeof(sa->sin6_addr.s6_addr));
    memcpy(sa->sin6_addr.s6_addr, ip.base, ip.len);

    *addr = (struct st_server_address_t){
        .sa = (struct sockaddr *)sa,
        .salen = sizeof(*sa),
    };
}

static uint32_t get_port(struct st_server_address_t *addr)
{
    switch (addr->sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sa = (struct sockaddr_in *)addr->sa;
        return sa->sin_port;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)addr->sa;
        return sa->sin6_port;
    }
    default:
        assert(0);
    }
}

static void test_get_next_server_address_for_connect(void)
{
    struct st_connect_generator_t self = {};
    add_ipv6_dest_addr(&self, h2o_iovec_init(H2O_STRLIT("AAAABBBBCCCC\0\0\0\1")), 1);
    add_ipv6_dest_addr(&self, h2o_iovec_init(H2O_STRLIT("AAAABBBBCCCC\0\0\0\2")), 2);
    add_ipv6_dest_addr(&self, h2o_iovec_init(H2O_STRLIT("AAAABBBBCCCC\0\0\0\3")), 3);
    add_ipv4_dest_addr(&self, 0x7f000001, 4);
    add_ipv4_dest_addr(&self, 0x7f000002, 5);
    add_ipv4_dest_addr(&self, 0x7f000003, 6);
    add_ipv4_dest_addr(&self, 0x7f000004, 7);
    add_ipv4_dest_addr(&self, 0x7f000005, 8);

    struct st_server_address_t *next_addr;

    /* Verify that the picked address alternates between v6 and v4 until only 1 address family remains */
    ok(self.pick_v4 == 0);
    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET6);
    ok(get_port(next_addr) == 1);
    ok(self.server_addresses.used == 1);
    ok(self.pick_v4 == 1);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET);
    ok(get_port(next_addr) == 4);
    ok(self.server_addresses.used == 2);
    ok(self.pick_v4 == 0);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET6);
    ok(get_port(next_addr) == 3);
    ok(self.server_addresses.used == 3);
    ok(self.pick_v4 == 1);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET);
    ok(get_port(next_addr) == 5);
    ok(self.server_addresses.used == 4);
    ok(self.pick_v4 == 0);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET6);
    ok(get_port(next_addr) == 2);
    ok(self.server_addresses.used == 5);
    ok(self.pick_v4 == 1);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET);
    ok(get_port(next_addr) == 6);
    ok(self.server_addresses.used == 6);
    ok(self.pick_v4 == 0);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET);
    ok(get_port(next_addr) == 7);
    ok(self.server_addresses.used == 7);
    ok(self.pick_v4 == 0);

    next_addr = get_next_server_address_for_connect(&self);
    assert(next_addr != NULL);
    ok(next_addr->sa->sa_family == AF_INET);
    ok(get_port(next_addr) == 8);
    ok(self.server_addresses.used == 8);
    ok(self.pick_v4 == 0);

    next_addr = get_next_server_address_for_connect(&self);
    ok(next_addr == NULL);
}

void test_lib__handler__connect_c()
{
    subtest("to_bitmask", test_to_bitmask);
    subtest("acl", test_acl);
    subtest("masque_decode_hostport", test_masque_decode_hostport);
    subtest("get_next_server_address_for_connect", test_get_next_server_address_for_connect);
}
