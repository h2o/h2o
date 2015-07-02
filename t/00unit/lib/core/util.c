/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include "../../test.h"
#include "../../../../lib/core/util.c"

static void test_parse_proxy_line(void)
{
    char in[256];
    struct sockaddr_storage sa;
    ssize_t ret;

    strcpy(in, "");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == -2);

    strcpy(in, "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\nabc");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == strlen(in) - 3);
    ok(sa.ss_family == AF_INET);
    ok(((struct sockaddr_in *)&sa)->sin_addr.s_addr == htonl(0xc0a80001));
    ok(((struct sockaddr_in *)&sa)->sin_port == htons(56324));

    strcpy(in, "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == -2);

    strcpy(in, "PROXY TCP5");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == -1);

    strcpy(in, "PROXY UNKNOWN");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == -2);

    strcpy(in, "PROXY UNKNOWN\r\nabc");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == strlen(in) - 3);
    ok(sa.ss_len == 0);

    strcpy(in, "PROXY TCP6 ::1 ::1 56324 443\r\n");
    ret = parse_proxy_line(in, strlen(in), (void *)&sa);
    ok(ret == strlen(in));
    ok(sa.ss_family == AF_INET6);
    ok(memcmp(&((struct sockaddr_in6 *)&sa)->sin6_addr, H2O_STRLIT("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1")) == 0);
    ok(((struct sockaddr_in6 *)&sa)->sin6_port == htons(56324));
}

void test_lib__core__util_c()
{
    subtest("parse_proxy_line", test_parse_proxy_line);
}
