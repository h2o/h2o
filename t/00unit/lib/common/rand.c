/*
 * Copyright (c) 2021 Goro Fuji, Fastly, Inc.
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
#include "../../../../lib/common/rand.c"

static void test_format_uuid_rfc4122(void)
{
    uint8_t octets[16] = {0};
    char dst[H2O_UUID_STR_RFC4122_LEN + 1];

    format_uuid_rfc4122(dst, octets, 4);
    ok(strlen(dst) == H2O_UUID_STR_RFC4122_LEN);
    ok(strcmp(dst, "00000000-0000-4000-8000-000000000000") == 0);

    memset(octets, 0xff, sizeof(octets));
    format_uuid_rfc4122(dst, octets, 4);
    ok(strlen(dst) == H2O_UUID_STR_RFC4122_LEN);
    ok(strcmp(dst, "ffffffff-ffff-4fff-bfff-ffffffffffff") == 0);
}

void test_lib__common__rand_c(void)
{
    subtest("format_uuid_rfc4122", test_format_uuid_rfc4122);
}
