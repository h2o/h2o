/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include "../../../../lib/common/time.c"

void test_lib__common__time_c(void)
{
    struct tm tm = {
        56,  /* sec */
        34,  /* min */
        12,  /* hour */
        4,   /* 4th */
        1,   /* feb */
        115, /* 2015 */
        3    /* Wed */
    };
    char buf[H2O_TIMESTR_RFC1123_LEN + 1];

    h2o_time2str_rfc1123(buf, &tm);
    ok(strcmp(buf, "Wed, 04 Feb 2015 12:34:56 GMT") == 0);
    tm = (struct tm){0};
    h2o_time_parse_rfc1123(buf, H2O_TIMESTR_RFC1123_LEN, &tm);
    ok(tm.tm_year == 115);
    ok(tm.tm_mon == 1);
    ok(tm.tm_mday == 4);
    ok(tm.tm_hour == 12);
    ok(tm.tm_min == 34);
    ok(tm.tm_sec == 56);
}
