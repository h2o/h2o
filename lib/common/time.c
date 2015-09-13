/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "h2o/time_.h"

static char *emit_wday(char *dst, int wday)
{
    memcpy(dst, ("SunMonTueWedThuFriSat") + wday * 3, 3);
    return dst + 3;
}

static char *emit_mon(char *dst, int mon)
{
    memcpy(dst, ("JanFebMarAprMayJunJulAugSepOctNovDec") + mon * 3, 3);
    return dst + 3;
}

static char *emit_digits(char *dst, int n, size_t cnt)
{
    char *p = dst + cnt;

    /* emit digits from back */
    do {
        *--p = '0' + n % 10;
        n /= 10;
    } while (p != dst);

    return dst + cnt;
}

void h2o_time2str_rfc1123(char *buf, struct tm *gmt)
{
    char *p = buf;

    /* format: Fri, 19 Sep 2014 05:24:04 GMT */
    p = emit_wday(p, gmt->tm_wday);
    *p++ = ',';
    *p++ = ' ';
    p = emit_digits(p, gmt->tm_mday, 2);
    *p++ = ' ';
    p = emit_mon(p, gmt->tm_mon);
    *p++ = ' ';
    p = emit_digits(p, gmt->tm_year + 1900, 4);
    *p++ = ' ';
    p = emit_digits(p, gmt->tm_hour, 2);
    *p++ = ':';
    p = emit_digits(p, gmt->tm_min, 2);
    *p++ = ':';
    p = emit_digits(p, gmt->tm_sec, 2);
    memcpy(p, " GMT", 4);
    p += 4;
    *p = '\0';

    assert(p - buf == H2O_TIMESTR_RFC1123_LEN);
}

static int fetch_digits(const char *s, size_t n)
{
    int value = 0;
    for (; n != 0; ++s, --n) {
        if (!('0' <= *s && *s <= '9'))
            return -1;
        value = value * 10 + *s - '0';
    }
    return value;
}

int h2o_time_parse_rfc1123(const char *s, size_t len, struct tm *tm)
{
    if (len != H2O_TIMESTR_RFC1123_LEN)
        return -1;

/*           1         2
 * 01234567890123456789012345678
 * Fri, 19 Sep 2014 05:24:04 GMT
 */

#define FETCH(dst, pos, n)                                                                                                         \
    if ((dst = fetch_digits(s + pos, n)) == -1)                                                                                    \
        return -1;
    FETCH(tm->tm_year, 12, 4);
    tm->tm_year -= 1900;
    /* month is parsed afterwards */
    FETCH(tm->tm_mday, 5, 2);
    FETCH(tm->tm_hour, 17, 2);
    FETCH(tm->tm_min, 20, 2);
    FETCH(tm->tm_sec, 23, 2);
#undef FETCH

#define PACK3(a, b, c) (((a)&0xff) << 16 | ((b)&0xff) << 8 | ((c)&0xff))
#define MAP(c1, c2, c3, value)                                                                                                     \
    case PACK3(c1, c2, c3):                                                                                                        \
        tm->tm_mon = value;                                                                                                        \
        break
    switch (PACK3(s[8], s[9], s[10])) {
        MAP('J', 'a', 'n', 0);
        MAP('F', 'e', 'b', 1);
        MAP('M', 'a', 'r', 2);
        MAP('A', 'p', 'r', 3);
        MAP('M', 'a', 'y', 4);
        MAP('J', 'u', 'n', 5);
        MAP('J', 'u', 'l', 6);
        MAP('A', 'u', 'g', 7);
        MAP('S', 'e', 'p', 8);
        MAP('O', 'c', 't', 9);
        MAP('N', 'o', 'v', 10);
        MAP('D', 'e', 'c', 11);
    default:
        return -1;
    }
#undef MAP
#undef PACK3

    return 0;
}

static int calc_gmt_offset(time_t t, struct tm *local)
{
    struct tm gmt;
    int delta;

    gmtime_r(&t, &gmt);
    delta = (local->tm_hour - gmt.tm_hour) * 60 + (local->tm_min - gmt.tm_min);

    if (local->tm_yday != gmt.tm_yday) {
        int day_offset;
        if (local->tm_year == gmt.tm_year)
            day_offset = local->tm_yday - gmt.tm_yday;
        else
            day_offset = local->tm_year - gmt.tm_year;
        delta += day_offset * 24 * 60;
    }
    return delta;
}

void h2o_time2str_log(char *buf, time_t time)
{
    struct tm localt;
    localtime_r(&time, &localt);
    int gmt_off = calc_gmt_offset(time, &localt);
    int gmt_sign;

    if (gmt_off >= 0) {
        gmt_sign = '+';
    } else {
        gmt_off = -gmt_off;
        gmt_sign = '-';
    }

    int len = sprintf(buf, "%02d/%s/%d:%02d:%02d:%02d %c%02d%02d", localt.tm_mday,
                      ("Jan\0Feb\0Mar\0Apr\0May\0Jun\0Jul\0Aug\0Sep\0Oct\0Nov\0Dec\0") + localt.tm_mon * 4, localt.tm_year + 1900,
                      localt.tm_hour, localt.tm_min, localt.tm_sec, gmt_sign, gmt_off / 60, gmt_off % 60);
    assert(len == H2O_TIMESTR_LOG_LEN);
}
