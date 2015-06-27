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
#ifndef h2o__time_h
#define h2o__time_h

#ifndef _WIN32
#define _timezone localt.tm_gmtoff
#endif
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define H2O_TIMESTR_RFC1123_LEN (sizeof("Sun, 06 Nov 1994 08:49:37 GMT") - 1)
#define H2O_TIMESTR_LOG_LEN (sizeof("29/Aug/2014:15:34:38 +0900") - 1)

/**
 * builds a RFC-1123 style date string
 */
void h2o_time2str_rfc1123(char *buf, struct tm *gmt);
/**
 * converts HTTP-date to packed format (or returns UINT64_MAX on failure)
 */
int h2o_time_parse_rfc1123(const char *s, size_t len, struct tm *tm);
/**
 * builds an Apache log-style date string
 */
void h2o_time2str_log(char *buf, time_t time);

#ifdef __cplusplus
}
#endif

#endif
