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
#ifndef h2o__t__test_h
#define h2o__t__test_h

#include "picotest.h"
#include "h2o.h"

typedef struct st_h2o_loopback_conn_t {
    h2o_conn_t super;
    /**
     * the response
     */
    h2o_buffer_t *body;
    /* internal structure */
    h2o_ostream_t _ostr_final;
    int _is_complete;
    /**
     * the HTTP request / response (intentionally placed at the last, since it is a large structure and has it's own ctor)
     */
    h2o_req_t req;
} h2o_loopback_conn_t;

h2o_loopback_conn_t *h2o_loopback_create(h2o_context_t *ctx, h2o_hostconf_t **hosts);
void h2o_loopback_destroy(h2o_loopback_conn_t *conn);
void h2o_loopback_run_loop(h2o_loopback_conn_t *conn);

extern h2o_loop_t *test_loop;

char *sha1sum(const void *src, size_t len);

void test_lib__common__cache_c(void);
void test_lib__common__hostinfo_c(void);
void test_lib__common__multithread_c(void);
void test_lib__common__serverutil_c(void);
void test_lib__common__socket_c(void);
void test_lib__common__string_c(void);
void test_lib__common__time_c(void);
void test_lib__common__url_c(void);
void test_lib__core__headers_c(void);
void test_lib__core__proxy_c(void);
void test_lib__core__util_c(void);
void test_lib__handler__fastcgi_c(void);
void test_lib__handler__file_c(void);
void test_lib__handler__gzip_c(void);
void test_lib__handler__headers_c(void);
void test_lib__handler__mimemap_c(void);
void test_lib__handler__redirect_c(void);
void test_lib__http2__hpack(void);
void test_lib__http2__scheduler(void);
void test_lib__http2__casper(void);
void test_lib__http2__cache_digests(void);
void test_src__ssl_c(void);
void test_issues293(void);
void test_percent_encode_zero_byte(void);

#endif
