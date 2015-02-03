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
#ifndef h2o__memcached_h
#define h2o__memcached_h

#include "yrmcds.h"

typedef struct st_h2o_memcached_conn_t h2o_memcached_conn_t;
typedef struct st_h2o_memcached_request_t h2o_memcached_request_t;

typedef struct st_h2o_memcached_response_t {
    yrmcds_error err;
    yrmcds_command cmd;
    yrmcds_status status;
    void *app_data;
    union {
        h2o_iovec_t get;
    } data;
} h2o_memcached_response_t;

typedef void (*h2o_memcached_response_cb)(h2o_memcached_response_t *resp);

h2o_memcached_conn_t *h2o_memcached_open(const char *host, uint16_t port);
void h2o_memcached_dispatch_response(void);
h2o_memcached_request_t *h2o_memcached_get(h2o_memcached_conn_t *conn, const char *key, size_t keylen, h2o_memcached_response_cb cb,
                                           void *app_data);
h2o_memcached_request_t *h2o_memcached_set(h2o_memcached_conn_t *conn, const char *key, size_t keylen, const char *data,
                                           size_t datalen, uint32_t expires, h2o_memcached_response_cb cb, void *app_data);
h2o_memcached_request_t *h2o_memcached_remove(h2o_memcached_conn_t *conn, const char *key, size_t keylen,
                                              h2o_memcached_response_cb cb, void *app_data);
void h2o_memcached_discard_response(h2o_memcached_request_t *req);
void h2o_memcached_print_error(yrmcds_error err);

#endif
