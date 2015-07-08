/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__libmemcached_h
#define h2o__libmemcached_h

#include <pthread.h>
#include <time.h>
#include "h2o/memory.h"
#include "h2o/multithread.h"

typedef struct st_h2o_libmemcached_context_t h2o_libmemcached_context_t;
typedef struct st_h2o_libmemcached_req_t h2o_libmemcached_req_t;
typedef void (*h2o_libmemcached_get_cb)(h2o_iovec_t value, void *cb_data);

h2o_libmemcached_context_t *h2o_libmemcached_create_context(const char *config, size_t max_threads);

void h2o_libmemcached_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages);

h2o_libmemcached_req_t *h2o_libmemcached_get(h2o_libmemcached_context_t *ctx, h2o_multithread_receiver_t *receiver, h2o_iovec_t key,
                                             h2o_libmemcached_get_cb cb, void *cb_data);

void h2o_libmemcached_cancel_get(h2o_libmemcached_context_t *ctx, h2o_libmemcached_req_t *req);

void h2o_libmemcached_set(h2o_libmemcached_context_t *ctx, h2o_iovec_t key, h2o_iovec_t value, time_t expiration);

void h2o_libmemcached_delete(h2o_libmemcached_context_t *ctx, h2o_iovec_t key);

#endif
