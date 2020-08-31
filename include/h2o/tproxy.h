/*
 * Copyright (c) 2020 Chul-Woong Yang
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
#ifndef h2o__tproxy_h
#define h2o__tproxy_h

#ifdef __cplusplus
//extern "C" {
#endif

#include "h2o.h"
#include "h2o/cache.h"
#include "h2o/socketpool.h"

h2o_httpclient_connection_pool_t *h2o_tproxy_get_connpool(h2o_cache_t *cache, h2o_req_t *req,
                                                          h2o_proxy_config_vars_t *config,
                                                          h2o_socketpool_t *_sockpool);
h2o_cache_t *h2o_tproxy_create_connpool_cache(size_t pool_duration);

#ifdef __cplusplus
//}
#endif

#endif
