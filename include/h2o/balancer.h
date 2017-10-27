/*
 * Copyright (c) 2017 Justin Zhu
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
#ifndef h2o__balancer_h
#define h2o__balancer_h

#ifdef __cplusplus
extern "C" {
#endif

#include <netdb.h>
#include "h2o/socketpool.h"
#include "yoml.h"

typedef struct st_h2o_balancer_request_info {
    char remote_addr[NI_MAXHOST];
    size_t remote_addr_len;
    int32_t port;
    h2o_iovec_t path;
} h2o_balancer_request_info;

/* function for configure per-target extra data when parsing configuration. node = NULL for default */
typedef int (*h2o_balancer_per_target_conf_parser)(yoml_t *node, void **data, yoml_t **errnode, char **errstr);

/* function for parsing overall configuration of a load balancer */
typedef int (*h2o_balancer_overall_conf_parser)(yoml_t *node, void **data, yoml_t **errnode, char **errstr);

typedef size_t (*h2o_balancer_selector)(h2o_socketpool_target_vector_t *targets, void *data, int *tried,
                                        h2o_balancer_request_info *req_info);

typedef void (*h2o_balancer_constructor)(h2o_socketpool_target_vector_t *targets, void *conf, void **data);

typedef void (*h2o_balancer_finalizer)(void *data);

typedef struct st_h2o_balancer_callbacks_t {
    h2o_balancer_per_target_conf_parser target_conf_parser;
    h2o_balancer_overall_conf_parser overall_conf_parser;
    h2o_balancer_constructor construct;
    h2o_balancer_selector selector;
    h2o_balancer_finalizer finalize;
} h2o_balancer_callbacks_t;

/* round robin */
const h2o_balancer_callbacks_t *h2o_balancer_rr_get_callbacks();

/* least connection */
const h2o_balancer_callbacks_t *h2o_balancer_lc_get_callbacks();

/* bounded hash */
const h2o_balancer_callbacks_t *h2o_balancer_hash_get_callbacks();

typedef enum en_h2o_balancer_hash_key_type {
    H2O_BALANCER_HASH_KEY_TYPE_PATH,
    H2O_BALANCER_HASH_KEY_TYPE_IP,
    H2O_BALANCER_HASH_KEY_TYPE_IP_PORT
} h2o_balancer_hash_key_type;

#ifdef __cplusplus
}
#endif

#endif
