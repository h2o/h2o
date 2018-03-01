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

typedef struct st_h2o_balancer_t h2o_balancer_t;

typedef size_t (*h2o_balancer_selector)(h2o_balancer_t *balancer, h2o_socketpool_target_vector_t *targets, char *tried, void *socketpool_req_data);

typedef void (*h2o_balancer_destroyer)(h2o_balancer_t *balancer);

typedef struct st_h2o_balancer_callbacks_t {
    h2o_balancer_selector select_;
    h2o_balancer_destroyer destroy;
} h2o_balancer_callbacks_t;

typedef enum en_h2o_balancer_type_t {
    H2O_BALANCER_TYPE_ROUND_ROBIN,
    H2O_BALANCER_TYPE_LEAST_CONN,
    H2O_BALANCER_TYPE_HASH
} h2o_balancer_type_t;

struct st_h2o_balancer_t {
    const h2o_balancer_callbacks_t *callbacks;
    const int idempotent;
    h2o_balancer_type_t type;
};

typedef enum en_h2o_balancer_hash_key_type_t {
    H2O_BALANCER_HASH_KEY_IP,
    H2O_BALANCER_HASH_KEY_IP_PORT,
    H2O_BALANCER_HASH_KEY_PATH
} h2o_balancer_hash_key_type_t;

/* round robin */
h2o_balancer_t *h2o_balancer_create_rr(void);

/* least connection */
h2o_balancer_t *h2o_balancer_create_lc(void);

/* consistent hashing with bound */
h2o_balancer_t *h2o_balancer_create_hash(float c, h2o_balancer_hash_key_type_t type);

typedef h2o_iovec_t (*h2o_balancer_hash_get_key_cb)(void *socketpool_req_data, h2o_balancer_hash_key_type_t key_type);
void h2o_balancer_hash_set_get_key_cb(h2o_balancer_t *balancer, h2o_balancer_hash_get_key_cb cb);
void h2o_balancer_hash_set_total_leased_count(h2o_balancer_t *balancer, size_t *total_leased_count);
void h2o_balancer_hash_set_targets(h2o_balancer_t *balancer, h2o_socketpool_target_t **targets, size_t num_targets);

#ifdef __cplusplus
}
#endif

#endif
