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

#include <stdint.h>

typedef struct st_h2o_balancer_backend_t h2o_balancer_backend_t;

typedef struct st_h2o_balancer_t h2o_balancer_t;

typedef size_t (*h2o_balancer_selector)(h2o_balancer_t *balancer, h2o_balancer_backend_t **backends,
                                        size_t backends_len, char *tried);

typedef void (*h2o_balancer_destroyer)(h2o_balancer_t *balancer);

typedef struct st_h2o_balancer_callbacks_t {
    h2o_balancer_selector select_;
    h2o_balancer_destroyer destroy;
} h2o_balancer_callbacks_t;

struct st_h2o_balancer_backend_t {
    /**
     * weight - 1 for load balancer, where weight is an integer within range [1, 256]
     */
    uint8_t weight_m1;
    /**
     * connection count
     */
    size_t conn_count;
};

struct st_h2o_balancer_t {
    const h2o_balancer_callbacks_t *callbacks;

    /**
     * need connection count
     */
    char conn_count_needed;
};

/* common */
static void h2o_balancer_inc_conn_count(h2o_balancer_t *balancer, h2o_balancer_backend_t *backend);
static void h2o_balancer_dec_conn_count(h2o_balancer_t *balancer, h2o_balancer_backend_t *backend);

/* round robin */
h2o_balancer_t *h2o_balancer_create_rr(void);

/* least connection */
h2o_balancer_t *h2o_balancer_create_lc(void);

inline void h2o_balancer_inc_conn_count(h2o_balancer_t *balancer, h2o_balancer_backend_t *backend)
{
    if (balancer != NULL && balancer->conn_count_needed)
        __sync_add_and_fetch(&backend->conn_count, 1);
}

inline void h2o_balancer_dec_conn_count(h2o_balancer_t *balancer, h2o_balancer_backend_t *backend)
{
    if (balancer != NULL && balancer->conn_count_needed)
        __sync_sub_and_fetch(&backend->conn_count, 1);
}

#ifdef __cplusplus
}
#endif

#endif
