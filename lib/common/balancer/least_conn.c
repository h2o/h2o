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
#include <pthread.h>
#include "h2o/memory.h"
#include "h2o/balancer.h"

struct least_conn_t {
    h2o_balancer_t super;
    pthread_mutex_t mutex;
    h2o_balancer_lc_get_conn_count_cb get_conn_count_cb;
};

static size_t selector(h2o_balancer_t *balancer, h2o_balancer_backend_t **backends,
                       size_t backends_len, char *tried)
{
    struct least_conn_t *self = (void *)balancer;
    size_t i;
    size_t result_index = -1;
    size_t result_weight = 0;
    size_t result_leased = 1;
    size_t *conn_count;
    uint64_t leftprod, rightprod;

    assert(backends_len != 0);
    pthread_mutex_lock(&self->mutex);
    conn_count = alloca(backends_len * sizeof(*conn_count));
    self->get_conn_count_cb(conn_count, backends, backends_len);
    for (i = 0; i < backends_len; i++) {
        leftprod = conn_count[i];
        leftprod *= result_weight;
        rightprod = result_leased;
        rightprod *= ((unsigned)backends[i]->weight_m1) + 1;
        if (!tried[i] && leftprod < rightprod) {
            result_index = i;
            result_leased = conn_count[i];
            result_weight = ((unsigned)backends[i]->weight_m1) + 1;
        }
    }
    pthread_mutex_unlock(&self->mutex);

    assert(result_index < backends_len);
    return result_index;
}

static void destroy(h2o_balancer_t *_self)
{
    struct least_conn_t *self = (void *)_self;
    pthread_mutex_destroy(&self->mutex);
    free(self);
}

h2o_balancer_t *h2o_balancer_create_lc(h2o_balancer_lc_get_conn_count_cb conn_count_cb)
{
    static const h2o_balancer_callbacks_t lc_callbacks = {selector, destroy};
    struct least_conn_t *self = h2o_mem_alloc(sizeof(*self));
    self->super.callbacks = &lc_callbacks;
    self->get_conn_count_cb = conn_count_cb;
    pthread_mutex_init(&self->mutex, NULL);
    return &self->super;
}
