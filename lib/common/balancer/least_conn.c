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
#include "h2o/balancer.h"

struct least_conn_t {
    h2o_balancer_t super;
    pthread_mutex_t mutex;
};

static size_t selector(h2o_balancer_t *_self, h2o_socketpool_target_vector_t *targets, int *tried)
{
    struct least_conn_t *self = (void *)_self;
    size_t i;
    size_t result_index = -1;
    size_t result_weight = 0;
    size_t result_leased = 1;
    uint64_t leftprod, rightprod;

    assert(targets->size != 0);
    pthread_mutex_lock(&self->mutex);
    for (i = 0; i < targets->size; i++) {
        leftprod = targets->entries[i]->_shared.leased_count;
        leftprod *= result_weight;
        rightprod = result_leased;
        rightprod *= ((unsigned)targets->entries[i]->conf.weight) + 1;
        if (!tried[i] && leftprod < rightprod) {
            result_index = i;
            result_leased = targets->entries[i]->_shared.leased_count;
            result_weight = ((unsigned)targets->entries[i]->conf.weight) + 1;
        }
    }
    pthread_mutex_unlock(&self->mutex);

    assert(result_index < targets->size);
    return result_index;
}

static void destroy(h2o_balancer_t *_self) {
    struct least_conn_t *self = (void *)_self;
    pthread_mutex_destroy(&self->mutex);
    free(self);
}

h2o_balancer_t *h2o_balancer_create_lc(void)
{
    static const h2o_balancer_callbacks_t lc_callbacks = {
        selector,
        destroy
    };
    struct least_conn_t *self = h2o_mem_alloc(sizeof(*self));
    self->super.callbacks = &lc_callbacks;
    pthread_mutex_init(&self->mutex, NULL);
    return &self->super;
}
