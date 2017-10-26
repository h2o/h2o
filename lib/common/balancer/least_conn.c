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
    pthread_mutex_t mutex;
};

static void construct(h2o_socketpool_target_vector_t *targets, void *unused, void **data)
{
    struct least_conn_t *self = h2o_mem_alloc(sizeof(*self));
    pthread_mutex_init(&self->mutex, NULL);
    *data = self;
}

static size_t selector(h2o_socketpool_target_vector_t *targets, void *_data, int *tried, void *dummy)
{
    size_t i;
    size_t result = 0;
    size_t least_conn = SIZE_MAX;
    struct least_conn_t *self = _data;

    pthread_mutex_lock(&self->mutex);

    assert(targets->size != 0);
    for (i = 0; i < targets->size; i++) {
        if (!tried[i] && targets->entries[i]->_shared.leased_count < least_conn) {
            least_conn = targets->entries[i]->_shared.leased_count;
            result = i;
        }
    }

    assert(result < targets->size);
    pthread_mutex_unlock(&self->mutex);
    return result;
}

static void finalize(void *data)
{
    struct least_conn_t *self = data;
    pthread_mutex_destroy(&self->mutex);
    free(data);
}

const h2o_balancer_callbacks_t *h2o_balancer_lc_get_callbacks() {
    static const h2o_balancer_callbacks_t lc_callbacks = {
        NULL,
        NULL,
        construct,
        selector,
        finalize
    };
    return &lc_callbacks;
}
