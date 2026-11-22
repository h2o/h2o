/*
 * Copyright (c) 2021 Julien Benoist
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
#include "h2o/rand.h"
#include "h2o/balancer.h"

struct best_of_two {
    h2o_balancer_t super;
    pthread_mutex_t mutex;
};

static size_t selector(h2o_balancer_t *_self, h2o_socketpool_target_vector_t *targets, char *tried)
{
    size_t i, j;
    size_t left, right;
    size_t result_index;
    size_t idxs[targets->size];
    struct best_of_two *self = (void *)_self;

    assert(targets->size != 0);
    for (i = j = 0; i < targets->size; i++) {
      if (!tried[i]) {
        idxs[j++] = i;
      }
    }
    assert(j != 0);
    if (j == 1) {
      return idxs[0];
    }
    left = h2o_rand() % j;
    do {
      right = h2o_rand() % j;
    } while (left == right);
    left = idxs[left];
    right = idxs[right];
    pthread_mutex_lock(&self->mutex);
    result_index = targets->entries[left]->_shared.leased_count / (((unsigned)targets->entries[left]->conf.weight_m1) + 1) <
                   targets->entries[right]->_shared.leased_count / (((unsigned)targets->entries[right]->conf.weight_m1) + 1) ? left : right;
    pthread_mutex_unlock(&self->mutex);
    assert(result_index < targets->size);
    return result_index;
}

static void destroy(h2o_balancer_t *_self)
{
    struct best_of_two *self = (void *)_self;
    pthread_mutex_destroy(&self->mutex);
    free(self);
}

h2o_balancer_t *h2o_balancer_create_bo2(void)
{
    static const h2o_balancer_callbacks_t bo2_callbacks = {selector, destroy};
    struct best_of_two *self = h2o_mem_alloc(sizeof(*self));
    self->super.callbacks = &bo2_callbacks;
    pthread_mutex_init(&self->mutex, NULL);
    return &self->super;
}
