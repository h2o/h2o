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

struct round_robin_t {
    h2o_balancer_t super;
    size_t pos;           /* current position */
    size_t remained_weight; /* remained weight of current position */
    pthread_mutex_t mutex;
};

static inline void select_next(struct round_robin_t *self, h2o_socketpool_target_vector_t *targets) {
    self->pos += 1;
    if (self->pos == targets->size)
        self->pos = 0;
    self->remained_weight = ((unsigned)targets->entries[self->pos]->conf->weight) + 1;
}

static size_t selector(h2o_balancer_t *balancer, h2o_socketpool_target_vector_t *targets, int *tried)
{
    size_t i;
    size_t result = 0;
    struct round_robin_t *self = (void *)balancer;
    
    if (H2O_UNLIKELY(self->pos == SIZE_MAX)) {
        self->pos = 0;
        self->remained_weight = ((unsigned)targets->entries[0]->conf->weight) + 1;
    }

    pthread_mutex_lock(&self->mutex);

    assert(targets->size != 0);
    for (i = 0; i < targets->size; i++) {
        if (!tried[self->pos]) {
            /* get the result */
            result = self->pos;
            if (--self->remained_weight == 0)
                select_next(self, targets);
            pthread_mutex_unlock(&self->mutex);
            return result;
        } else {
            select_next(self, targets);
        }
    }
    assert(!"unreachable");
}

static void destroy(h2o_balancer_t *balancer)
{
    struct round_robin_t *self = (void *)balancer;
    pthread_mutex_destroy(&self->mutex);
    free(self);
}

h2o_balancer_t *h2o_balancer_create_rr(void) {
    static const h2o_balancer_callbacks_t rr_callbacks = {
        selector,
        destroy
    };

    struct round_robin_t *self = h2o_mem_alloc(sizeof(*self));
    memset(self, 0, sizeof(*self));
    pthread_mutex_init(&self->mutex, NULL);
    self->super.callbacks = &rr_callbacks;
    self->pos = SIZE_MAX;
    self->remained_weight = 0;

    return &self->super;
}
