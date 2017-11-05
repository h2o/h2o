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
    size_t next_pos;           /* counting next logic index */
    size_t next_actual_target; /* indicate next actual target index */
    size_t *floor_next_target; /* caching logic indices indicating next target should be used */
    size_t pos_less_than;      /* return point for logic count */
    pthread_mutex_t mutex;
};

static void construct(h2o_socketpool_target_vector_t *targets, void *unused, void **data)
{
    size_t i;
    struct round_robin_t *self = h2o_mem_alloc(sizeof(*self));
    self->next_pos = 0;
    self->next_actual_target = 0;
    pthread_mutex_init(&self->mutex, NULL);
    self->floor_next_target = h2o_mem_alloc(sizeof(*self->floor_next_target) * targets->size);

    self->floor_next_target[0] = targets->entries[0]->conf.weight;
    for (i = 1; i < targets->size; i++) {
        self->floor_next_target[i] = self->floor_next_target[i - 1] + targets->entries[i]->conf.weight;
    }
    self->pos_less_than = self->floor_next_target[targets->size - 1];
    *data = self;
}

static size_t selector(h2o_socketpool_target_vector_t *targets, void *_data, int *tried, h2o_balancer_request_info *dummy)
{
    size_t i;
    size_t result = 0;
    struct round_robin_t *self = _data;

    pthread_mutex_lock(&self->mutex);

    assert(targets->size != 0);
    for (i = 0; i < targets->size; i++) {
        if (!tried[self->next_actual_target]) {
            /* get the result */
            result = self->next_actual_target;
            break;
        }
        /* this target has been tried, fall to next target */
        self->next_pos = self->floor_next_target[self->next_actual_target];
        self->next_actual_target++;
        if (self->next_pos == self->pos_less_than) {
            self->next_pos = 0;
            self->next_actual_target = 0;
        }
    }

    assert(i < targets->size);
    self->next_pos++;
    if (self->next_pos == self->floor_next_target[self->next_actual_target]) {
        self->next_actual_target++;
    }
    if (self->next_pos == self->pos_less_than) {
        self->next_pos = 0;
        self->next_actual_target = 0;
    }
    pthread_mutex_unlock(&self->mutex);
    return result;
}

static void finalize(void *data)
{
    struct round_robin_t *self = data;
    pthread_mutex_destroy(&self->mutex);
    free(self->floor_next_target);
    free(data);
}

const h2o_balancer_callbacks_t *h2o_balancer_rr_get_callbacks() {
    static const h2o_balancer_callbacks_t rr_callbacks = {
        construct,
        selector,
        finalize
    };
    return &rr_callbacks;
}
