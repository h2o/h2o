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

static size_t selector(h2o_balancer_t *ignored, h2o_socketpool_target_vector_t *targets, int *tried)
{
    size_t i;
    size_t result = -1;
    size_t result_weight = 0;
    uint64_t leftprod, rightprod;

    assert(targets->size != 0);
    for (i = 0; i < targets->size; i++) {
        if (!tried[i]) {
            result = i;
            result_weight = targets->entries[i]->conf->weight;
            break;
        }
    }
    /* I'm not sure if we should lock here. Or if difference between unlocked & locked could be acceptable. */
    for (i += 1; i < targets->size; i++) {
        leftprod = targets->entries[i]->_shared.leased_count;
        leftprod *= result_weight;
        rightprod = targets->entries[result]->_shared.leased_count;
        rightprod *= targets->entries[i]->conf->weight;
        if (!tried[i] && leftprod < rightprod) {
            result = i;
            result_weight = targets->entries[i]->conf->weight;
        }
    }

    assert(result < targets->size);
    return result;
}

static void destroy(h2o_balancer_t *ignored) {}

h2o_balancer_t *h2o_balancer_create_lc(void)
{
    static const h2o_balancer_callbacks_t lc_callbacks = {
        NULL,
        selector,
        destroy
    };
    static const size_t target_conf_len = sizeof(h2o_socketpool_target_conf_t);
    static h2o_balancer_t lc_balancer = {&lc_callbacks, target_conf_len};
    return &lc_balancer;
}
