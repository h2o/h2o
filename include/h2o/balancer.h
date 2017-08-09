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

#include "h2o/socketpool.h"
#include "yoml.h"

/* function for configure per-target extra data when parsing configuration. node = NULL for default */
typedef int (*h2o_balancer_per_target_conf_parser)(yoml_t *node, void **data, yoml_t **errnode, char **errstr);

/* round robin */
void h2o_balancer_rr_init(h2o_socketpool_target_vector_t *targets, void **data);
size_t h2o_balancer_rr_selector(h2o_socketpool_target_vector_t *targets, h2o_socketpool_target_status_vector_t *status,
                                void *_data, int *tried, void *dummy);
void h2o_balancer_rr_dispose(void *data);
int h2o_balancer_rr_per_target_conf_parser(yoml_t *node, void **data, yoml_t **errnode, char **errstr);

/* least connection */
void h2o_balancer_lc_init(h2o_socketpool_target_vector_t *targets, void **data);
size_t h2o_balancer_lc_selector(h2o_socketpool_target_vector_t *targets, h2o_socketpool_target_status_vector_t *status,
                                void *_data, int *tried, void *dummy);
void h2o_balancer_lc_dispose(void *data);

#ifdef __cplusplus
}
#endif

#endif
