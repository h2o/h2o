/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#ifndef h2o__timeout_h
#define h2o__timeout_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "h2o/linklist.h"
#include "h2o/socket.h"

typedef struct st_h2o_timeout_entry_t h2o_timeout_entry_t;
typedef void (*h2o_timeout_cb)(h2o_timeout_entry_t *entry);

/**
 * an entry linked to h2o_timeout_t.
 * Modules willing to use timeouts should embed this object as part of itself, and link it to a specific timeout by calling
 * h2o_timeout_link.
 */
struct st_h2o_timeout_entry_t {
    uint64_t registered_at;
    h2o_timeout_cb cb;
    h2o_linklist_t _link;
};

/**
 * represents a collection of h2o_timeout_entry_t linked to a single timeout value
 */
typedef struct st_h2o_timeout_t {
    uint64_t timeout;
    h2o_linklist_t _link;
    h2o_linklist_t _entries; /* link list of h2o_timeout_entry_t */
    struct st_h2o_timeout_backend_properties_t _backend;
} h2o_timeout_t;

/**
 * initializes and registers a timeout
 * @param loop loop to which the timeout should be registered
 * @param timeout the timeout structure to be initialized
 * @param millis timeout in milliseconds
 */
void h2o_timeout_init(h2o_loop_t *loop, h2o_timeout_t *timeout, uint64_t millis);
/**
 *
 */
void h2o_timeout_dispose(h2o_loop_t *loop, h2o_timeout_t *timeout);
/**
 * activates a timeout entry, by linking it to a timeout
 */
void h2o_timeout_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);
/**
 * deactivates a timeout entry, by unlinking it from a timeout
 */
void h2o_timeout_unlink(h2o_timeout_entry_t *entry);
/**
 * returns a boolean value indicating if the timeout is linked (i.e. active) or not
 */
static int h2o_timeout_is_linked(h2o_timeout_entry_t *entry);

void h2o_timeout_run(h2o_loop_t *loop, h2o_timeout_t *timeout, uint64_t now);
uint64_t h2o_timeout_get_wake_at(h2o_linklist_t *timeouts);
void h2o_timeout__do_init(h2o_loop_t *loop, h2o_timeout_t *timeout);
void h2o_timeout__do_dispose(h2o_loop_t *loop, h2o_timeout_t *timeout);
void h2o_timeout__do_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry);
void h2o_timeout__do_post_callback(h2o_loop_t *loop);

/* inline defs */

inline int h2o_timeout_is_linked(h2o_timeout_entry_t *entry)
{
    return h2o_linklist_is_linked(&entry->_link);
}

#ifdef __cplusplus
}
#endif

#endif
