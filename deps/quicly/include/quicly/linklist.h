/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#ifndef quicly_linklist_h
#define quicly_linklist_h

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>

typedef struct st_quicly_linklist_t {
    struct st_quicly_linklist_t *prev;
    struct st_quicly_linklist_t *next;
} quicly_linklist_t;

static void quicly_linklist_init(quicly_linklist_t *l);
static int quicly_linklist_is_linked(quicly_linklist_t *l);
static void quicly_linklist_insert(quicly_linklist_t *prev, quicly_linklist_t *n);
static void quicly_linklist_unlink(quicly_linklist_t *l);
static void quicly_linklist_insert_list(quicly_linklist_t *prev, quicly_linklist_t *l);

/* inline functions */

inline void quicly_linklist_init(quicly_linklist_t *l)
{
    l->prev = l->next = l;
}

inline int quicly_linklist_is_linked(quicly_linklist_t *l)
{
    return l->prev != l;
}

inline void quicly_linklist_insert(quicly_linklist_t *prev, quicly_linklist_t *n)
{
    assert(!quicly_linklist_is_linked(n));
    n->prev = prev;
    n->next = prev->next;
    n->prev->next = n;
    n->next->prev = n;
}

inline void quicly_linklist_unlink(quicly_linklist_t *l)
{
    l->prev->next = l->next;
    l->next->prev = l->prev;
    quicly_linklist_init(l);
}

inline void quicly_linklist_insert_list(quicly_linklist_t *prev, quicly_linklist_t *l)
{
    if (quicly_linklist_is_linked(l)) {
        l->next->prev = prev;
        l->prev->next = prev->next;
        prev->next->prev = l->prev;
        prev->next = l->next;
        quicly_linklist_init(l);
    }
}

#ifdef __cplusplus
}
#endif

#endif
