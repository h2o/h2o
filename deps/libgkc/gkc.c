/*
 * Copyright (c) 2016 Fastly, Inc.
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

/*
 * A streaming quantile library.
 *
 *
 * A `gkc_summary` structure is used to summarize observations
 * within a given error range. Observations are inserted using
 * `gkc_insert_value`, quantile queries can then be performed with
 * `gkc_query` against the summary.
 * Provided two summaries are using the same epsilon, they can be merged
 * by calling `gkc_combine`.
 *
 * The algorithm guaranties a bounded memory usage to:
 * (11/(2 x epsilon))*log(2 * epsilon * N)
 *
 * For epsilon = 0.01 and N = 2^64, this is only 10k max in the
 * theoritical worse case. In practice, it's reliably using less:
 * inserting random data gets us * ~100 max insertions for > 50 millions
 * of entries.
 *
 * See www.cis.upenn.edu/~sanjeev/papers/sigmod01_quantiles.pdf for
 * the paper describing this algorithm and data structure.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>

struct list {
    struct list *prev, *next;
};

struct gkc_summary {
    size_t nr_elems;
    double epsilon;
    uint64_t alloced;
    uint64_t max_alloced;
    struct list head;
    struct freelist *fl;
};


static inline int list_empty(struct list *l)
{
    return l->next == l;
}
static inline void list_init(struct list *n)
{
    n->next = n;
    n->prev = n;
}

static inline void list_del(struct list *n)
{
    n->next->prev = n->prev;
    n->prev->next = n->next;
}

static inline void list_add(struct list *l, struct list *n)
{
    n->next = l->next;
    n->next->prev = n;
    l->next = n;
    n->prev = l;
}

static inline void list_add_tail(struct list *l, struct list *n)
{
    list_add(l->prev, n);
}

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

struct freelist {
    struct freelist *next;
};

static uint64_t ullog2(uint64_t x)
{
    static const uint64_t debruijn_magic = 0x022fdd63cc95386dULL;

    static const uint64_t magic_table[] = {
        0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
        62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
        63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
        51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12,
    };

    x |= (x >> 1);
    x |= (x >> 2);
    x |= (x >> 4);
    x |= (x >> 8);
    x |= (x >> 16);
    x |= (x >> 32);
    return (magic_table[((x & ~(x>>1))*debruijn_magic)>>58]);
}

struct gkc_tuple {
    uint64_t value;
    double g;
    uint64_t delta;
    struct list node;
};
#define list_to_tuple(ln) (container_of((ln), struct gkc_tuple, node))


void gkc_summary_init(struct gkc_summary *s, double epsilon)
{
    list_init(&s->head);
    s->epsilon = epsilon;
}

struct gkc_summary *gkc_summary_alloc(double epsilon)
{
    struct gkc_summary *s;
    s = calloc(1, sizeof(*s));
    gkc_summary_init(s, epsilon);
    return s;
}

#include <assert.h>
/* debug only, checks a number of properties that s must satisfy at all times */
void gkc_sanity_check(struct gkc_summary *s)
{
    uint64_t nr_elems, nr_alloced;
    struct list *cur;
    struct gkc_tuple *tcur;

    nr_elems = 0;
    nr_alloced = 0;
    cur = s->head.next;
    while (cur != &s->head) {
        tcur = list_to_tuple(cur);
        cur = cur->next;
        nr_elems += tcur->g;
        nr_alloced++;
        if (s->nr_elems > (1/s->epsilon)) {
            /* there must be enough observations for this to become true */
            assert(tcur->g + tcur->delta <= (s->nr_elems * s->epsilon * 2));
        }
        assert(nr_alloced <= s->alloced);
    }
    assert(nr_elems == s->nr_elems);
    assert(nr_alloced == s->alloced);
}

static struct gkc_tuple *gkc_alloc(struct gkc_summary *s)
{
    s->alloced++;
    if (s->alloced > s->max_alloced) {
        s->max_alloced = s->alloced;
    }

    if (s->fl) {
        void *ret;
        ret = s->fl;
        s->fl = s->fl->next;
        return ret;
    }
    return malloc(sizeof(struct gkc_tuple));
}

static void gkc_free(struct gkc_summary *s, struct gkc_tuple *p)
{
    struct freelist *flp = (void *)p;
    s->alloced--;

    flp->next = s->fl;
    s->fl = flp;
}

void gkc_summary_free(struct gkc_summary *s)
{
    struct freelist *fl;
    struct list *cur;

    cur = s->head.next;
    while (cur != &s->head) {
        struct list *next;
        next = cur->next;
        gkc_free(s, list_to_tuple(cur));
        cur = next;
    }
    fl = s->fl;
    while (fl) {
        void *p;
        p = fl;
        fl = fl->next;
        free(p);
    }
    free(s);
}

uint64_t gkc_query(struct gkc_summary *s, double q)
{
    struct list *cur, *next;
    int rank;
    double gi;
    double ne;

    rank = 0.5 + q * s->nr_elems;
    ne = s->nr_elems * s->epsilon;
    gi = 0;
    if (list_empty(&s->head)) {
        return 0;
    }

    cur = s->head.next;

    while (1) {
        struct gkc_tuple *tcur, *tnext;

        tcur = list_to_tuple(cur);
        next = cur->next;
        if (next == &s->head) {
            return tcur->value;
        }
        tnext = list_to_tuple(next);

        gi += tcur->g;
        if ((rank + ne) < (gi + tnext->g + tnext->delta)) {
            if ((rank + ne) < (gi + tnext->g)) {
                return tcur->value;
            }
            return tnext->value;
        }
        cur = next;
    }
}

static uint64_t band(struct gkc_summary *s, uint64_t delta)
{
    uint64_t diff;

    diff = 1 + (s->epsilon * s->nr_elems * 2) - delta;

    if (diff == 1) {
        return 0;
    } else {
        return ullog2(diff)/ullog2(2);
    }
}

static void gkc_compress(struct gkc_summary *s)
{
    int max_compress;
    struct list *cur, *prev;
    struct gkc_tuple *tcur, *tprev;
    uint64_t bi, b_plus_1;

    max_compress = 2 * s->epsilon * s->nr_elems;
    if (s->nr_elems < 2) {
        return;
    }

    prev = s->head.prev;
    cur = prev->prev;

    while (cur != &s->head) {
        tcur = list_to_tuple(cur);
        tprev = list_to_tuple(prev);

        b_plus_1 = band(s, tprev->delta);
        bi = band(s, tcur->delta);

        if (bi <= b_plus_1 && ((tcur->g + tprev->g + tprev->delta) <= max_compress)) {
            tprev->g += tcur->g;
            list_del(cur);
            gkc_free(s, tcur);
            cur = prev->prev;
            continue;
        }
        prev = cur;
        cur = cur->prev;
    }
}

void gkc_insert_value(struct gkc_summary *s, double value)
{
    struct list *cur = NULL;
    struct gkc_tuple *new, *tcur, *tnext = NULL;

    new = gkc_alloc(s);
    memset(new, 0, sizeof(*new));
    new->value = value;
    new->g = 1;
    list_init(&new->node);


    s->nr_elems++;


    /* first insert */
    if (list_empty(&s->head)) {
        list_add(&s->head, &new->node);
        return;
    }

    cur = s->head.next;
    tcur = list_to_tuple(cur);
    /* v < v0, new min */
    if (tcur->value > new->value) {
        list_add(&s->head, &new->node);
        goto out;
    }

    double gi = 0;
    while (cur->next != &s->head) {
        tnext = list_to_tuple(cur->next);
        tcur = list_to_tuple(cur);

        gi += tcur->g;
        if (tcur->value <= new->value && new->value < tnext->value) {
            /*     INSERT "(v, 1, Δ)" into S between vi and vi+1; */
            new->delta = tcur->g + tcur->delta - 1;
            list_add(cur, &new->node);
            goto out;
        }
        cur = cur->next;
    }
    /* v > vs-1, new max */
    list_add_tail(&s->head, &new->node);
out:
    if (s->nr_elems % (int)(1/(2*s->epsilon))) {
        gkc_compress(s);
    }
}

void gkc_print_summary(struct gkc_summary *s)
{
    struct gkc_tuple *tcur;
    struct list *cur;

    fprintf(stderr, "nr_elems: %zu, epsilon: %.02f, alloced: %" PRIu64 ", overfilled: %.02f, max_alloced: %" PRIu64 "\n",
            s->nr_elems, s->epsilon, s->alloced, 2 * s->epsilon * s->nr_elems, s->max_alloced);
    if (list_empty(&s->head)) {
        fprintf(stderr, "Empty summary\n");
        return;
    }

    cur = s->head.next;
    while (cur != &s->head) {
        tcur = list_to_tuple(cur);
        fprintf(stderr, "(v: %" PRIu64 ", g: %.02f, d: %" PRIu64 ") ", tcur->value, tcur->g, tcur->delta);
        cur = cur->next;
    }
    fprintf(stderr, "\n");
}

struct gkc_summary *gkc_combine(struct gkc_summary *s1, struct gkc_summary *s2)
{
    struct gkc_summary *snew;
    struct list *cur1, *cur2;
    struct gkc_tuple *tcur1, *tcur2, *tnew;

    if (s1->epsilon != s2->epsilon) {
        return NULL;
    }
    snew = gkc_summary_alloc(s1->epsilon);

    cur1 = s1->head.next;
    cur2 = s2->head.next;
    while (cur1 != &s1->head && cur2 != &s2->head) {
        tcur1 = list_to_tuple(cur1);
        tcur2 = list_to_tuple(cur2);

        tnew = gkc_alloc(snew);
        if (tcur1->value < tcur2->value) {
            tnew->value = tcur1->value;
            tnew->g = tcur1->g;
            tnew->delta = tcur1->delta;
            cur1 = cur1->next;
        } else {
            tnew->value = tcur2->value;
            tnew->g = tcur2->g;
            tnew->delta = tcur2->delta;
            cur2 = cur2->next;
        }
        list_add_tail(&snew->head, &tnew->node);
        snew->nr_elems += tnew->g;
    }
    while (cur1 != &s1->head) {
        tcur1 = list_to_tuple(cur1);

        tnew = gkc_alloc(snew);
        tnew->value = tcur1->value;
        tnew->g = tcur1->g;
        tnew->delta = tcur1->delta;
        list_add_tail(&snew->head, &tnew->node);
        snew->nr_elems += tnew->g;
        cur1 = cur1->next;
    }
    while (cur2 != &s2->head) {
        tcur2 = list_to_tuple(cur2);

        tnew = gkc_alloc(snew);
        tnew->value = tcur2->value;
        tnew->g = tcur2->g;
        tnew->delta = tcur2->delta;
        list_add_tail(&snew->head, &tnew->node);
        snew->nr_elems += tnew->g;
        cur2 = cur2->next;
    }
    snew->max_alloced = snew->alloced;
    gkc_compress(snew);

    return snew;
}
