#include "h2o/linklist.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s *)((char *)(p)-offsetof(s, m)))

#define NR_WHEELS 6
#define BITS_PER_WHEEL 6
#define NR_SLOTS (1 << BITS_PER_WHEEL)

struct timer;
typedef void (*timer_cb)(struct timer *);

struct timer {
    h2o_linklist_t next;
    timer_cb cb;
    uint64_t expiry;
};

struct tw {
    h2o_linklist_t wheels[NR_WHEELS][NR_SLOTS];
    uint64_t base[NR_WHEELS];
    uint8_t idx[NR_WHEELS];
};

void tw_init(struct tw *w, uint64_t now)
{
    int i, j;
    for (i = 0; i < NR_WHEELS; i++) {
        for (j = 0; j < NR_SLOTS; j++) {
            h2o_linklist_init_anchor(&w->wheels[i][j]);
        }
        w->base[i] = now + (1 << (i * BITS_PER_WHEEL)) - !i;
        w->idx[i] = 0;
    }
}

static uint64_t wheel_upper_bound(struct tw *w, int wid)
{
    return w->base[wid] + (1 << ((wid + 1) * BITS_PER_WHEEL));
}

static void tw_find_slot(struct tw *w, uint64_t expiry, int *wid, int *slot)
{
    int i;
    for (i = 0; i < NR_WHEELS; i++) {
        uint64_t wup = wheel_upper_bound(w, i);
        if (expiry < wup) {
            uint64_t delta;
            *wid = i;
            *slot = (expiry - w->base[i]) / (1 << i * BITS_PER_WHEEL);
            return;
        }
    }
    assert(0 && "expiry doesn't fit in timerwheel");
}

void tw_insert(struct tw *w, struct timer *timer)
{
    int wid, slot;
    uint64_t delta;
    if (timer->expiry < w->base[0])
        timer->expiry = w->base[0];
    tw_find_slot(w, timer->expiry, &wid, &slot);
    assert(wid < NR_WHEELS);
    assert(slot < NR_SLOTS);
    h2o_linklist_insert(&w->wheels[wid][slot], &timer->next);
}

void tw_run(struct tw *w, uint64_t now)
{
    int i, j, cascade = 0;
    h2o_linklist_t todo;
    h2o_linklist_init_anchor(&todo);

    for (i = 0; i < NR_WHEELS; i++) {
        int idx_icn = 0, slot;
        if (now < w->base[i]) {
            break;
        }
        for (j = 0; j < NR_SLOTS; j++) {
            slot = (j + w->idx[i]) % (1 << BITS_PER_WHEEL);
            if (now < w->base[i] + (j * (1 << (i * BITS_PER_WHEEL))))
                break;
            if (now > (w->base[i] + ((j + 1) * (1 << (i * BITS_PER_WHEEL))) - 1)) {
                idx_icn++;
                h2o_linklist_t *node;
                for (node = w->wheels[i][slot].next; node != &w->wheels[i][slot]; node = node->next) {
                    struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
                    assert(timer->expiry <= now);
                }
                h2o_linklist_insert_list(&todo, &w->wheels[i][slot]);
            } else {
                h2o_linklist_t *node, *next;
                for (node = w->wheels[i][slot].next; node != &w->wheels[i][slot]; node = next) {
                    struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
                    next = node->next;
                    if (timer->expiry <= now) {
                        h2o_linklist_unlink(&timer->next);
                        h2o_linklist_insert(&todo, &timer->next);
                    } else {
                        cascade = 1;
                    }
                }
            }
        }
        w->base[i] = now;
        w->idx[i] = (w->idx[i] + idx_icn) % NR_SLOTS;
        if (cascade) {
            h2o_linklist_t *node, *next;
            for (node = w->wheels[i][slot].next; node != &w->wheels[i][slot]; node = next) {
                struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
                next = node->next;
                h2o_linklist_unlink(&timer->next);
                tw_insert(w, timer);
            }
        }
    }
    while (!h2o_linklist_is_empty(&todo)) {
        struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, todo.next);
        h2o_linklist_unlink(todo.next);
        if (timer->expiry > now) {
            abort();
        }
        timer->cb(timer);
    }
    return;
}

struct debug_timer {
    struct timer t;
};

#if 1
static int gnow;
static void debug_timer_fn(struct timer *t)
{
    struct debug_timer *dt = (struct debug_timer *)t;
    fprintf(stderr, "expiry: %llu, now: %llu\n", dt->t.expiry, gnow);
}

#define NR_DEBUG_TIMERS 127
int main(void)
{
    struct tw w;
    int i;
    int now = 0;
    struct debug_timer timers[NR_DEBUG_TIMERS];
    tw_init(&w, now);
    for (i = 0; i < NR_DEBUG_TIMERS; i++) {
        timers[i] = (struct debug_timer){{{}, debug_timer_fn, i < now ? now : i}};
        tw_insert(&w, &timers[i].t);
    }
    for (i = 32; i < NR_DEBUG_TIMERS + 64; i+=1) {
        gnow = i;
        fprintf(stderr, "tick: %d\n", i);
        tw_run(&w, i);
    }
    return 0;
}

#endif
