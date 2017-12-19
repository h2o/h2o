#include "h2o/linklist.h"
#include <stdint.h>
#include <stdlib.h>

#define NR_WHEELS 6
#define BITS_PER_WHEEL 6
#define NR_SLOTS (1 << BITS_PER_WHEEL)

struct timer;
typedef void (*timer_cb)(struct timer *);

struct timer {
    h2o_linklist_t next;
    timer_cb cb;
};

struct tw {
    h2o_linklist_t wheels[NR_WHEELS][NR_SLOTS];
    uint64_t nows[NR_WHEELS];
};

void tw_init(struct tw *w, uint64_t now)
{
    int i, j;
    for (i = 0; i < NR_WHEELS; i++) {
        for (j = 0; j < NR_SLOTS; j++) {
            h2o_linklist_init_anchor(&w->wheels[i][j]);
        }
        w->nows[i] = now >> (i * BITS_PER_WHEEL);
    }
}

static int tw_wid(uint64_t delta)
{
    int wid = 0;
    while (delta > 0) {
        delta >>= BITS_PER_WHEEL;
        wid++;
    }
    return wid;
}

static int tw_slot(int wid, uint64_t delta)
{
    int slot = delta - (1 << (wid * BITS_PER_WHEEL));
}

void tw_insert(struct tw *w, timer_cb cb, uint64_t expire)
{
    int wid, slot;
    uint64_t delta;
    if (expire < w->now[0])
        expire = w->now[0];
    delta = expire - w->now[0];
    wid = tw_wid(delta);
    slot = tw_slot(wid, delta);
    assert(wid < NR_WHEELS);
    assert(slot < NR_SLOTS);
    struct timer *timer = calloc(1, sizeof(*timer));
    timer->cb = cb;
    h2o_linklist_insert(&w->wheels[wid][slot], &timer->next);
}

void tw_run(struct tw *w, uint64_t now)
{
}
