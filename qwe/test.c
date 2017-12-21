#include "h2o/linklist.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "theft.h"

#define H2O_STRUCT_FROM_MEMBER(s, m, p) ((s *)((char *)(p)-offsetof(s, m)))

#define NR_WHEELS 4
#define BITS_PER_WHEEL 4
#define NR_SLOTS (1 << BITS_PER_WHEEL)

struct timer;
typedef void (*timer_cb)(struct timer *);

struct timer {
    h2o_linklist_t next;
    timer_cb cb;
    uint64_t expiry;
};

void timer_init(struct timer *t, timer_cb cb)
{
    *t = (struct timer){.cb = cb};
}

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

int tw_is_empty(struct tw *w)
{
    int i, j;
    for (i = 0; i < NR_WHEELS; i++) {
        for (j = 0; j < NR_SLOTS; j++) {
            if (!h2o_linklist_is_empty(&w->wheels[i][j]))
                return 0;
        }
    }
    return 1;
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
        if (expiry < wup || (i + 1 == NR_WHEELS)) {
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
    fprintf(stderr, "inserted %p at [%d:%d]\n", timer, wid, slot);
    h2o_linklist_insert(&w->wheels[wid][slot], &timer->next);
}

int tw_run(struct tw *w, uint64_t now)
{
    int i, j, cascade = 0;
    int events_run;
    h2o_linklist_t todo;
    h2o_linklist_init_anchor(&todo);

    fprintf(stderr, "%s:%d\n", __func__, __LINE__);
    for (i = 0; i < NR_WHEELS; i++) {
        int idx_icn = 0, slot;
        if (now < w->base[i]) {
            fprintf(stderr, "ran up to wheel [%d:0[\n", i);
            break;
        }
        for (j = 0; j < NR_SLOTS; j++) {
            slot = (j + w->idx[i]) % (1 << BITS_PER_WHEEL);
            fprintf(stderr, "slot: [%d:%d(%d)], now: %llu, base: %llu, end_base: %llu\n",
                    i, j, slot, now, w->base[i], w->base[i] + (j * (1 << (i * BITS_PER_WHEEL))));
            if (now < w->base[i] + (j * (1 << (i * BITS_PER_WHEEL)))) {
                fprintf(stderr, "ran up to slot [%d:%d(%d)[\n", i, j, slot);
                break;
            }
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
    events_run = 0;
    while (!h2o_linklist_is_empty(&todo)) {
        events_run++;
        struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, todo.next);
        h2o_linklist_unlink(todo.next);
        if (timer->expiry > now) {
            abort();
        }
        timer->cb(timer);
    }
    fprintf(stderr, "%s:%d\n", __func__, __LINE__);
    for (i = 0; i < NR_WHEELS; i++) {
        for (j = 0; j < NR_SLOTS; j++) {
                h2o_linklist_t *node;
                int slot = (j + w->idx[i]) % (1 << BITS_PER_WHEEL);
                for (node = w->wheels[i][slot].next; node != &w->wheels[i][slot]; node = node->next) {
                    struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
                    if (timer->expiry <= now) {
                        fprintf(stderr, "Should have run timer %p (now: %llu, expiry: %llu) [%d:%d(%d)]\n", timer, now, timer->expiry, i, j, slot);
                        abort();
                    }
                }
        }
    }
    return events_run;
}

struct debug_timer {
    struct timer t;
    int called;
};

#if 0
static int gnow;
static void debug_timer_fn(struct timer *t)
{
    struct debug_timer *dt = (struct debug_timer *)t;
    dt->called = 1;
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

struct test_timer {
    struct timer t;
    int called;
};

static void test_timer_cb(struct timer *t_)
{
    struct test_timer *t = H2O_STRUCT_FROM_MEMBER(struct test_timer, t, t_);
    fprintf(stderr, "timer %p ran, expiry: %d\n", t->t.expiry);
    t->called++;
    return;
}

struct test_input {
    uint64_t init_time;
    uint64_t first_time;
    uint64_t second_time;
};

#define TIMER_MAX ((1UL << (NR_WHEELS * BITS_PER_WHEEL)) - 1)

#define RET_FAIL                                                                                                                   \
    do {                                                                                                                           \
        abort();                                                                                                                   \
        return THEFT_TRIAL_FAIL;                                                                                                   \
    } while (0)
static enum theft_trial_res prop_inserted_timer_should_run_at_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    size_t events_run;
    struct tw w;
    tw_init(&w, input->init_time);
    tw_run(&w, input->init_time);

    struct test_timer t;
    timer_init(&t.t, test_timer_cb);
    t.called = 0;
    t.t.expiry = input->first_time;
    tw_insert(&w, &t.t);
    events_run = tw_run(&w, input->second_time);

    if (events_run != 1)
        RET_FAIL;
    if (t.called != 1)
        RET_FAIL;
    if (!tw_is_empty(&w))
        RET_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_not_run_before_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    size_t events_run;
    struct tw w;
    tw_init(&w, input->init_time);
    tw_run(&w, input->init_time);

    struct test_timer t;
    timer_init(&t.t, test_timer_cb);
    t.called = 0;
    t.t.expiry = input->second_time;
    tw_insert(&w, &t.t);
    events_run = tw_run(&w, input->first_time);

    if (events_run != 0)
        RET_FAIL;
    if (t.called != 0)
        RET_FAIL;
    if (tw_is_empty(&w))
        RET_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_not_run_before_reaching_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    uint64_t i;
    size_t events_run;
    struct tw w;
    tw_init(&w, input->init_time);
    tw_run(&w, input->init_time);
    size_t slices = 1;

    struct test_timer t;
    timer_init(&t.t, test_timer_cb);
    t.called = 0;
    t.t.expiry = input->first_time;
    tw_insert(&w, &t.t);

    slices = input->second_time / 100;
    for (i = input->init_time; i < input->first_time; i += theft_random_choice(theft, slices)) {
        events_run = tw_run(&w, i);
        if (events_run != 0)
            RET_FAIL;
        if (t.called != 0)
            RET_FAIL;
        if (tw_is_empty(&w))
            RET_FAIL;
    }

    events_run = tw_run(&w, i);

    if (events_run != 1)
        RET_FAIL;
    if (t.called != 1)
        RET_FAIL;
    if (!tw_is_empty(&w))
        RET_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_alloc_res alloc_cb(struct theft *t, void *penv, void **output)
{
    struct test_input *ret;
    ret = malloc(sizeof(*ret));
    ret->init_time = theft_random_choice(t, 28);
    ret->second_time = theft_random_choice(t, TIMER_MAX / 2 - 1) + 1;
    ret->first_time = theft_random_choice(t, ret->second_time);

    /* make times absolute */
    ret->first_time += ret->init_time;
    ret->second_time += ret->init_time;

    *output = ret;
    return THEFT_ALLOC_OK;
}

static void free_cb(void *instance, void *env)
{
    free(instance);
}

static void print_cb(FILE *f, const void *instance, void *env)
{
    const struct test_input *input = instance;
    fprintf(f, "init: %" PRIu64 ", first:%" PRIu64 ", second: %" PRIu64 "\n", input->init_time, input->first_time,
            input->second_time);
}

static struct theft_type_info random_buffer_info = {
    /* allocate a buffer based on random bitstream */
    .alloc = alloc_cb,
    .free = free_cb,
    .print = print_cb,
};

#define TEST(name_, fn_)                                                                                                           \
    bool name_(void)                                                                                                               \
    {                                                                                                                              \
        theft_seed seed = theft_seed_of_time();                                                                                    \
                                                                                                                                   \
        struct theft_run_config config = {                                                                                         \
            .name = __func__,                                                                                                      \
            .prop1 = fn_,                                                                                                          \
            .type_info = {&random_buffer_info},                                                                                    \
            .seed = seed,                                                                                                          \
            .trials = 100000,                                                                                                      \
        };                                                                                                                         \
                                                                                                                                   \
        enum theft_run_res res = theft_run(&config);                                                                               \
        return res == THEFT_RUN_PASS;                                                                                              \
    }
TEST(timers_should_run, prop_inserted_timer_should_run_at_expiry);
TEST(timers_should_not_run, prop_inserted_timer_should_not_run_before_expiry);
TEST(timers_should_not_run_before_expiry, prop_inserted_timer_should_not_run_before_reaching_expiry);
int main(void)
{
    timers_should_run();
    timers_should_not_run();
    timers_should_not_run_before_expiry();
    return 0;
}
