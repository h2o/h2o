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
#define WHEEL_MASK ((1 << BITS_PER_WHEEL) - 1)

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
    uint64_t last_run;
};

void tw_init(struct tw *w, uint64_t now)
{
    int i, j;
    for (i = 0; i < NR_WHEELS; i++) {
        for (j = 0; j < NR_SLOTS; j++) {
            h2o_linklist_init_anchor(&w->wheels[i][j]);
        }
        w->last_run = now;
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

void get_wid_and_slot(struct tw *w, uint64_t time, int *wid, int *slot)
{
    uint64_t delta;
    delta = time - (w->last_run & ~WHEEL_MASK);
    *wid = 0;
    while (1) {
        *slot = delta & WHEEL_MASK;
        delta = delta >> BITS_PER_WHEEL;
        if (delta == 0)
            break;
        *wid += 1;
    }
    assert(*wid < NR_WHEELS);
    assert(*slot < NR_SLOTS);
}
void tw_insert(struct tw *w, struct timer *timer)
{
    int wid, slot;

    if (timer->expiry < w->last_run)
        timer->expiry = w->last_run;
    get_wid_and_slot(w, timer->expiry, &wid, &slot);
    fprintf(stderr, "%s:%d insert: %p(%"PRIu64") at [%d:%d], wt:%"PRIu64"\n", __func__, __LINE__, timer, timer->expiry, wid, slot, w->last_run);
    h2o_linklist_insert(&w->wheels[wid][slot], &timer->next);
}

void tw_check(struct tw *w, uint64_t now)
{
    int i, j;
    for (i = 0; i < NR_WHEELS; i++) {
        for (j = 0; j < NR_SLOTS; j++) {
                h2o_linklist_t *node;
                for (node = w->wheels[i][j].next; node != &w->wheels[i][j]; node = node->next) {
                    struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
                    if (timer->expiry <= now) {
                        fprintf(stderr, "Should have run timer %p (now: %"PRIu64", expiry: %"PRIu64") [%d:%d]\n", timer, now, timer->expiry, i, j);
                        abort();
                    }
                }
        }
    }
}
void cascade(struct tw *w, int wid, int slot)
{
    h2o_linklist_t *node, *next;
    for (node = w->wheels[wid][slot].next; node != &w->wheels[wid][slot]; node = next) {
        struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
        next = node->next;
        h2o_linklist_unlink(&timer->next);
        tw_insert(w, timer);
    }
}

int tw_run(struct tw *w, uint64_t now)
{
    int events_run, slot, wid, j, end_slot, end_wid;
    h2o_linklist_t todo;
    int should_cascade_next = 0;

    h2o_linklist_init_anchor(&todo);
    assert(now >= w->last_run);

    fprintf(stderr, "%s:%d now:%"PRIu64", lr: %"PRIu64"\n", __func__, __LINE__, now, w->last_run);
    get_wid_and_slot(w, now, &end_wid, &end_slot);
    fprintf(stderr, "now is [%d:%d]\n", end_wid, end_slot);

    for (wid = 0; wid <= end_wid; wid++) {
        int cur_end_slot = ((wid == end_wid) ? end_slot : NR_SLOTS);
        for (j = 0; j <= cur_end_slot; j++) {
            h2o_linklist_t *node, *next;
            slot = ((w->last_run >> (wid * BITS_PER_WHEEL)) + j) & WHEEL_MASK;
            if (wid == end_wid && j > 0 && slot == 0) {
                should_cascade_next = 1;
            }
            //fprintf(stderr, "%s:%d [%d:%d(%d)]\n", __func__, __LINE__, wid, j, slot);
            for (node = w->wheels[wid][slot].next; node != &w->wheels[wid][slot]; node = next) {
                struct timer *timer = H2O_STRUCT_FROM_MEMBER(struct timer, next, node);
                next = node->next;
                if (timer->expiry < now) {
                    h2o_linklist_unlink(&timer->next);
                    h2o_linklist_insert(&todo, &timer->next);
                }
            }
        }
    }
    if (wid > 0) {
        slot = ((w->last_run >> (wid * BITS_PER_WHEEL)) + j) & WHEEL_MASK;
        w->last_run = now;
        cascade(w, wid - 1, slot);
    }
    if (should_cascade_next && wid != NR_WHEELS) {
        slot = ((w->last_run >> (wid * BITS_PER_WHEEL)) + j) & WHEEL_MASK;
        w->last_run = now;
        if (slot == 0) {
            wid++;
        }
        cascade(w, wid, slot);
    }
    w->last_run = now;

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

    tw_check(w, now);
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
    fprintf(stderr, "timer %p ran, expiry: %"PRIu64"\n", t, t->t.expiry);
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
