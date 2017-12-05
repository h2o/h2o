#include <assert.h>
#include <inttypes.h>
#include "h2o.h"
#include "h2o/timer.h"
#include "theft.h"

struct test_timer {
    h2o_timeout_t t;
    int called;
};
static void timer_cb(h2o_timeout_t *t_)
{
    struct test_timer *t = H2O_STRUCT_FROM_MEMBER(struct test_timer, t, t_);
    t->called++;
    return;
}

#define TIMER_MAX ((1UL << 36) - 1)
static enum theft_trial_res prop_inserted_timer_should_run_at_expiry(struct theft *theft, void *input_)
{
    uint64_t *input = input_;
    uint64_t now;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);

    struct test_timer t;
    t.t = h2o_timeout_init(timer_cb);
    t.called = 0;
    if (input[0] > TIMER_MAX - input[1])
        now = TIMER_MAX;
    else
        now = input[1] + input[0];
    assert(now >= input[0]);
    h2o_timer_link_(&w, &t.t, input[0]);
    events_run = h2o_timer_run_wheel(&w, now);

    if (events_run != 1)
        return THEFT_TRIAL_FAIL;
    if (t.called != 1)
        return THEFT_TRIAL_FAIL;
    if (!h2o_timer_is_empty_wheel(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_not_run_before_expiry(struct theft *theft, void *input_)
{
    uint64_t *input = input_;
    uint64_t expire;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);

    struct test_timer t;
    t.t = h2o_timeout_init(timer_cb);
    t.called = 0;
    if (input[0] > TIMER_MAX - input[1])
        expire = TIMER_MAX;
    else
        expire = input[1] + input[0];
    assert(expire > input[0]);
    h2o_timer_link_(&w, &t.t, expire);
    events_run = h2o_timer_run_wheel(&w, input[0]);

    if (events_run != 0)
        return THEFT_TRIAL_FAIL;
    if (t.called != 0)
        return THEFT_TRIAL_FAIL;
    if (h2o_timer_is_empty_wheel(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_not_run_before_reaching_expiry(struct theft *theft, void *input_)
{
    uint64_t *input = input_;
    uint64_t i;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);
    size_t slices = 1;

    struct test_timer t;
    t.t = h2o_timeout_init(timer_cb);
    t.called = 0;
    h2o_timer_link_(&w, &t.t, input[0]);

    slices = input[0] / 100;
    for (i = 0; i < input[0]; i += theft_random_choice(theft, slices)) {
        events_run = h2o_timer_run_wheel(&w, i);
        if (events_run != 0)
            return THEFT_TRIAL_FAIL;
        if (t.called != 0)
            return THEFT_TRIAL_FAIL;
        if (h2o_timer_is_empty_wheel(&w))
            return THEFT_TRIAL_FAIL;
    }

    events_run = h2o_timer_run_wheel(&w, i);

    if (events_run != 1)
        return THEFT_TRIAL_FAIL;
    if (t.called != 1)
        return THEFT_TRIAL_FAIL;
    if (!h2o_timer_is_empty_wheel(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_alloc_res alloc_cb(struct theft *t, void *penv, void **output)
{
    uint64_t *ret;
    ret = malloc(sizeof(uint64_t) * 2);
    ret[0] = theft_random_choice(t, TIMER_MAX);
    ret[1] = theft_random_choice(t, TIMER_MAX);
    *output = ret;
    return THEFT_ALLOC_OK;
}

static void free_cb(void *instance, void *env)
{
    free(instance);
}

static void print_cb(FILE *f, const void *instance, void *env)
{
    const uint64_t *input = instance;
    fprintf(f, "expire: %" PRIu64 ", now:%" PRIu64 "\n", input[0], input[1]);
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
