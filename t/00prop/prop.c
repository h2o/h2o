#include <assert.h>
#include <inttypes.h>
#include "h2o/timer.h"
#include "h2o/socket.h"
#include "theft.h"

struct test_timer {
    h2o_timer_t t;
    int called;
};

static void timer_cb(h2o_timer_t *t_)
{
    struct test_timer *t = H2O_STRUCT_FROM_MEMBER(struct test_timer, t, t_);
    t->called++;
    return;
}


struct test_input {
    uint64_t init_time;
    uint64_t a;
    uint64_t b;
};

#define TIMER_MAX ((1UL << 36) - 1)
static enum theft_trial_res prop_wake_time_should_be_before_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    uint64_t now;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);

    struct test_timer t;
    h2o_timer_init(&t.t, timer_cb);
    t.called = 0;
    if (input->a > TIMER_MAX - input->b)
        now = TIMER_MAX;
    else
        now = input->b + input->a;
    assert(now >= input->a);
    h2o_timer_link_(&w, &t.t, input->a);
    events_run = h2o_timer_run_wheel(&w, now);

    if (events_run != 1)
        return THEFT_TRIAL_FAIL;
    if (t.called != 1)
        return THEFT_TRIAL_FAIL;
    if (!h2o_timer_wheel_is_empty(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_run_at_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    uint64_t now;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);

    struct test_timer t;
    h2o_timer_init(&t.t, timer_cb);
    t.called = 0;
    if (input->a > TIMER_MAX - input->b)
        now = TIMER_MAX;
    else
        now = input->b + input->a;
    assert(now >= input->a);
    h2o_timer_link_(&w, &t.t, input->a);
    events_run = h2o_timer_run_wheel(&w, now);

    if (events_run != 1)
        return THEFT_TRIAL_FAIL;
    if (t.called != 1)
        return THEFT_TRIAL_FAIL;
    if (!h2o_timer_wheel_is_empty(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_not_run_before_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    uint64_t expire;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);

    struct test_timer t;
    h2o_timer_init(&t.t, timer_cb);
    t.called = 0;
    if (input->a > TIMER_MAX - input->b)
        expire = TIMER_MAX;
    else
        expire = input->b + input->a;
    assert(expire > input->a);
    h2o_timer_link_(&w, &t.t, expire);
    events_run = h2o_timer_run_wheel(&w, input->a);

    if (events_run != 0)
        return THEFT_TRIAL_FAIL;
    if (t.called != 0)
        return THEFT_TRIAL_FAIL;
    if (h2o_timer_wheel_is_empty(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_trial_res prop_inserted_timer_should_not_run_before_reaching_expiry(struct theft *theft, void *input_)
{
    struct test_input *input = input_;
    uint64_t i;
    size_t events_run;
    h2o_timer_wheel_t w;
    h2o_timer_init_wheel(&w, 0);
    size_t slices = 1;

    struct test_timer t;
    h2o_timer_init(&t.t, timer_cb);
    t.called = 0;
    h2o_timer_link_(&w, &t.t, input->a);

    slices = input->a / 100;
    for (i = 0; i < input->a; i += theft_random_choice(theft, slices)) {
        events_run = h2o_timer_run_wheel(&w, i);
        if (events_run != 0)
            return THEFT_TRIAL_FAIL;
        if (t.called != 0)
            return THEFT_TRIAL_FAIL;
        if (h2o_timer_wheel_is_empty(&w))
            return THEFT_TRIAL_FAIL;
    }

    events_run = h2o_timer_run_wheel(&w, i);

    if (events_run != 1)
        return THEFT_TRIAL_FAIL;
    if (t.called != 1)
        return THEFT_TRIAL_FAIL;
    if (!h2o_timer_wheel_is_empty(&w))
        return THEFT_TRIAL_FAIL;
    return THEFT_TRIAL_PASS;
}

static enum theft_alloc_res alloc_cb(struct theft *t, void *penv, void **output)
{
    struct test_input *ret;
    ret = malloc(sizeof(*ret));
    ret->init_time = theft_random_bits(t, 64);
    ret->a = theft_random_choice(t, TIMER_MAX);
    ret->b = theft_random_choice(t, TIMER_MAX);
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
