/*
 * Copyright (c) 2017 Fastly, Inc.
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
#include <inttypes.h>
#include <sys/mman.h>
#include "../../test.h"
#include "../../../../include/h2o/timer.h"

static int invokes = 0;
static void my_callback(h2o_timer_t *timer)
{
    invokes++;
}

static int rseed = 13;

static inline int lcg_rand()
{
    return rseed = (rseed * 1103515245 + 12345) & RAND_MAX;
}

#define N 14000
void test_add_fixed_timers()
{
    uint32_t abs_wtime = 3;
    h2o_timer_wheel_t *testwheel = h2o_timer_create_wheel(6, abs_wtime);
    int i;

    h2o_timer_t timers[N];
    /* add timers */
    for (i = 0; i < N; i++) {
        uint32_t expiry = abs_wtime + i + 5;
        h2o_timer_init(&timers[i], my_callback);
        h2o_timer_link(testwheel, &timers[i], expiry);
    }

    /* run the wheel */
    ok(h2o_timer_run_wheel(testwheel, 139) == 132);
    h2o_timer_show_wheel(testwheel);

    h2o_timer_destroy_wheel(testwheel);
}

void test_del_timers()
{
    uint32_t abs_wtime = 3;
    h2o_timer_wheel_t *testwheel = h2o_timer_create_wheel(6, abs_wtime);
    h2o_timer_t timers[N];
    int i;

    /* add N timers */
    for (i = 0; i < N; i++) {
        uint32_t expiry = abs_wtime + i + 5;
        h2o_timer_init(&timers[i], my_callback);
        h2o_timer_link(testwheel, &timers[i], expiry);
    }

    /* delete N-1 timers, so there should be 1 timer left */
    for (i = 0; i < N - 1; i++) {
        h2o_timer_unlink(&timers[i]);
    }

    /* run the wheel */
    ok(h2o_timer_run_wheel(testwheel, N + 6) == 0);
    h2o_timer_show_wheel(testwheel);
    ok(h2o_timer_run_wheel(testwheel, N + 7) == 1);
    h2o_timer_show_wheel(testwheel);

    h2o_timer_destroy_wheel(testwheel);
}

void test_add_rand_timers()
{
    uint32_t abs_wtime = 3;
    h2o_timer_wheel_t *testwheel = h2o_timer_create_wheel(6, abs_wtime);
    h2o_timer_t timers[N];
    int i;

    /* add timers */
    for (i = 0; i < N; i++) {
        uint32_t expiry = abs_wtime + lcg_rand() % N;
        h2o_timer_init(&timers[i], my_callback);
        h2o_timer_link(testwheel, &timers[i], expiry);
    }

    int start = invokes;
    /* run the wheel: the timers has a max expiry N-1 + abs_wtime  */
    ok(h2o_timer_run_wheel(testwheel, N - 1 + abs_wtime) == N);
    ok(invokes - start == N);
    h2o_timer_show_wheel(testwheel);

    h2o_timer_destroy_wheel(testwheel);
}

void test_invalid_timer()
{
    h2o_timer_wheel_t *testwheel = h2o_timer_create_wheel(6, 3);

    h2o_timer_t timer = (h2o_timer_t){{NULL}};
    timer.cb = my_callback;

#define NTIMERS 54
    h2o_timer_t *arr = calloc(NTIMERS, sizeof(h2o_timer_t));
    uint32_t expiry = 11;
    int i;
    for (i = 0; i < NTIMERS; i++) {
        arr[i].cb = my_callback;
        h2o_timer_link(testwheel, &arr[i], expiry);
        h2o_timer_show_wheel(testwheel);
        expiry++;
    }

    h2o_timer_show_wheel(testwheel);
    expiry = 11;
    for (i = 0; i < NTIMERS; i++) {
        h2o_timer_show_wheel(testwheel);
        size_t ret = h2o_timer_run_wheel(testwheel, expiry);
        if (ret != 1) {
            h2o_timer_show_wheel(testwheel);
            abort();
        }
        expiry++;
    }

    h2o_timer_destroy_wheel(testwheel);
}

static struct {
    uint64_t now;
    size_t num_linked;
    h2o_linklist_t unused;
} test_exhaustive_data;

static void test_exhaustive_on_expire(h2o_timer_t *timer)
{
    if (test_exhaustive_data.now != timer->expire_at) {
        note("unexpected expire time; expected: %" PRIu64 ", actual: %" PRIu64, timer->expire_at, test_exhaustive_data.now);
        ok(0);
    }
    if (test_exhaustive_data.num_linked == 0) {
        note("now: %" PRIu64, test_exhaustive_data.now);
        ok(!"unexpected num_linked");
    }
    --test_exhaustive_data.num_linked;
    h2o_linklist_insert(&test_exhaustive_data.unused, &timer->_link);
}

static void test_exhaustive(void)
{
    h2o_timer_wheel_t *wheel = h2o_timer_create_wheel(2, 0);
    uint64_t max_interval = H2O_TIMERWHEEL_SLOTS_PER_WHEEL * (H2O_TIMERWHEEL_SLOTS_PER_WHEEL - 1) + 1;
    h2o_timer_t *timer_buf;
    size_t timer_buf_size = max_interval * (max_interval + 1) / 2;

    test_exhaustive_data.now = 0;
    test_exhaustive_data.num_linked = 0;
    h2o_linklist_init_anchor(&test_exhaustive_data.unused);

    { /* use our own allocator so that a debug version of malloc (with guard pages) can be used for running other tests */
        size_t i;
        timer_buf = mmap(NULL, sizeof(*timer_buf) * timer_buf_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        for (i = 0; i != timer_buf_size; ++i) {
            timer_buf[i].cb = test_exhaustive_on_expire;
            h2o_linklist_insert(&test_exhaustive_data.unused, &timer_buf[i]._link);
        }
    }

    for (; test_exhaustive_data.now < max_interval * 2; ++test_exhaustive_data.now) {
        uint64_t i;
        for (i = 0; i < max_interval; ++i) {
            assert(!h2o_linklist_is_empty(&test_exhaustive_data.unused));
            h2o_timer_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timer_t, _link, test_exhaustive_data.unused.next);
            h2o_linklist_unlink(&timer->_link);
            h2o_timer_link(wheel, timer, test_exhaustive_data.now + i);
            ++test_exhaustive_data.num_linked;
        }
        h2o_timer_run_wheel(wheel, test_exhaustive_data.now);
        size_t num_linked_expected;
        if (test_exhaustive_data.now < max_interval) {
            num_linked_expected =
                (test_exhaustive_data.now + 1) * max_interval - (test_exhaustive_data.now + 1) * (test_exhaustive_data.now + 2) / 2;
        } else {
            num_linked_expected = max_interval * (max_interval - 1) / 2;
        }
        if (test_exhaustive_data.num_linked != num_linked_expected) {
            note("unexpcted number of objects; expected: %zu, actual %zu, now: %" PRIu64, num_linked_expected,
                 test_exhaustive_data.num_linked, test_exhaustive_data.now);
            ok(0);
        }
    }
    for (; test_exhaustive_data.now < max_interval * 3; ++test_exhaustive_data.now)
        h2o_timer_run_wheel(wheel, test_exhaustive_data.now);
    ok(test_exhaustive_data.num_linked == 0);

    munmap(timer_buf, sizeof(*timer_buf) * timer_buf_size);
    h2o_timer_destroy_wheel(wheel);
}

static void test_get_wake_at(void)
{
#define OK(cond)                                                                                                                   \
    do {                                                                                                                           \
        if ((cond))                                                                                                                \
            break;                                                                                                                 \
        note("delta=%" PRIu64 ",base=%" PRIu64, delta, base);                                                                      \
        ok(0);                                                                                                                     \
        return;                                                                                                                    \
    } while (0)

    h2o_timer_t timer;
    uint64_t delta, base;

    h2o_timer_init(&timer, my_callback);

    for (delta = 0; delta < H2O_TIMERWHEEL_SLOTS_PER_WHEEL * H2O_TIMERWHEEL_SLOTS_PER_WHEEL * 3;
         delta = delta < 200 ? delta + 1 : delta * 1.1) {
        for (base = 0; base <= H2O_TIMERWHEEL_SLOTS_PER_WHEEL; ++base) {
            uint64_t now = base;
            h2o_timer_wheel_t *wheel = h2o_timer_create_wheel(3, now);
            invokes = 0;
            h2o_timer_link(wheel, &timer, now + delta);
            if (delta == 0) {
                OK(h2o_timer_get_wake_at(wheel) == now);
                h2o_timer_run_wheel(wheel, now);
                OK(invokes == 1);
            } else {
                int cnt = 0;
                do {
                    uint64_t wake_at = h2o_timer_get_wake_at(wheel);
                    OK(wake_at > now);
                    now = wake_at;
                    h2o_timer_run_wheel(wheel, now);
                    ++cnt;
                } while (invokes != 1);
                OK(cnt <= 3);
            }
            OK(h2o_timer_get_wake_at(wheel) == UINT64_MAX);
            h2o_timer_destroy_wheel(wheel);
        }
    }

#undef OK

    ok(1);
}

void test_lib__common__timerwheel_c()
{
    subtest("add fixed timers", test_add_fixed_timers);
    subtest("add random timers", test_add_rand_timers);
    subtest("del fixed timers", test_del_timers);
    subtest("test out-of-range timer", test_invalid_timer);
    subtest("exhaustive", test_exhaustive);
    subtest("get_wake_at", test_get_wake_at);
}
