#include <math.h>

#include "../../../test.h"
#include "../../../../../lib/common/balancer/best_of_two.c"

static h2o_socketpool_target_vector_t gen_targets(size_t size)
{
    size_t i;
    h2o_socketpool_target_vector_t targets = {NULL};

    h2o_vector_reserve(NULL, &targets, size);
    for (i = 0; i < size; i++) {
        h2o_socketpool_target_t *target = h2o_mem_alloc(sizeof(*target));
        target->_shared.leased_count = 0;
        target->conf.weight_m1 = 0;
        targets.entries[i] = target;
    }
    targets.size = size;

    return targets;
}

static void free_targets(h2o_socketpool_target_vector_t *targets)
{
    size_t i;

    for (i = 0; i < targets->size; i++) {
        free(targets->entries[i]);
    }
    free(targets->entries);
}

static void check_distrib(size_t *distrib, size_t len)
{
  for (size_t i = 1; i < len; i++) {
    double cur = (double)distrib[i] / (double)distrib[0];
    double prev = (double)distrib[i-1] / (double)distrib[0];
    ok(nearbyint(cur) == nearbyint(prev)+1.00);
  }
}

static void test_best_of_two(void)
{
    size_t distrib[10] = { 0 };
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    char tried[10] = { '\0' };
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_bo2();
    for (i = 0; i < 10; i++) {
      targets.entries[i]->conf.weight_m1 = i;
    }
    for (i = 0; i < 100000; i++) {
        selected = selector(balancer, &targets, tried);
        distrib[selected]++;
        if (i > 0 && i % 10000 == 0) {
          check_distrib(distrib, 10);
        }
        targets.entries[selected]->_shared.leased_count++;
    }
    free_targets(&targets);
    destroy(balancer);
}

static void test_when_backend_down(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    char tried[10] = {0};
    size_t i;
    size_t selected;
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_bo2();
    for (i = 0; i < 10; i++) {
        selected = selector(balancer, &targets, tried);
        ok(selected >= 0 && selected < 10);
        ok(!tried[selected]);
        tried[selected] = 1;
    }
    free_targets(&targets);
    destroy(balancer);
}

void test_lib__common__balancer__best_of_two_c(void)
{
    subtest("when_backend_down", test_when_backend_down);
    subtest("best_of_two", test_best_of_two);
}
