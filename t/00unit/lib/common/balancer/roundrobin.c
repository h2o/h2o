#include "../../../test.h"
#include "../../../../../lib/common/balancer/roundrobin.c"

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

static void test_when_backend_down(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    char tried[10] = {0};
    size_t i;
    size_t selected;
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_rr();

    for (i = 0; i < 10; i++) {
        selected = selector(balancer, &targets, tried);
        ok(selected >= 0 && selected < 10);
        ok(!tried[selected]);
        tried[selected] = 1;
    }

    destroy(balancer);

    free_targets(&targets);
}

static int check_weight_distribution(h2o_socketpool_target_vector_t *targets)
{
    size_t i, j;

    for (i = 0; i < targets->size; i++) {
        for (j = i + 1; j < targets->size; j++) {
            if (targets->entries[i]->_shared.leased_count * ((unsigned)targets->entries[j]->conf.weight_m1 + 1) !=
                targets->entries[j]->_shared.leased_count * ((unsigned)targets->entries[i]->conf.weight_m1 + 1))
                return 0;
        }
    }
    return 1;
}

static void test_round_robin(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    size_t last_selected = 0;
    size_t total_count = 0;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_rr();

    for (i = 0; i < targets.size; i++)
        total_count += ((unsigned)targets.entries[i]->conf.weight_m1) + 1;
    total_count *= 1000;

    for (i = 0; i < total_count; i++) {
        selected = selector(balancer, &targets, tried);
        if (selected > targets.size) {
            ok(selected >= 0 && selected < targets.size);
            goto Done;
        }
        check_result = selected >= last_selected || (last_selected == targets.size - 1 && selected == 0);
        if (!check_result) {
            ok(check_result);
            goto Done;
        }
        targets.entries[selected]->_shared.leased_count++;
        last_selected = selected;
    }
    ok(check_weight_distribution(&targets));

Done:
    destroy(balancer);
    free_targets(&targets);
}

static void test_round_robin_weighted(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    size_t last_selected = 0;
    size_t total_count = 0;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        targets.entries[i]->conf.weight_m1 = i % 3;
    balancer = h2o_balancer_create_rr();

    for (i = 0; i < targets.size; i++)
        total_count += ((unsigned)targets.entries[i]->conf.weight_m1) + 1;
    total_count *= 1000;

    for (i = 0; i < total_count; i++) {
        selected = selector(balancer, &targets, tried);
        if (selected > targets.size) {
            ok(selected >= 0 && selected < targets.size);
            goto Done;
        }
        check_result = selected >= last_selected || (last_selected == targets.size - 1 && selected == 0);
        if (!check_result) {
            ok(check_result);
            goto Done;
        }
        targets.entries[selected]->_shared.leased_count++;
        last_selected = selected;
    }
    ok(check_weight_distribution(&targets));

Done:
    destroy(balancer);
    free_targets(&targets);
}

void test_lib__common__balancer__roundrobin_c(void)
{
    subtest("when_backend_down", test_when_backend_down);
    subtest("round_robin", test_round_robin);
    subtest("round_robin_weighted", test_round_robin_weighted);
}
