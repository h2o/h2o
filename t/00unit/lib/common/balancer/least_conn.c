#include "../../../test.h"
#include "../../../../../lib/common/balancer/least_conn.c"

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

    balancer = h2o_balancer_create_lc();

    for (i = 0; i < 10; i++) {
        selected = selector(balancer, &targets, tried, NULL);
        ok(selected >= 0 && selected < 10);
        ok(!tried[selected]);
        tried[selected] = 1;
    }

    free_targets(&targets);
    destroy(balancer);
}

static int check_if_acceptable(h2o_socketpool_target_vector_t *targets, size_t selected)
{
    double conn_weight_quotient;
    size_t i;
    double selected_conn_weight_quotient = targets->entries[selected]->_shared.leased_count;
    selected_conn_weight_quotient /= ((int)targets->entries[selected]->conf.weight_m1) + 1;

    for (i = 0; i < targets->size; i++) {
        if (i == selected)
            continue;
        conn_weight_quotient = targets->entries[i]->_shared.leased_count;
        conn_weight_quotient /= ((unsigned)targets->entries[i]->conf.weight_m1) + 1;
        if (conn_weight_quotient < selected_conn_weight_quotient) {
            return -1;
        }
    }

    return 0;
}

static void test_least_conn(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_lc();

    for (i = 0; i < 10000; i++) {
        selected = selector(balancer, &targets, tried, NULL);
        if (selected > 10) {
            ok(selected >= 0 && selected < targets.size);
            goto Done;
        }
        check_result = check_if_acceptable(&targets, selected);
        if (check_result == -1) {
            ok(!check_result);
            goto Done;
        }
        targets.entries[selected]->_shared.leased_count++;
    }
    ok(!check_result);

Done:
    free_targets(&targets);
    destroy(balancer);
}

static void test_least_conn_weighted(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_lc();

    for (i = 0; i < 10; i++)
        targets.entries[i]->conf.weight_m1 = i % 3;

    for (i = 0; i < 10000; i++) {
        selected = selector(balancer, &targets, tried, NULL);
        if (selected > 10) {
            ok(selected >= 0 && selected < targets.size);
            goto Done;
        }
        check_result = check_if_acceptable(&targets, selected);
        if (check_result == -1) {
            ok(!check_result);
            goto Done;
        }
        targets.entries[selected]->_shared.leased_count++;
    }
    ok(!check_result);

Done:
    free_targets(&targets);
    destroy(balancer);
}

void test_lib__common__balancer__least_conn_c(void)
{
    subtest("when_backend_down", test_when_backend_down);
    subtest("least_conn", test_least_conn);
    subtest("least_conn_weighted", test_least_conn_weighted);
}
