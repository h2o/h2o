#include "../../../test.h"
#include "../../../../../lib/common/balancer/least_conn.c"

static h2o_balancer_backend_t *gen_backends(size_t size)
{
    size_t i;
    h2o_balancer_backend_t *backends = h2o_mem_alloc(size * sizeof(*backends));

    for (i = 0; i < size; i++) {
        backends[i].conn_count = 0;
        backends[i].weight_m1 = 0;
    }

    return backends;
}

static void free_backends(h2o_balancer_backend_t *backends)
{
    free(backends);
}

static void test_when_backend_down(void)
{
    h2o_balancer_backend_t *real_backends = gen_backends(10);
    h2o_balancer_backend_t **backends = alloca(10 * sizeof(*backends));
    char tried[10] = {0};
    size_t i;
    size_t selected;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        backends[i] = &real_backends[i];
    balancer = h2o_balancer_create_lc();

    for (i = 0; i < 10; i++) {
        selected = selector(balancer, backends, 10, tried);
        ok(selected >= 0 && selected < 10);
        ok(!tried[selected]);
        tried[selected] = 1;
    }

    free_backends(real_backends);
    destroy(balancer);
}

static int check_if_acceptable(h2o_balancer_backend_t *backends, size_t backends_len, size_t selected)
{
    double conn_weight_quotient;
    size_t i;
    double selected_conn_weight_quotient = backends[selected].conn_count;
    selected_conn_weight_quotient /= ((int)backends[selected].weight_m1) + 1;

    for (i = 0; i < backends_len; i++) {
        if (i == selected)
            continue;
        conn_weight_quotient = backends[i].conn_count;
        conn_weight_quotient /= ((unsigned)backends[i].weight_m1) + 1;
        if (conn_weight_quotient < selected_conn_weight_quotient) {
            return -1;
        }
    }

    return 0;
}

static void test_least_conn(void)
{
    h2o_balancer_backend_t *real_backends = gen_backends(10);
    h2o_balancer_backend_t **backends = alloca(10 * sizeof(*backends));
    size_t i, selected;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        backends[i] = &real_backends[i];
    balancer = h2o_balancer_create_lc();

    for (i = 0; i < 10000; i++) {
        selected = selector(balancer, backends, 10, tried);
        if (selected > 10) {
            ok(selected >= 0 && selected < 10);
            goto Done;
        }
        check_result = check_if_acceptable(real_backends, 10, selected);
        if (check_result == -1) {
            ok(!check_result);
            goto Done;
        }
        real_backends[selected].conn_count++;
    }
    ok(!check_result);

Done:
    free_backends(real_backends);
    destroy(balancer);
}

static void test_least_conn_weighted(void)
{
    h2o_balancer_backend_t *real_backends = gen_backends(10);
    h2o_balancer_backend_t **backends = alloca(10 * sizeof(*backends));
    size_t i, selected;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        backends[i] = &real_backends[i];
    balancer = h2o_balancer_create_lc();

    for (i = 0; i < 10; i++)
        real_backends[i].weight_m1 = i % 3;

    for (i = 0; i < 10000; i++) {
        selected = selector(balancer, backends, 10, tried);
        if (selected > 10) {
            ok(selected >= 0 && selected < 10);
            goto Done;
        }
        check_result = check_if_acceptable(real_backends, 10, selected);
        if (check_result == -1) {
            ok(!check_result);
            goto Done;
        }
        real_backends[selected].conn_count++;
    }
    ok(!check_result);

Done:
    free_backends(real_backends);
    destroy(balancer);
}

void test_lib__common__balancer__least_conn_c(void)
{
    subtest("when_backend_down", test_when_backend_down);
    subtest("least_conn", test_least_conn);
    subtest("least_conn_weighted", test_least_conn_weighted);
}
