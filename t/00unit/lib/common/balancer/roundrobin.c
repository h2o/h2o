#include "../../../test.h"
#include "../../../../../lib/common/balancer/roundrobin.c"

struct round_robin_test_backend_t {
    h2o_balancer_backend_t super;
    size_t leased_count;
};

static struct round_robin_test_backend_t *gen_backends(size_t size)
{
    size_t i;
    struct round_robin_test_backend_t *backends = h2o_mem_alloc(size * sizeof(*backends));

    for (i = 0; i < size; i++) {
        backends[i].super.weight_m1 = 0;
        backends[i].leased_count = 0;
    }

    return backends;
}

static void free_backends(struct round_robin_test_backend_t *backends)
{
    free(backends);
}

static void test_when_backend_down(void)
{
    struct round_robin_test_backend_t *real_backends = gen_backends(10);
    h2o_balancer_backend_t **backends = alloca(10 * sizeof(*backends));
    char tried[10] = {0};
    size_t i;
    size_t selected;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        backends[i] = &real_backends[i].super;
    balancer = h2o_balancer_create_rr();

    for (i = 0; i < 10; i++) {
        selected = selector(balancer, backends, 10, tried);
        ok(selected >= 0 && selected < 10);
        ok(!tried[selected]);
        tried[selected] = 1;
    }

    destroy(balancer);

    free_backends(real_backends);
}

static int check_weight_distribution(struct round_robin_test_backend_t *backends, size_t backends_len)
{
    size_t i, j;

    for (i = 0; i < backends_len; i++) {
        for (j = i + 1; j < backends_len; j++) {
            if (backends[i].leased_count * ((unsigned)backends[j].super.weight_m1 + 1) !=
                backends[j].leased_count * ((unsigned)backends[i].super.weight_m1 + 1))
                return 0;
        }
    }
    return 1;
}

static void test_round_robin(void)
{
    struct round_robin_test_backend_t *real_backends = gen_backends(10);
    h2o_balancer_backend_t **backends = alloca(10 * sizeof(*backends));
    size_t i, selected;
    size_t last_selected = 0;
    size_t total_count = 0;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        backends[i] = &real_backends[i].super;
    balancer = h2o_balancer_create_rr();

    for (i = 0; i < 10; i++)
        total_count += ((unsigned)real_backends[i].super.weight_m1) + 1;
    total_count *= 1000;

    for (i = 0; i < total_count; i++) {
        selected = selector(balancer, backends, 10, tried);
        if (selected > 10) {
            ok(selected >= 0 && selected < 10);
            goto Done;
        }
        check_result = selected >= last_selected || (last_selected == 10 - 1 && selected == 0);
        if (!check_result) {
            ok(check_result);
            goto Done;
        }
        real_backends[selected].leased_count++;
        last_selected = selected;
    }
    ok(check_weight_distribution(real_backends, 10));

Done:
    destroy(balancer);
    free_backends(real_backends);
}

static void test_round_robin_weighted(void)
{
    struct round_robin_test_backend_t *real_backends = gen_backends(10);
    h2o_balancer_backend_t **backends = alloca(10 * sizeof(*backends));
    size_t i, selected;
    size_t last_selected = 0;
    size_t total_count = 0;
    char tried[10] = {0};
    int check_result = 1;
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++) {
        backends[i] = &real_backends[i].super;
        real_backends[i].super.weight_m1 = i % 3;
    }
    balancer = h2o_balancer_create_rr();

    for (i = 0; i < 10; i++)
        total_count += ((unsigned)real_backends[i].super.weight_m1) + 1;
    total_count *= 1000;

    for (i = 0; i < total_count; i++) {
        selected = selector(balancer, backends, 10, tried);
        if (selected > 10) {
            ok(selected >= 0 && selected < 10);
            goto Done;
        }
        check_result = selected >= last_selected || (last_selected == 10 - 1 && selected == 0);
        if (!check_result) {
            ok(check_result);
            goto Done;
        }
        real_backends[selected].leased_count++;
        last_selected = selected;
    }
    ok(check_weight_distribution(real_backends, 10));

Done:
    destroy(balancer);
    free_backends(real_backends);
}

void test_lib__common__balancer__roundrobin_c(void)
{
    subtest("when_backend_down", test_when_backend_down);
    subtest("round_robin", test_round_robin);
    subtest("round_robin_weighted", test_round_robin_weighted);
}
