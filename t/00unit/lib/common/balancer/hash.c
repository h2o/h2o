#include "../../../test.h"
#include "../../../../../lib/common/balancer/hash.c"

#define TEST_REQ_PATH "path/for/testing"

static h2o_socketpool_target_vector_t gen_targets(size_t size)
{
    size_t i;
    h2o_socketpool_target_vector_t targets = {NULL};

    h2o_vector_reserve(NULL, &targets, size);
    for (i = 0; i < size; i++) {
        h2o_socketpool_target_t *target = h2o_mem_alloc(sizeof(*target));
        h2o_url_parse("http://test.vector/some/path", SIZE_MAX, &target->url);
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

static int simple_cmp(const void *_key, const void *_elt)
{
    const uint8_t *key = _key;
    const uint8_t *elt = _elt;

    if (*key > *elt) return 1;
    else if (*key < *elt) return -1;
    else return 0;
}

static void test_range_bsearch(void)
{
    uint8_t buckets[7] = {2, 4, 8, 16, 32, 64, 128};
    uint8_t i;
    size_t expected;
    for (i = 0; i < 255; i++) {
        if (i > 128)
            expected = 0;
        else if (i > 64)
            expected = 6;
        else if (i > 32)
            expected = 5;
        else if (i > 16)
            expected = 4;
        else if (i > 8)
            expected = 3;
        else if (i > 4)
            expected = 2;
        else if (i > 2)
            expected = 1;
        else
            expected = 0;
        if (range_bsearch(&i, buckets, 7, sizeof(uint8_t), simple_cmp, 1) != expected) {
            ok(!"failed on ranged bsearch for ring");
            break;
        }
    }
    for (i = 0; i < 255; i++) {
        if (i > 128)
            expected = 7;
        else if (i > 64)
            expected = 6;
        else if (i > 32)
            expected = 5;
        else if (i > 16)
            expected = 4;
        else if (i > 8)
            expected = 3;
        else if (i > 4)
            expected = 2;
        else if (i > 2)
            expected = 1;
        else
            expected = 0;
        if (range_bsearch(&i, buckets, 7, sizeof(uint8_t), simple_cmp, 0) != expected)
            ok(!"failed on ranged bsearch");
    }
}

static void test_add_bucket(void)
{
    hash_bucket_vector_t buckets = {};
    char tag_buf[NI_MAXHOST + sizeof(":65535")];
    size_t tag_buf_len, i;
    h2o_vector_reserve(NULL, &buckets, 10);
    int checked[10] = {};

    for (i = 0; i < 10; i++) {
        tag_buf_len = sprintf(tag_buf, "%s:%zu", "test.vector", i);
        struct hash_bucket_t bucket = {
            compute_hash(tag_buf, tag_buf_len),
            i,
            1,
            NULL
        };
        add_bucket(&buckets, &bucket);
    }

    checked[buckets.entries[0].target] = 1;
    for (i = 1; i < 10; i++) {
        ok(buckets.entries[i].hash > buckets.entries[i - 1].hash);
        checked[buckets.entries[i].target] = 1;
    }

    for (i = 0; i < 10; i++) {
        ok(checked[i]);
    }
}

static h2o_iovec_t get_same_hash_key(void *socketpool_req_data, h2o_balancer_hash_key_type_t key_type)
{
    h2o_iovec_t result = {H2O_STRLIT(TEST_REQ_PATH)};
    return result;
}

static void test_when_backend_down(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    char tried[10] = {0};
    size_t i;
    size_t selected;
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_hash(1.2, H2O_BALANCER_HASH_KEY_PATH);
    h2o_balancer_hash_set_targets(balancer, targets.entries, 10);
    h2o_balancer_hash_set_get_key_cb(balancer, get_same_hash_key);

    for (i = 0; i < 10; i++) {
        selected = selector(balancer, &targets, tried, NULL);
        ok(selected >= 0 && selected < 10);
        ok(!tried[selected]);
        tried[selected] = 1;
        targets.entries[selected]->_shared.leased_count++;
    }

    free_targets(&targets);
    destroy(balancer);
}

static int check_if_acceptable(h2o_socketpool_target_vector_t *targets, float c, int same_key, hash_bucket_vector_t *buckets)
{
    size_t total_weight = 0;
    size_t i;
    size_t total_leased = 0;
    size_t hashed_index, right_before_hashed_index, target_index;
    size_t max_this_target;
    float max_per_weight;

    if (buckets != NULL && buckets->size != targets->size)
        return -1;

    for (i = 0; i < targets->size; i++) {
        total_weight += targets->entries[i]->conf.weight_m1 + 1;
        total_leased += targets->entries[i]->_shared.leased_count;
    }

    max_per_weight = (total_leased * c) / total_weight;
    for (i = 0; i < buckets->size; i++) {
        target_index = buckets->entries[i].target;
        max_this_target = ceil(max_per_weight * (targets->entries[target_index]->conf.weight_m1 + 1));
        printf("%zu %zu %zu %zu\n", i, target_index, targets->entries[target_index]->_shared.leased_count, max_this_target);
        ok(max_this_target >= targets->entries[target_index]->_shared.leased_count);
        if (max_this_target < targets->entries[target_index]->_shared.leased_count)
            return -1;
    }

    /* Check a special case of Lemma 5 from https://arxiv.org/pdf/1608.01350.pdf where balls hashed to the same bin */
    if (same_key) {
        hashed_index = find_bucket_for_item(buckets, H2O_STRLIT(TEST_REQ_PATH));
        if (hashed_index == 0)
            right_before_hashed_index = buckets->size - 1;
        else
            right_before_hashed_index = hashed_index - 1;
        target_index = buckets->entries[right_before_hashed_index].target;
        max_this_target = ceil(max_per_weight * (targets->entries[target_index]->conf.weight_m1 + 1));
        ok(targets->entries[target_index]->_shared.leased_count < max_this_target);
        for (i = 0; i < targets->size; i++) {
            target_index = buckets->entries[hashed_index].target;
            max_this_target = ceil(max_per_weight * (targets->entries[target_index]->conf.weight_m1 + 1));
            if (targets->entries[target_index]->_shared.leased_count < max_this_target) {
                break;
            }
            hashed_index++;
            if (hashed_index == buckets->size)
                hashed_index = 0;
        }
    }
    return 0;
}

static void test_bounded_hash(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    size_t total_leased = 0;
    char tried[10] = {0};
    h2o_balancer_t *balancer;

    balancer = h2o_balancer_create_hash(1.2, H2O_BALANCER_HASH_KEY_PATH);
    h2o_balancer_hash_set_targets(balancer, targets.entries, 10);
    h2o_balancer_hash_set_get_key_cb(balancer, get_same_hash_key);
    h2o_balancer_hash_set_total_leased_count(balancer, &total_leased);

    for (i = 0; i < 10000; i++) {
        selected = selector(balancer, &targets, tried, NULL);
        if (selected > 10) {
            ok(selected >= 0 && selected < targets.size);
            goto Done;
        }
        targets.entries[selected]->_shared.leased_count++;
        total_leased++;
    }
    if (check_if_acceptable(&targets, 1.2, 1, &((struct bounded_hash_t *)balancer)->buckets) != 0) {
        ok(!"result failed expectation");
    }

Done:
    free_targets(&targets);
    destroy(balancer);
}

static void test_bounded_hash_weighted(void)
{
    h2o_socketpool_target_vector_t targets = gen_targets(10);
    size_t i, selected;
    size_t total_leased = 0;
    char tried[10] = {0};
    h2o_balancer_t *balancer;

    for (i = 0; i < 10; i++)
        targets.entries[i]->conf.weight_m1 = i % 3;

    balancer = h2o_balancer_create_hash(1.2, H2O_BALANCER_HASH_KEY_PATH);
    h2o_balancer_hash_set_targets(balancer, targets.entries, 10);
    h2o_balancer_hash_set_get_key_cb(balancer, get_same_hash_key);
    h2o_balancer_hash_set_total_leased_count(balancer, &total_leased);

    for (i = 0; i < 10000; i++) {
        selected = selector(balancer, &targets, tried, NULL);
        if (selected > 10) {
            ok(selected >= 0 && selected < targets.size);
            goto Done;
        }
        targets.entries[selected]->_shared.leased_count++;
        total_leased++;
    }
    if (check_if_acceptable(&targets, 1.2, 1, &((struct bounded_hash_t *)balancer)->buckets) != 0) {
        ok(!"result failed expectation");
    }

Done:
    free_targets(&targets);
    destroy(balancer);
}

void test_lib__common__balancer__hash_c(void)
{
    subtest("range_bsearch", test_range_bsearch);
    subtest("add_bucket", test_add_bucket);
    subtest("when_backend_down", test_when_backend_down);
    subtest("bounded_hash", test_bounded_hash);
    subtest("bounded_hash_weighted", test_bounded_hash_weighted);
}

