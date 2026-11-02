/*
 * Copyright (c) 2026 Fastly, Kazuho Oku
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
#include <arpa/inet.h>
#include "../../test.h"
#include "../../../../lib/common/socketpool.c"

static h2o_multithread_receiver_t getaddr_receiver;

struct connect_result_t {
    int called;
    h2o_socket_t *sock;
    const char *errstr;
};

static void on_connect_cb(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *url)
{
    struct connect_result_t *result = data;
    result->called = 1;
    result->sock = sock;
    result->errstr = errstr;
}

static void run_loop_once(void)
{
#if H2O_USE_LIBUV
    uv_run(test_loop, UV_RUN_ONCE);
#else
    h2o_evloop_run(test_loop, INT32_MAX);
#endif
}

static void init_pool(h2o_socketpool_t *pool, const char **urls, size_t num_urls)
{
    h2o_socketpool_target_t *targets[num_urls];

    for (size_t i = 0; i != num_urls; ++i) {
        h2o_url_t url;
        int ret = h2o_url_parse(NULL, urls[i], SIZE_MAX, &url);
        assert(ret == 0);
        targets[i] = h2o_socketpool_create_target(&url, NULL);
    }
    h2o_socketpool_init_specific(pool, SIZE_MAX, targets, num_urls, NULL);
    h2o_socketpool_register_loop(pool, test_loop);
}

static int counters_are_zero(h2o_socketpool_t *pool)
{
    if (pool->_shared.count != 0)
        return 0;
    for (size_t i = 0; i != pool->targets.size; ++i)
        if (pool->targets.entries[i]->_shared.leased_count != 0)
            return 0;
    return 1;
}

static int open_listener(char *url, size_t url_size)
{
    struct sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sinlen = sizeof(sin);
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd != -1);
    if (bind(fd, (void *)&sin, sizeof(sin)) != 0 || listen(fd, 8) != 0 || getsockname(fd, (void *)&sin, &sinlen) != 0)
        h2o_fatal("failed to open listener:%s", strerror(errno));
    snprintf(url, url_size, "http://127.0.0.1:%u/", (unsigned)ntohs(sin.sin_port));

    return fd;
}

static void test_refused(void)
{
    const char *urls[] = {"http://127.0.0.1:1/"};
    h2o_socketpool_t pool;
    struct connect_result_t result = {0};

    init_pool(&pool, urls, PTLS_ELEMENTSOF(urls));
    h2o_socketpool_connect(NULL, &pool, &pool.targets.entries[0]->url, test_loop, &getaddr_receiver, h2o_iovec_init(NULL, 0),
                           on_connect_cb, &result);
    while (!result.called)
        run_loop_once();
    ok(result.sock == NULL);
    ok(result.errstr != NULL);
    ok(counters_are_zero(&pool));

    h2o_socketpool_dispose(&pool);
}

static void test_refused_with_retry(void)
{
    const char *urls[] = {"http://127.0.0.1:1/", "http://127.0.0.1:2/"};
    h2o_socketpool_t pool;
    struct connect_result_t result = {0};

    init_pool(&pool, urls, PTLS_ELEMENTSOF(urls));
    h2o_socketpool_connect(NULL, &pool, &pool.targets.entries[0]->url, test_loop, &getaddr_receiver, h2o_iovec_init(NULL, 0),
                           on_connect_cb, &result);
    while (!result.called)
        run_loop_once();
    ok(result.sock == NULL);
    ok(result.errstr != NULL);
    ok(counters_are_zero(&pool));

    h2o_socketpool_dispose(&pool);
}

static void test_connected(void)
{
    char url[64];
    int listen_fd = open_listener(url, sizeof(url));
    const char *urls[] = {url};
    h2o_socketpool_t pool;
    struct connect_result_t result = {0};

    init_pool(&pool, urls, PTLS_ELEMENTSOF(urls));
    h2o_socketpool_connect(NULL, &pool, &pool.targets.entries[0]->url, test_loop, &getaddr_receiver, h2o_iovec_init(NULL, 0),
                           on_connect_cb, &result);
    while (!result.called)
        run_loop_once();
    ok(result.sock != NULL);
    ok(pool._shared.count == 1);
    ok(pool.targets.entries[0]->_shared.leased_count == 1);
    h2o_socket_close(result.sock);
    ok(counters_are_zero(&pool));

    h2o_socketpool_dispose(&pool);
    close(listen_fd);
}

static void test_cancel_connecting(void)
{
    char url[64];
    int listen_fd = open_listener(url, sizeof(url));
    const char *urls[] = {url};
    h2o_socketpool_t pool;
    h2o_socketpool_connect_request_t *req;
    struct connect_result_t result = {0};

    init_pool(&pool, urls, PTLS_ELEMENTSOF(urls));
    h2o_socketpool_connect(&req, &pool, &pool.targets.entries[0]->url, test_loop, &getaddr_receiver, h2o_iovec_init(NULL, 0),
                           on_connect_cb, &result);
    /* connection establishment is always notified asynchronously */
    ok(req->sock != NULL);
    h2o_socketpool_cancel_connect(req);
    ok(counters_are_zero(&pool));

    h2o_socketpool_dispose(&pool);
    close(listen_fd);
}

static void test_cancel_resolving_after_refused(void)
{
    const char *urls[] = {"http://127.0.0.1:1/", "http://localhost:1/"};
    h2o_socketpool_t pool;
    h2o_socketpool_connect_request_t *req;
    struct connect_result_t result = {0};

    init_pool(&pool, urls, PTLS_ELEMENTSOF(urls));
    h2o_socketpool_connect(&req, &pool, &pool.targets.entries[0]->url, test_loop, &getaddr_receiver, h2o_iovec_init(NULL, 0),
                           on_connect_cb, &result);
    /* the first target is refused, then the request waits for the name of the second target to be resolved */
    while (!(req->remaining_try_count == 0 && req->getaddr_req != NULL)) {
        assert(!result.called);
        run_loop_once();
    }
    ok(req->sock == NULL);
    h2o_socketpool_cancel_connect(req);
    ok(counters_are_zero(&pool));

    h2o_socketpool_dispose(&pool);
}

void test_lib__common__socketpool_c(void)
{
    /* the receiver is never unregistered, as the result of a cancelled name resolution may arrive later */
    h2o_multithread_register_receiver(h2o_multithread_create_queue(test_loop), &getaddr_receiver, h2o_hostinfo_getaddr_receiver);

    subtest("refused", test_refused);
    subtest("refused_with_retry", test_refused_with_retry);
    subtest("connected", test_connected);
    subtest("cancel_connecting", test_cancel_connecting);
    subtest("cancel_resolving_after_refused", test_cancel_resolving_after_refused);
}
