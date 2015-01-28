/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "h2o/string_.h"
#include "h2o/memcached.h"
#include "h2o/serverutil.h"
#include "../../test.h"
#include "../../../../lib/common/memcached.c"

static struct {
    yrmcds_command cmd;
    yrmcds_status status;
    union {
        h2o_iovec_t get;
    } data;
} expected;

static int expect_cb_called;

static void expect_cb(h2o_memcached_response_t *resp)
{
    int success = 0;

    ++expect_cb_called;

    if (resp->err != 0) {
        h2o_memcached_print_error(resp->err);
        goto Exit;
    }
    if (resp->cmd != expected.cmd) {
        fprintf(stderr, "unexpected command response, expected %u, got %u\n", expected.cmd, resp->cmd);
        goto Exit;
    }
    if (resp->status != expected.status) {
        fprintf(stderr, "unexpected status, expected %u, got %u\n", expected.status, resp->status);
        goto Exit;
    }
    if (expected.data.get.base != NULL) {
        if (!h2o_memis(resp->data.get.base, resp->data.get.len, expected.data.get.base, expected.data.get.len)) {
            fprintf(stderr, "unexpected get data, expected %.*s, got %.*s\n", (int)expected.data.get.len, expected.data.get.base, (int)resp->data.get.len, resp->data.get.base);
        goto Exit;
        }
    }

    success = 1;
Exit:
    ok(success);
}

static void test_expect(void)
{
    sleep(3);
    if (!h2o_thread_is_notified()) {
        fprintf(stderr, "no notification from the receiving thread\n");
        goto Fail;
    }
    expect_cb_called = 0;
    h2o_memcached_dispatch_response();
    if (!expect_cb_called) {
        fprintf(stderr, "callback not invoked\n");
        goto Fail;
    }
    /* result is reported by the callback */
    return;
Fail:
    ok(0);
}

void test_lib__memcached_c(void)
{
    const char *memcached_port_str = getenv("MEMCACHED_PORT");
    uint16_t memcached_port;
    h2o_memcached_conn_t *conn;

    if (memcached_port_str == NULL) {
        printf("# SKIP skipping memcached tests (setenv MEMCACHED_PORT=<port> to run)\n");
        return;
    }
    if (sscanf(memcached_port_str, "%" PRIu16, &memcached_port) != 1) {
        fprintf(stderr, "MEMCACHED_PORT is invalid\n");
        ok(0);
        return;
    }

    /* connect */
    conn = h2o_memcached_open("127.0.0.1", memcached_port);
    ok(conn != NULL);

    /* get nonexistitent value */
    h2o_memcached_get(conn, H2O_STRLIT("hello"), expect_cb, NULL);
    memset(&expected, 0, sizeof(expected));
    expected.cmd = YRMCDS_CMD_GET;
    expected.status = YRMCDS_STATUS_NOTFOUND;
    test_expect();

    /* set (and do not wait for response) */
    h2o_memcached_set(conn, H2O_STRLIT("hello"), H2O_STRLIT("world"), INT32_MAX, NULL, NULL);

    /* get */
    h2o_memcached_get(conn, H2O_STRLIT("hello"), expect_cb, NULL);
    memset(&expected, 0, sizeof(expected));
    expected.cmd = YRMCDS_CMD_GET;
    expected.status = YRMCDS_STATUS_OK;
    expected.data.get = (h2o_iovec_t){H2O_STRLIT("world")};
    test_expect();

    /* h2o_memcached_close(conn); */
}
