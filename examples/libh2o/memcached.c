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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "h2o/string_.h"
#include "h2o/memcached.h"
#include "h2o/serverutil.h"

int get_cb_called = 0;

static void get_cb(h2o_memcached_response_t *resp)
{
    ++get_cb_called;

    if (resp->err != 0) {
        h2o_memcached_print_error(resp->err);
        return;
    }
    if (resp->cmd != YRMCDS_CMD_GET) {
        fprintf(stderr, "unexpected command response:%u\n", resp->cmd);
        return;
    }
    switch (resp->status) {
    case YRMCDS_STATUS_NOTFOUND:
        fprintf(stderr, "value not found\n");
        break;
    case YRMCDS_STATUS_OK:
        printf("%.*s\n", (int)resp->data.get.len, resp->data.get.base);
        break;
    default:
        fprintf(stderr, "unexpected status:%u\n", resp->status);
        break;
    }
}

int main(int argc, char **argv)
{
    h2o_thread_initialize_signal_for_notification(SIGCONT);

    h2o_memcached_conn_t *conn = h2o_memcached_open("127.0.0.1", 11211);
    if (conn == NULL)
        return EX_CONFIG;

    /* set (and do not wait for response) */
    h2o_memcached_set(conn, H2O_STRLIT("hello"), H2O_STRLIT("world"), INT32_MAX, NULL, NULL);
    /* get */
    h2o_memcached_get(conn, H2O_STRLIT("hello"), get_cb, NULL);

    while (1) {
        if (h2o_thread_is_notified()) {
            h2o_memcached_dispatch_response();
            if (get_cb_called)
                break;
        }
        sleep(100);
    }

    /* h2o_memcached_close(conn); */
    return 0;
}
