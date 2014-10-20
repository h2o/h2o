/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include "h2o/string_.h"
#include "h2o/http1client.h"

static int exit_status = -1;

static int on_body(h2o_http1client_t *client, const char *errstr, h2o_buf_t *bufs, size_t bufcnt)
{
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        fprintf(stderr, "%s\n", errstr);
        exit_status = 1;
        return -1;
    }

    for (i = 0; i != bufcnt; ++i)
        fwrite(bufs[i].base, 1, bufs[i].len, stdout);

    if (errstr == h2o_http1client_error_is_eos)
        exit_status = 0;

    return 0;
}

static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status, h2o_buf_t msg, struct phr_header *headers, size_t num_headers)
{
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        fprintf(stderr, "%s\n", errstr);
        exit_status = 1;
        return NULL;
    }

    printf("HTTP/1.%d %d %.*s\n", minor_version, status, (int)msg.len, msg.base);
    for (i = 0; i != num_headers; ++i)
        printf("%.*s: %.*s\n", (int)headers[i].name_len, headers[i].name, (int)headers[i].value_len, headers[i].value);
    printf("\n");

    if (errstr == h2o_http1client_error_is_eos) {
        exit_status = 0;
        return NULL;
    }

    return on_body;
}

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_buf_t **reqbufs, size_t *reqbufcnt, int *method_is_head)
{
    if (errstr != NULL) {
        fprintf(stderr, "%s\n", errstr);
        exit_status = 1;
        return NULL;
    }

    *reqbufs = (h2o_buf_t*)client->data;
    *reqbufcnt = 1;
    *method_is_head = 0;

    return on_head;
}

int main(int argc, char **argv)
{
    h2o_timeout_t zero_timeout, io_timeout;
    h2o_http1client_ctx_t ctx = {
        NULL,
        &zero_timeout,
        &io_timeout
    };
    h2o_mempool_t pool;
    char *scheme, *host, *path;
    uint16_t port;
    h2o_buf_t req;
    h2o_http1client_t *client;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <url>\n", argv[0]);
        return 1;
    }

    h2o_mempool_init(&pool);

    if (h2o_parse_url(&pool, argv[1], &scheme, &host, &port, &path) != 0) {
        fprintf(stderr, "unrecognized type of URL: %s\n", argv[1]);
        return 1;
    }
    if (strcmp(scheme, "https") == 0) {
        fprintf(stderr, "https is not (yet) supported\n");
        return 1;
    }
    req.len = asprintf((char**)&req.base, "GET %s HTTP/1.1\r\nhost: %s:%u\r\nconnection: close\r\n\r\n", path, host, (unsigned)port);

    /* setup context */
#if H2O_USE_LIBUV
    ctx.loop = uv_loop_new();
#else
    ctx.loop = h2o_evloop_create();
#endif
    h2o_timeout_init(ctx.loop, &zero_timeout, 0);
    h2o_timeout_init(ctx.loop, &io_timeout, 5000); /* 5 seconds */

    /* setup client */
    client = h2o_http1client_connect(&ctx, &pool, host, port, on_connect);
    assert(client != NULL);
    client->data = &req;

    while (exit_status == -1) {
#if H2O_USE_LIBUV
        uv_run(ctx.loop, UV_RUN_DEFAULT);
#else
        h2o_evloop_run(ctx.loop);
#endif
    }

    return exit_status;
}
