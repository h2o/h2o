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
#include <stdlib.h>
#include "h2o.h"

static h2o_socketpool_t *sockpool;
static h2o_mem_pool_t pool;
static const char *url;
static int cnt_left = 3;

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head);
static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, h2o_header_t *headers, size_t num_headers);

static void start_request(h2o_http1client_ctx_t *ctx)
{
    h2o_url_t url_parsed;
    h2o_iovec_t *req;
    int is_ssl;

    /* clear memory pool */
    h2o_mem_clear_pool(&pool);

    /* parse URL */
    if (h2o_url_parse(url, SIZE_MAX, &url_parsed) != 0) {
        fprintf(stderr, "unrecognized type of URL: %s\n", url);
        exit(1);
    }
    is_ssl = url_parsed.scheme == &H2O_URL_SCHEME_HTTPS;

    /* build request */
    req = h2o_mem_alloc_pool(&pool, sizeof(*req));
    req->base = h2o_mem_alloc_pool(&pool, 1024);
    req->len = snprintf(req->base, 1024, "GET %.*s HTTP/1.1\r\nhost: %.*s\r\n\r\n", (int)url_parsed.path.len, url_parsed.path.base,
                        (int)url_parsed.authority.len, url_parsed.authority.base);
    assert(req->len < 1024);

    /* initiate the request */
    if (1) {
        if (sockpool == NULL) {
            sockpool = h2o_mem_alloc(sizeof(*sockpool));
            h2o_socketpool_init_by_hostport(sockpool, url_parsed.host, h2o_url_get_port(&url_parsed), is_ssl, 10);
            h2o_socketpool_set_timeout(sockpool, ctx->loop, 5000 /* in msec */);
        }
        h2o_http1client_connect_with_pool(NULL, req, ctx, sockpool, on_connect);
    } else {
        h2o_http1client_connect(NULL, req, ctx, url_parsed.host, h2o_url_get_port(&url_parsed), is_ssl, on_connect);
    }
}

static int on_body(h2o_http1client_t *client, const char *errstr)
{
    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        fprintf(stderr, "%s\n", errstr);
        exit(1);
        return -1;
    }

    fwrite(client->sock->input->bytes, 1, client->sock->input->size, stdout);
    h2o_buffer_consume(&client->sock->input, client->sock->input->size);

    if (errstr == h2o_http1client_error_is_eos) {
        if (--cnt_left != 0) {
            /* next attempt */
            h2o_mem_clear_pool(&pool);
            start_request(client->ctx);
        }
    }

    return 0;
}

h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status, h2o_iovec_t msg,
                                h2o_header_t *headers, size_t num_headers)
{
    size_t i;

    if (errstr != NULL && errstr != h2o_http1client_error_is_eos) {
        fprintf(stderr, "%s\n", errstr);
        exit(1);
        return NULL;
    }

    printf("HTTP/1.%d %d %.*s\n", minor_version, status, (int)msg.len, msg.base);
    for (i = 0; i != num_headers; ++i)
        printf("%.*s: %.*s\n", (int)headers[i].name->len, headers[i].name->base, (int)headers[i].value.len, headers[i].value.base);
    printf("\n");

    if (errstr == h2o_http1client_error_is_eos) {
        fprintf(stderr, "no body\n");
        exit(1);
        return NULL;
    }

    return on_body;
}

h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                   int *method_is_head)
{
    if (errstr != NULL) {
        fprintf(stderr, "%s\n", errstr);
        exit(1);
        return NULL;
    }

    *reqbufs = (h2o_iovec_t *)client->data;
    *reqbufcnt = 1;
    *method_is_head = 0;

    return on_head;
}

int main(int argc, char **argv)
{
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_timeout_t io_timeout;
    h2o_http1client_ctx_t ctx = {NULL, &getaddr_receiver, &io_timeout};

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ctx.ssl_ctx = SSL_CTX_new(TLSv1_client_method());
    SSL_CTX_load_verify_locations(ctx.ssl_ctx, H2O_TO_STR(H2O_ROOT) "/share/h2o/ca-bundle.crt", NULL);
    SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <url>\n", argv[0]);
        return 1;
    }
    url = argv[1];

    h2o_mem_init_pool(&pool);

/* setup context */
#if H2O_USE_LIBUV
    ctx.loop = uv_loop_new();
#else
    ctx.loop = h2o_evloop_create();
#endif
    queue = h2o_multithread_create_queue(ctx.loop);
    h2o_multithread_register_receiver(queue, ctx.getaddr_receiver, h2o_hostinfo_getaddr_receiver);
    h2o_timeout_init(ctx.loop, &io_timeout, 5000); /* 5 seconds */

    /* setup the first request */
    start_request(&ctx);

    while (cnt_left != 0) {
#if H2O_USE_LIBUV
        uv_run(ctx.loop, UV_RUN_ONCE);
#else
        h2o_evloop_run(ctx.loop, INT32_MAX);
#endif
    }

    return 0;
}
