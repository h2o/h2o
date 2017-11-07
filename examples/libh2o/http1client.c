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
#include <unistd.h>
#include <stdlib.h>
#include "h2o.h"

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

static h2o_socketpool_t *sockpool;
static h2o_mem_pool_t pool;
static const char *url;
static char *method = "GET";
static int cnt_left = 3;
static int body_size = 0;
static int chunk_size = 10;
static h2o_iovec_t iov_filler;
static int delay_interval_ms = 0;
static int cur_body_size;

static h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                          int *method_is_head, h2o_http1client_proceed_req_cb *proceed_req_cb,
                                          h2o_iovec_t *cur_body, int *body_is_chunked, h2o_url_t *origin);
static h2o_http1client_body_cb on_head(h2o_http1client_t *client, const char *errstr, int minor_version, int status,
                                       h2o_iovec_t msg, h2o_header_t *headers, size_t num_headers, int rlen);

static void start_request(h2o_http1client_ctx_t *ctx)
{
    h2o_url_t url_parsed;
    h2o_iovec_t *req;

    /* clear memory pool */
    h2o_mem_clear_pool(&pool);

    /* parse URL */
    if (h2o_url_parse(url, SIZE_MAX, &url_parsed) != 0) {
        fprintf(stderr, "unrecognized type of URL: %s\n", url);
        exit(1);
    }

    /* build request */
    req = h2o_mem_alloc_pool(&pool, sizeof(*req));
    req->base = h2o_mem_alloc_pool(&pool, 1024);
    req->len =
        snprintf(req->base, 1024, "%s %.*s HTTP/1.1\r\ncontent-length:%d\r\nhost: %.*s\r\n\r\n", method, (int)url_parsed.path.len,
                 url_parsed.path.base, body_size, (int)url_parsed.authority.len, url_parsed.authority.base);
    cur_body_size = body_size;
    assert(req->len < 1024);

    /* initiate the request */
    if (sockpool == NULL) {
        sockpool = h2o_mem_alloc(sizeof(*sockpool));
        h2o_socketpool_init_specific(sockpool, 10, &url_parsed, 1, NULL, NULL, NULL);
        h2o_socketpool_set_timeout(sockpool, 5000 /* in msec */);
        h2o_socketpool_register_loop(sockpool, ctx->loop);

        SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method());
        SSL_CTX_load_verify_locations(ssl_ctx, H2O_TO_STR(H2O_ROOT) "/share/h2o/ca-bundle.crt", NULL);
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        h2o_socketpool_set_ssl_ctx(sockpool, ssl_ctx);
        SSL_CTX_free(ssl_ctx);
    }
    h2o_http1client_connect(NULL, req, ctx, sockpool, &url_parsed, on_connect, NULL);
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
                                h2o_header_t *headers, size_t num_headers, int rlen)
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

int fill_body(h2o_iovec_t *reqbuf)
{
    if (cur_body_size > 0) {
        memcpy(reqbuf, &iov_filler, sizeof(*reqbuf));
        reqbuf->len = MIN(iov_filler.len, cur_body_size);
        cur_body_size -= reqbuf->len;
        return 0;
    } else {
        *reqbuf = h2o_iovec_init(NULL, 0);
        return 1;
    }
}

static h2o_timeout_t post_body_timeout;

struct st_timeout_ctx {
    h2o_socket_t *sock;
    h2o_timeout_entry_t _timeout;
};
static void timeout_cb(h2o_timeout_entry_t *entry)
{
    static h2o_iovec_t reqbuf;
    struct st_timeout_ctx *tctx = H2O_STRUCT_FROM_MEMBER(struct st_timeout_ctx, _timeout, entry);

    fill_body(&reqbuf);
    h2o_timeout_unlink(&tctx->_timeout);
    h2o_http1client_write_req(tctx->sock, reqbuf, cur_body_size <= 0);
    free(tctx);

    return;
}

static void proceed_request(h2o_http1client_t *client, size_t written, int is_end_stream)
{
    if (cur_body_size > 0) {
        struct st_timeout_ctx *tctx;
        tctx = h2o_mem_alloc(sizeof(*tctx));
        memset(tctx, 0, sizeof(*tctx));
        tctx->sock = client->sock;
        tctx->_timeout.cb = timeout_cb;
        h2o_timeout_link(client->ctx->loop, &post_body_timeout, &tctx->_timeout);
    }
}

h2o_http1client_head_cb on_connect(h2o_http1client_t *client, const char *errstr, h2o_iovec_t **reqbufs, size_t *reqbufcnt,
                                   int *method_is_head, h2o_http1client_proceed_req_cb *proceed_req_cb, h2o_iovec_t *cur_body,
                                   int *body_is_chunked, h2o_url_t *dummy)
{
    if (errstr != NULL) {
        fprintf(stderr, "%s\n", errstr);
        exit(1);
        return NULL;
    }

    *reqbufs = (h2o_iovec_t *)client->data;
    *reqbufcnt = 1;
    *method_is_head = 0;
    if (cur_body_size > 0) {
        *proceed_req_cb = proceed_request;

        struct st_timeout_ctx *tctx;
        tctx = h2o_mem_alloc(sizeof(*tctx));
        memset(tctx, 0, sizeof(*tctx));
        tctx->sock = client->sock;
        tctx->_timeout.cb = timeout_cb;
        h2o_timeout_link(client->ctx->loop, &post_body_timeout, &tctx->_timeout);
    }

    return on_head;
}

static void usage(const char *progname)
{
    fprintf(stderr,
            "Usage: [-t <times>] [-m <method>] [-b <body size>] [-c <chunk size>] [-i <interval between chunks>] %s <url>\n",
            progname);
}
int main(int argc, char **argv)
{
    h2o_multithread_queue_t *queue;
    h2o_multithread_receiver_t getaddr_receiver;
    h2o_timeout_t io_timeout;
    h2o_http1client_ctx_t ctx = {NULL, &getaddr_receiver, &io_timeout, &io_timeout, &io_timeout};
    int opt;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    while ((opt = getopt(argc, argv, "t:m:b:c:i:")) != -1) {
        switch (opt) {
        case 't':
            cnt_left = atoi(optarg);
            break;
        case 'm':
            method = optarg;
            break;
        case 'b':
            body_size = atoi(optarg);
            break;
        case 'c':
            chunk_size = atoi(optarg);
            if (chunk_size <= 0) {
                fprintf(stderr, "chunk size must be greater than 0\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'i':
            delay_interval_ms = atoi(optarg);
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }
    if (argc - optind != 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    url = argv[optind];

    if (body_size != 0) {
        iov_filler.base = h2o_mem_alloc(chunk_size);
        memset(iov_filler.base, 'a', chunk_size);
        iov_filler.len = chunk_size;
    }
    h2o_mem_init_pool(&pool);

/* setup context */
#if H2O_USE_LIBUV
    ctx.loop = uv_loop_new();
#else
    ctx.loop = h2o_evloop_create();
#endif

    h2o_timeout_init(ctx.loop, &post_body_timeout, delay_interval_ms);

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
