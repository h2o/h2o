/*
 * Copyright (c) 2016 Fastly, Inc.
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
#define H2O_USE_EPOLL 1
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <wait.h>
#include <malloc.h>
#include <unistd.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/memcached.h"

#if !defined(HTTP1) && !defined(HTTP2)
#  error "Please defined one of HTTP1 or HTTP2"
#endif

#if defined(HTTP1) && defined(HTTP2)
#  error "Please defined one of HTTP1 or HTTP2, but not both"
#endif

static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
    h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;
    return pathconf;
}

static int chunked_test(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = {NULL, NULL};

    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    h2o_iovec_t body = h2o_strdup(&req->pool, "hello world\n", SIZE_MAX);
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain"));
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, H2O_SEND_STATE_FINAL);

    return 0;
}

static int reproxy_test(h2o_handler_t *self, h2o_req_t *req)
{
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_X_REPROXY_URL, H2O_STRLIT("http://www.ietf.org/"));
    h2o_send_inline(req, H2O_STRLIT("you should never see this!\n"));

    return 0;
}

static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_accept_ctx_t accept_ctx;


/* copy from src to dst, return true if src has EOF */
static int drain(int fd)
{
    char buf[4096];
    ssize_t n;

    n = read(fd, buf, sizeof(buf));
    if(n <= 0) {
        return 1;
    }
    return 0;
}

struct writer_thread_arg {
    char *buf;
    size_t len;
    int fd;
};

void *writer_thread(void *arg)
{
    struct writer_thread_arg *wta = (struct writer_thread_arg *)arg;
    int pos = 0;
    int sockinp = wta->fd;
    int sockoutp = wta->fd;
    int cnt = 0;
    char *buf = wta->buf;
    int len = wta->len;

    while(cnt++ < 20 && (pos < len || sockinp >= 0)) {
#define MARKER "\n--MARK--\n"
        /* send 1 packet */
        if(pos < len) {
            char *p = (char *)memmem(buf + pos, len - pos, MARKER, sizeof(MARKER) - 1);
            if(p) {
                int l = p - (buf + pos);
                write(sockoutp, buf + pos, l);
                pos += l;
                pos += sizeof(MARKER) - 1;
            }
        } else {
            if(sockinp >= 0) {
                shutdown(sockinp, SHUT_WR);
            }
        }

        /* drain socket */
        if(sockinp >= 0) {
            struct timeval timeo;
            fd_set rd;
            int n;

            FD_ZERO(&rd);
            FD_SET(sockinp, &rd);
            timeo.tv_sec = 0;
            timeo.tv_usec = 10 * 1000;
            n = select(sockinp+1, &rd, NULL, NULL, &timeo);
            if(n > 0 && FD_ISSET(sockinp, &rd) && drain(sockinp)) {
                sockinp = -1;
            }
        }
    }
    close(wta->fd);
    free(wta);
    return NULL;
}

static int feeder(pthread_t *t, char *buf, size_t len)
{
    int pair[2];
    struct writer_thread_arg *wta;

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
        return -1;

    wta = (struct writer_thread_arg *)malloc(sizeof(*wta));
    wta->fd = pair[0];
    wta->buf = buf;
    wta->len = len;
    assert(pthread_create(t, NULL, writer_thread, wta) == 0);
    return pair[1];
}

static int create_accepted(pthread_t *t, char *buf, size_t len)
{
    int fd;
    h2o_socket_t *sock;
    struct timeval connected_at = *h2o_get_timestamp(&ctx, NULL, NULL);

    fd = feeder(t, buf, len);
    assert(fd >= 0);

    sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION);

#if defined(HTTP1)
    h2o_http1_accept(&accept_ctx, sock, connected_at);
#else
    h2o_http2_accept(&accept_ctx, sock, connected_at);
#endif

    return fd;
}

static int is_valid_fd(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

int init_done;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int c;
    h2o_loop_t *loop;
    h2o_hostconf_t *hostconf;
    pthread_t t;

    if (!init_done) {
        signal(SIGPIPE, SIG_IGN);

        h2o_config_init(&config);
        config.http2.idle_timeout = 10 * 1000;
        config.http1.req_timeout = 10 * 1000;
        hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);
        register_handler(hostconf, "/chunked-test", chunked_test);
        h2o_reproxy_register(register_handler(hostconf, "/reproxy-test", reproxy_test));
        h2o_file_register(h2o_config_register_path(hostconf, "/", 0), "./examples/doc_root", NULL, NULL, 0);

        loop = h2o_evloop_create();
        h2o_context_init(&ctx, loop, &config);

        accept_ctx.ctx = &ctx;
        accept_ctx.hosts = config.hosts;
        init_done = 1;
    }
    c = create_accepted(&t, (char *)Data, (size_t)Size);
    if (c < 0) {
        goto Error;
    }

    while (is_valid_fd(c) && h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
        ;

    pthread_join(t, NULL);
    return 0;
Error:
    return 1;
}
