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

/*
 * This file implements a test harness for using h2o with LibFuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info.
 */

#define H2O_USE_EPOLL 1
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/url.h"
#include "h2o/memcached.h"

#if !defined(HTTP1) && !defined(HTTP2)
#error "Please defined one of HTTP1 or HTTP2"
#endif

#if defined(HTTP1) && defined(HTTP2)
#error "Please defined one of HTTP1 or HTTP2, but not both"
#endif

static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_accept_ctx_t accept_ctx;
static int client_timeout_ms;
static char unix_listener[PATH_MAX];

/*
 * Registers a request handler with h2o
 */
static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
    h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;
    return pathconf;
}

/*
 * Request handler used for testing. Returns a basic "200 OK" response.
 */
static int chunked_test(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = {NULL, NULL};

    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    h2o_iovec_t body = h2o_strdup(&req->pool, "hello world\n", SIZE_MAX);
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("text/plain"));
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, H2O_SEND_STATE_FINAL);

    return 0;
}

/* copy from src to dst, return true if src has EOF */
static int drain(int fd)
{
    char buf[4096];
    ssize_t n;

    n = read(fd, buf, sizeof(buf));
    if (n <= 0) {
        return 1;
    }
    return 0;
}

/* A request sent from client thread to h2o server */
struct writer_thread_arg {
    char *buf;
    size_t len;
    int fd;
    h2o_barrier_t barrier;
};

/*
 * Reads writer_thread_arg from fd and stores to buf
 */
static void read_fully(int fd, char *buf, size_t len)
{
    int done = 0;
    while (len) {
        int ret;
        while ((ret = read(fd, buf + done, len)) == -1 && errno == EINTR)
            ;
        if (ret <= 0) {
            abort();
        }
        done += ret;
        len -= ret;
    }
}

/*
 * Writes the writer_thread_args at buf to fd
 */
static void write_fully(int fd, char *buf, size_t len, int abort_on_err)
{
    int done = 0;
    while (len) {
        int ret;
        while ((ret = write(fd, buf + done, len)) == -1 && errno == EINTR)
            ;
        if (ret <= 0) {
            if (abort_on_err)
                abort();
            else
                return;
        }
        done += ret;
        len -= ret;
    }
}

#define OK_RESP                                                                                                                    \
    "HTTP/1.0 200 OK\r\n"                                                                                                          \
    "Connection: Close\r\n\r\nOk"
#define OK_RESP_LEN (sizeof(OK_RESP) - 1)

void *upstream_thread(void *arg)
{
    char *dirname = (char *)arg;
    char path[PATH_MAX];
    char rbuf[1 * 1024 * 1024];
    snprintf(path, sizeof(path), "/%s/_.sock", dirname);
    int sd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sd < 0) {
        abort();
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        abort();
    }
    if (listen(sd, 100) != 0) {
        abort();
    }

    while (1) {
        struct sockaddr_un caddr;
        socklen_t slen = 0;
        int cfs = accept(sd, (struct sockaddr *)&caddr, &slen);
        if (cfs < 0) {
            continue;
        }
        read(cfs, rbuf, sizeof(rbuf));
        write_fully(cfs, (char *)OK_RESP, OK_RESP_LEN, 0);
        close(cfs);
    }
}
/*
 * Thread: Loops writing fuzzed req to socket and then reading results back.
 * Acts as a client to h2o. *arg points to file descripter to read
 * writer_thread_args from.
 */
void *writer_thread(void *arg)
{
    int rfd = (long)arg;
    while (1) {
        int pos, sockinp, sockoutp, cnt, len;
        char *buf;
        struct writer_thread_arg *wta;

        /* Get fuzzed request */
        read_fully(rfd, (char *)&wta, sizeof(wta));

        pos = 0;
        sockinp = wta->fd;
        sockoutp = wta->fd;
        cnt = 0;
        buf = wta->buf;
        len = wta->len;

        /*
         * Send fuzzed req and read results until the socket is closed (or
         * something spurious happens)
         */
        while (cnt++ < 20 && (pos < len || sockinp >= 0)) {
#define MARKER "\n--MARK--\n"
            /* send 1 packet */
            if (pos < len) {
                char *p = (char *)memmem(buf + pos, len - pos, MARKER, sizeof(MARKER) - 1);
                if (p) {
                    int l = p - (buf + pos);
                    write(sockoutp, buf + pos, l);
                    pos += l;
                    pos += sizeof(MARKER) - 1;
                }
            } else {
                if (sockinp >= 0) {
                    shutdown(sockinp, SHUT_WR);
                }
            }

            /* drain socket */
            if (sockinp >= 0) {
                struct timeval timeo;
                fd_set rd;
                int n;

                FD_ZERO(&rd);
                FD_SET(sockinp, &rd);
                timeo.tv_sec = 0;
                timeo.tv_usec = client_timeout_ms * 1000;
                n = select(sockinp + 1, &rd, NULL, NULL, &timeo);
                if (n > 0 && FD_ISSET(sockinp, &rd) && drain(sockinp)) {
                    sockinp = -1;
                }
            }
        }
        close(wta->fd);
        h2o_barrier_wait(&wta->barrier);
        h2o_barrier_destroy(&wta->barrier);
        free(wta);
    }
}

/*
 * Creates socket pair and passes fuzzed req to a thread (the HTTP[/2] client)
 * for writing to the target h2o server. Returns the server socket fd.
 */
static int feeder(int sfd, char *buf, size_t len, h2o_barrier_t **barrier)
{
    int pair[2];
    struct writer_thread_arg *wta;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
        return -1;

    wta = (struct writer_thread_arg *)malloc(sizeof(*wta));
    wta->fd = pair[0];
    wta->buf = buf;
    wta->len = len;
    h2o_barrier_init(&wta->barrier, 2);
    *barrier = &wta->barrier;

    write_fully(sfd, (char *)&wta, sizeof(wta), 1);
    return pair[1];
}

/*
 * Creates/connects socket pair for client/server interaction and passes
 * fuzzed request to client for sending.
 * Returns server socket fd.
 */
static int create_accepted(int sfd, char *buf, size_t len, h2o_barrier_t **barrier)
{
    int fd;
    h2o_socket_t *sock;
    struct timeval connected_at = h2o_gettimeofday(ctx.loop);

    /* Create an HTTP[/2] client that will send the fuzzed request */
    fd = feeder(sfd, buf, len, barrier);
    if (fd < 0) {
        abort();
    }

    /* Pass the server socket to h2o and invoke request processing */
    sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION);

#if defined(HTTP1)
    h2o_http1_accept(&accept_ctx, sock, connected_at);
#else
    h2o_http2_accept(&accept_ctx, sock, connected_at);
#endif

    return fd;
}

/*
 * Returns true if fd if valid. Used to determine when connection is closed.
 */
static int is_valid_fd(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

/*
 * Entry point for libfuzzer.
 * See http://llvm.org/docs/LibFuzzer.html for more info
 */
static int init_done;
static int job_queue[2];
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int c;
    h2o_loop_t *loop;
    h2o_hostconf_t *hostconf;
    pthread_t twriter;
    pthread_t tupstream;

    /*
     * Perform one-time initialization
     */
    if (!init_done) {
        const char *client_timeout_ms_str;
        static char tmpname[] = "/tmp/h2o-fuzz-XXXXXX";
        char *dirname;
        h2o_url_t upstream;
        signal(SIGPIPE, SIG_IGN);

        dirname = mkdtemp(tmpname);
        snprintf(unix_listener, sizeof(unix_listener), "http://[unix://%s/_.sock]/proxy", dirname);
        if ((client_timeout_ms_str = getenv("H2O_FUZZER_CLIENT_TIMEOUT")) != NULL)
            client_timeout_ms = atoi(client_timeout_ms_str);
        if (!client_timeout_ms)
            client_timeout_ms = 10;

        /* Create a single h2o host with multiple request handlers */
        h2o_config_init(&config);
        config.http2.idle_timeout = 10 * 1000;
        config.http1.req_timeout = 10 * 1000;
        config.proxy.io_timeout = 10 * 1000;
        h2o_proxy_config_vars_t proxy_config = {};
        proxy_config.io_timeout = 10 * 1000;
        hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT(unix_listener)), 65535);
        register_handler(hostconf, "/chunked-test", chunked_test);
        h2o_url_parse(unix_listener, strlen(unix_listener), &upstream);
        h2o_socketpool_t *sockpool = new h2o_socketpool_t();
        h2o_socketpool_target_t *target = h2o_socketpool_create_target(&upstream, NULL);
        h2o_socketpool_init_specific(sockpool, SIZE_MAX /* FIXME */, &target, 1, NULL);
        h2o_socketpool_set_timeout(sockpool, 2000);
        h2o_socketpool_set_ssl_ctx(sockpool, NULL);
        h2o_proxy_register_reverse_proxy(h2o_config_register_path(hostconf, "/reproxy-test", 0), &proxy_config, sockpool);
        h2o_file_register(h2o_config_register_path(hostconf, "/", 0), "./examples/doc_root", NULL, NULL, 0);

        loop = h2o_evloop_create();
        h2o_context_init(&ctx, loop, &config);

        accept_ctx.ctx = &ctx;
        accept_ctx.hosts = config.hosts;

        /* Create a thread to act as the HTTP client */
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, job_queue) != 0) {
            abort();
        }
        if (pthread_create(&twriter, NULL, writer_thread, (void *)(long)job_queue[1]) != 0) {
            abort();
        }
        if (pthread_create(&tupstream, NULL, upstream_thread, dirname) != 0) {
            abort();
        }
        init_done = 1;
    }

    /*
     * Pass fuzzed request to client thread and get h2o server socket for
     * use below
     */
    h2o_barrier_t *end;
    c = create_accepted(job_queue[0], (char *)Data, (size_t)Size, &end);
    if (c < 0) {
        goto Error;
    }

    /* Loop until the connection is closed by the client or server */
    while (is_valid_fd(c)) {
        h2o_evloop_run(ctx.loop, 10);
    }

    h2o_barrier_wait(end);
    return 0;
Error:
    return 1;
}
