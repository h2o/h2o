/*
 * Copyright (c) 2021 Fastly, Inc.
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
#include "driver_common.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/*
 * Registers a request handler with h2o
 */
h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
    h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;
    return pathconf;
}

/*
 * Writes the writer_thread_args at buf to fd
 */
void write_fully(int fd, char *buf, size_t len, int abort_on_err)
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

h2o_barrier_t init_barrier;
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

    h2o_barrier_wait(&init_barrier);
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

void register_proxy(h2o_hostconf_t *hostconf, const char *unix_path, h2o_access_log_filehandle_t *logfh)
{
    h2o_url_t upstream;
    h2o_proxy_config_vars_t proxy_config = {};
    h2o_pathconf_t *pathconf;
    /* Assuming the origin is in the same node and is not super busy, we expect 100ms should be enough for proxy timeout.
     * Having a large value would explode the total runtime of the fuzzer. */
    proxy_config.io_timeout = 100;
    proxy_config.connect_timeout = proxy_config.io_timeout;
    proxy_config.first_byte_timeout = proxy_config.io_timeout;
    proxy_config.max_buffer_size = 1024 * 1024;
    h2o_url_parse(unix_path, strlen(unix_path), &upstream);
    h2o_socketpool_t *sockpool = new h2o_socketpool_t();
    h2o_socketpool_target_t *target = h2o_socketpool_create_target(&upstream, NULL);
    h2o_socketpool_init_specific(sockpool, SIZE_MAX /* FIXME */, &target, 1, NULL);
    h2o_socketpool_set_timeout(sockpool, 2000);
    h2o_socketpool_set_ssl_ctx(sockpool, NULL);
    pathconf = h2o_config_register_path(hostconf, "/reproxy-test", 0);
    h2o_proxy_register_reverse_proxy(pathconf, &proxy_config, sockpool);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);
}
