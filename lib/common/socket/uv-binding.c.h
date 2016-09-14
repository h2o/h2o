/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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

struct st_h2o_uv_socket_t {
    h2o_socket_t super;
    struct {
        uv_stream_t *stream;
        uv_close_cb close_cb;
    } uv;
    union {
        uv_connect_t _creq;
        uv_write_t _wreq;
    };
};

static void schedule_timer(h2o_timeout_t *timeout);

static void alloc_inbuf_tcp(uv_handle_t *handle, size_t suggested_size, uv_buf_t *_buf)
{
    struct st_h2o_uv_socket_t *sock = handle->data;

    h2o_iovec_t buf = h2o_buffer_reserve(&sock->super.input, 4096);
    memcpy(_buf, &buf, sizeof(buf));
}

static void alloc_inbuf_ssl(uv_handle_t *handle, size_t suggested_size, uv_buf_t *_buf)
{
    struct st_h2o_uv_socket_t *sock = handle->data;

    h2o_iovec_t buf = h2o_buffer_reserve(&sock->super.ssl->input.encrypted, 4096);
    memcpy(_buf, &buf, sizeof(buf));
}

static void on_read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_h2o_uv_socket_t *sock = stream->data;

    if (nread < 0) {
        sock->super.bytes_read = 0;
        sock->super._cb.read(&sock->super, h2o_socket_error_closed);
        return;
    }

    sock->super.input->size += nread;
    sock->super.bytes_read = nread;
    sock->super._cb.read(&sock->super, NULL);
}

static void on_read_ssl(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_h2o_uv_socket_t *sock = stream->data;
    size_t prev_bytes_read = sock->super.input->size;
    const char *err = h2o_socket_error_io;

    if (nread > 0) {
        sock->super.ssl->input.encrypted->size += nread;
        if (sock->super.ssl->handshake.cb == NULL)
            err = decode_ssl_input(&sock->super);
        else
            err = NULL;
    }
    sock->super.bytes_read = sock->super.input->size - prev_bytes_read;
    sock->super._cb.read(&sock->super, err);
}

static void on_do_write_complete(uv_write_t *wreq, int status)
{
    struct st_h2o_uv_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_uv_socket_t, _wreq, wreq);
    if (sock->super._cb.write != NULL)
        on_write_complete(&sock->super, status == 0 ? NULL : h2o_socket_error_io);
}

static void free_sock(uv_handle_t *handle)
{
    struct st_h2o_uv_socket_t *sock = handle->data;
    uv_close_cb cb = sock->uv.close_cb;
    free(sock);
    cb(handle);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;
    uv_close((uv_handle_t *)sock->uv.stream, free_sock);
}

int h2o_socket_get_fd(h2o_socket_t *_sock)
{
    int fd, ret;
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;

    ret = uv_fileno((uv_handle_t *)sock->uv.stream, (uv_os_fd_t *)&fd);
    if (ret)
        return -1;

    return fd;
}

void do_read_start(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;

    if (sock->super.ssl == NULL)
        uv_read_start(sock->uv.stream, alloc_inbuf_tcp, on_read_tcp);
    else
        uv_read_start(sock->uv.stream, alloc_inbuf_ssl, on_read_ssl);
}

void do_read_stop(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;
    uv_read_stop(sock->uv.stream);
}

void do_write(h2o_socket_t *_sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;

    assert(sock->super._cb.write == NULL);
    sock->super._cb.write = cb;

    uv_write(&sock->_wreq, sock->uv.stream, (uv_buf_t *)bufs, (int)bufcnt, on_do_write_complete);
}

static struct st_h2o_uv_socket_t *create_socket(h2o_loop_t *loop)
{
    uv_tcp_t *tcp = h2o_mem_alloc(sizeof(*tcp));

    if (uv_tcp_init(loop, tcp) != 0) {
        free(tcp);
        return NULL;
    }
    return (void *)h2o_uv_socket_create((void *)tcp, (uv_close_cb)free);
}

int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    uv_os_fd_t fd;

    if (uv_fileno((uv_handle_t *)sock->uv.stream, &fd) != 0)
        return -1;
    /* FIXME: consider how to overcome the epoll(2) problem; man says,
     * "even after a file descriptor that is part of an epoll set has been closed,
     * events may be reported for that file descriptor if other file descriptors
     * referring to the same underlying file description remain open"
     */
    if ((info->fd = dup(fd)) == -1)
        return -1;
    return 0;
}

h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    struct st_h2o_uv_socket_t *sock = create_socket(loop);

    if (sock == NULL)
        return NULL;
    if (uv_tcp_open((uv_tcp_t *)sock->uv.stream, info->fd) != 0) {
        h2o_socket_close(&sock->super);
        return NULL;
    }

    return &sock->super;
}

h2o_socket_t *h2o_uv_socket_create(uv_stream_t *stream, uv_close_cb close_cb)
{
    struct st_h2o_uv_socket_t *sock = h2o_mem_alloc(sizeof(*sock));

    memset(sock, 0, sizeof(*sock));
    h2o_buffer_init(&sock->super.input, &h2o_socket_buffer_prototype);
    sock->uv.stream = stream;
    sock->uv.close_cb = close_cb;
    stream->data = sock;
    return &sock->super;
}

static void on_connect(uv_connect_t *conn, int status)
{
    if (status == UV_ECANCELED)
        return;
    struct st_h2o_uv_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_uv_socket_t, _creq, conn);
    h2o_socket_cb cb = sock->super._cb.write;
    sock->super._cb.write = NULL;
    cb(&sock->super, status == 0 ? NULL : h2o_socket_error_conn_fail);
}

h2o_loop_t *h2o_socket_get_loop(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    return sock->uv.stream->loop;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock = create_socket(loop);

    if (sock == NULL)
        return NULL;
    if (uv_tcp_connect(&sock->_creq, (void *)sock->uv.stream, addr, on_connect) != 0) {
        h2o_socket_close(&sock->super);
        return NULL;
    }
    sock->super._cb.write = cb;
    return &sock->super;
}

socklen_t h2o_socket_getsockname(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getsockname((void *)sock->uv.stream, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

socklen_t get_peername_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getpeername((void *)sock->uv.stream, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

static void on_timeout(uv_timer_t *timer)
{
    h2o_timeout_t *timeout = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _backend.timer, timer);

    h2o_timeout_run(timer->loop, timeout, h2o_now(timer->loop));
    if (!h2o_linklist_is_empty(&timeout->_entries))
        schedule_timer(timeout);
}

void schedule_timer(h2o_timeout_t *timeout)
{
    h2o_timeout_entry_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_entry_t, _link, timeout->_entries.next);
    uv_timer_start(&timeout->_backend.timer, on_timeout,
                   entry->registered_at + timeout->timeout - h2o_now(timeout->_backend.timer.loop), 0);
}

void h2o_timeout__do_init(h2o_loop_t *loop, h2o_timeout_t *timeout)
{
    uv_timer_init(loop, &timeout->_backend.timer);
}

void h2o_timeout__do_dispose(h2o_loop_t *loop, h2o_timeout_t *timeout)
{
    uv_close((uv_handle_t *)&timeout->_backend.timer, NULL);
}

void h2o_timeout__do_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* register the timer if the entry just being added is the only entry */
    if (timeout->_entries.next == &entry->_link)
        schedule_timer(timeout);
}

void h2o_timeout__do_post_callback(h2o_loop_t *loop)
{
    /* nothing to do */
}
