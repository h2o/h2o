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
    uv_handle_t *handle;
    uv_close_cb close_cb;
    union {
        struct {
            union {
                uv_connect_t _creq;
                uv_write_t _wreq;
            };
        } stream;
        struct {
            int events;
        } poll;
    };
};

static void alloc_inbuf(h2o_buffer_t **buf, uv_buf_t *_vec)
{
    h2o_iovec_t vec = h2o_buffer_try_reserve(buf, 4096);

    /* Returning {NULL, 0} upon reservation failure is fine. Quoting from http://docs.libuv.org/en/v1.x/handle.html#c.uv_alloc_cb,
     * "if NULL is assigned as the buffer’s base or 0 as its length, a UV_ENOBUFS error will be triggered in the uv_udp_recv_cb or
     * the uv_read_cb callback."
     */
    memcpy(_vec, &vec, sizeof(vec));
}

static void alloc_inbuf_tcp(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    struct st_h2o_uv_socket_t *sock = handle->data;
    alloc_inbuf(&sock->super.input, buf);
}

static void alloc_inbuf_ssl(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    struct st_h2o_uv_socket_t *sock = handle->data;
    alloc_inbuf(&sock->super.ssl->input.encrypted, buf);
}

static void on_read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_h2o_uv_socket_t *sock = stream->data;

    if (nread < 0) {
        sock->super._cb.read(&sock->super, h2o_socket_error_closed);
        return;
    }

    sock->super.input->size += nread;
    sock->super.bytes_read += nread;
    sock->super._cb.read(&sock->super, NULL);
}

static void on_read_ssl(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_h2o_uv_socket_t *sock = stream->data;
    size_t prev_size = sock->super.input->size;
    const char *err = h2o_socket_error_io;

    if (nread > 0) {
        sock->super.ssl->input.encrypted->size += nread;
        if (sock->super.ssl->handshake.cb == NULL)
            err = decode_ssl_input(&sock->super);
        else
            err = NULL;
    }
    sock->super.bytes_read += sock->super.input->size - prev_size;
    sock->super._cb.read(&sock->super, err);
}

static void on_poll(uv_poll_t *poll, int status, int events);
static void update_poll(struct st_h2o_uv_socket_t *sock)
{
    assert(sock->handle->type == UV_POLL);
    if (sock->poll.events == 0) {
        uv_poll_stop((uv_poll_t *)sock->handle);
    } else {
        uv_poll_start((uv_poll_t *)sock->handle, sock->poll.events, on_poll);
    }
}

static void on_poll(uv_poll_t *poll, int status, int events)
{
    struct st_h2o_uv_socket_t *sock = poll->data;
    const char *err = status == 0 ? NULL : h2o_socket_error_io;

    if ((events & UV_READABLE) != 0) {
        sock->super._cb.read(&sock->super, err);
    }
    if ((events & UV_WRITABLE) != 0) {
        sock->super._cb.write(&sock->super, err);
        sock->poll.events &= ~UV_WRITABLE;
        update_poll(sock);
    }
}

static void on_do_write_complete(uv_write_t *wreq, int status)
{
    struct st_h2o_uv_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_uv_socket_t, stream._wreq, wreq);
    if (sock->super._cb.write != NULL)
        on_write_complete(&sock->super, status == 0 ? NULL : h2o_socket_error_io);
}

static void free_sock(uv_handle_t *handle)
{
    struct st_h2o_uv_socket_t *sock = handle->data;
    uv_close_cb cb = sock->close_cb;
    free(sock);
    cb(handle);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;
    sock->super._cb.write = NULL; /* avoid the write callback getting called when closing the socket (#1249) */
    uv_close(sock->handle, free_sock);
}

int h2o_socket_get_fd(h2o_socket_t *_sock)
{
    int fd, ret;
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;

    ret = uv_fileno(sock->handle, (uv_os_fd_t *)&fd);
    if (ret)
        return -1;

    return fd;
}

void do_read_start(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;

    switch (sock->handle->type) {
    case UV_TCP:
        if (sock->super.ssl == NULL) {
            uv_read_start((uv_stream_t *)sock->handle, alloc_inbuf_tcp, on_read_tcp);
        } else {
            uv_read_start((uv_stream_t *)sock->handle, alloc_inbuf_ssl, on_read_ssl);
        }
        break;
    case UV_POLL:
        sock->poll.events |= UV_READABLE;
        uv_poll_start((uv_poll_t *)sock->handle, sock->poll.events, on_poll);
        break;
    default:
        h2o_fatal("unexpected handle type");
    }
}

void do_read_stop(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;

    switch (sock->handle->type) {
    case UV_TCP:
        uv_read_stop((uv_stream_t *)sock->handle);
        break;
    case UV_POLL:
        sock->poll.events &= ~UV_READABLE;
        update_poll(sock);
        break;
    default:
        h2o_fatal("unexpected handle type");
    }
}

void do_write(h2o_socket_t *_sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;
    assert(sock->handle->type == UV_TCP);

    assert(sock->super._cb.write == NULL);
    sock->super._cb.write = cb;

    uv_write(&sock->stream._wreq, (uv_stream_t *)sock->handle, (uv_buf_t *)bufs, (int)bufcnt, on_do_write_complete);
}

void h2o_socket_notify_write(h2o_socket_t *_sock, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t *)_sock;
    assert(sock->handle->type == UV_POLL);
    assert(sock->super._cb.write == NULL);

    sock->super._cb.write = cb;
    sock->poll.events |= UV_WRITABLE;
    uv_poll_start((uv_poll_t *)sock->handle, sock->poll.events, on_poll);
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
    assert(sock->handle->type == UV_TCP);
    uv_os_fd_t fd;

    if (uv_fileno(sock->handle, &fd) != 0)
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
    if (uv_tcp_open((uv_tcp_t *)sock->handle, info->fd) != 0) {
        h2o_socket_close(&sock->super);
        return NULL;
    }

    return &sock->super;
}

h2o_socket_t *h2o_uv__poll_create(h2o_loop_t *loop, int fd, uv_close_cb close_cb)
{
    uv_poll_t *poll = h2o_mem_alloc(sizeof(*poll));
    if (uv_poll_init(loop, poll, fd) != 0) {
        free(poll);
        return NULL;
    }
    return h2o_uv_socket_create((uv_handle_t *)poll, close_cb);
}

h2o_socket_t *h2o_uv_socket_create(uv_handle_t *handle, uv_close_cb close_cb)
{
    struct st_h2o_uv_socket_t *sock = h2o_mem_alloc(sizeof(*sock));
    memset(sock, 0, sizeof(*sock));
    h2o_buffer_init(&sock->super.input, &h2o_socket_buffer_prototype);

    sock->handle = handle;
    sock->close_cb = close_cb;
    sock->handle->data = sock;
    if (h2o_socket_ebpf_lookup(sock->handle->loop, h2o_socket_ebpf_init_key, &sock->super).skip_tracing)
        sock->super._skip_tracing = 1;
    return &sock->super;
}

static void on_connect(uv_connect_t *conn, int status)
{
    if (status == UV_ECANCELED)
        return;
    struct st_h2o_uv_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_uv_socket_t, stream._creq, conn);
    h2o_socket_cb cb = sock->super._cb.write;
    sock->super._cb.write = NULL;
    cb(&sock->super, status == 0 ? NULL : h2o_socket_error_conn_fail);
}

h2o_loop_t *h2o_socket_get_loop(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    return sock->handle->loop;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock = create_socket(loop);

    if (sock == NULL)
        return NULL;
    if (uv_tcp_connect(&sock->stream._creq, (void *)sock->handle, addr, on_connect) != 0) {
        h2o_socket_close(&sock->super);
        return NULL;
    }
    sock->super._cb.write = cb;
    return &sock->super;
}

socklen_t h2o_socket_getsockname(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    assert(sock->handle->type == UV_TCP);

    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getsockname((void *)sock->handle, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

socklen_t get_peername_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_uv_socket_t *sock = (void *)_sock;
    assert(sock->handle->type == UV_TCP);

    int len = sizeof(struct sockaddr_storage);
    if (uv_tcp_getpeername((void *)sock->handle, sa, &len) != 0)
        return 0;
    return (socklen_t)len;
}

static void on_timeout(uv_timer_t *uv_timer)
{
    h2o_timer_t *timer = uv_timer->data;
    timer->is_linked = 0;
    timer->cb(timer);
}

void h2o_timer_link(h2o_loop_t *l, uint64_t delay_ticks, h2o_timer_t *timer)
{
    if (timer->uv_timer == NULL) {
        timer->uv_timer = h2o_mem_alloc(sizeof(*timer->uv_timer));
        uv_timer_init(l, timer->uv_timer);
        timer->uv_timer->data = timer;
    }
    timer->is_linked = 1;
    uv_timer_start(timer->uv_timer, on_timeout, delay_ticks, 0);
}

void h2o_timer_unlink(h2o_timer_t *timer)
{
    timer->is_linked = 0;
    if (timer->uv_timer != NULL) {
        uv_timer_stop(timer->uv_timer);
        uv_close((uv_handle_t*)timer->uv_timer, (uv_close_cb)free);
        timer->uv_timer = NULL;
    }
}
