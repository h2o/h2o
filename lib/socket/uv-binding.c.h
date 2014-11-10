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

    h2o_buf_t buf = h2o_reserve_input_buffer(&sock->super.input, 4096);
    memcpy(_buf, &buf, sizeof(buf));
}

static void alloc_inbuf_ssl(uv_handle_t *handle, size_t suggested_size, uv_buf_t *_buf)
{
    struct st_h2o_uv_socket_t *sock = handle->data;

    h2o_buf_t buf = h2o_reserve_input_buffer(&sock->super.ssl->input.encrypted, 4096);
    memcpy(_buf, &buf, sizeof(buf));
}

static void on_read_tcp(uv_stream_t *stream, ssize_t nread, const uv_buf_t* _unused)
{
    struct st_h2o_uv_socket_t *sock = stream->data;

    if (nread < 0) {
        sock->super._cb.read(&sock->super, -1);
        return;
    }

    sock->super.input->size += nread;
    sock->super._cb.read(&sock->super, 0);
}

static void on_read_ssl(uv_stream_t *stream, ssize_t nread, const uv_buf_t *_unused)
{
    struct st_h2o_uv_socket_t *sock = stream->data;
    int status = -1;

    if (nread > 0) {
        sock->super.ssl->input.encrypted->size += nread;
        if (sock->super.ssl->handshake.cb == NULL)
            status = decode_ssl_input(&sock->super);
        else
            status = 0;
    }
    sock->super._cb.read(&sock->super, status);
}

static void on_do_write_complete(uv_write_t *wreq, int status)
{
    struct st_h2o_uv_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_uv_socket_t, _wreq, wreq);
    on_write_complete(&sock->super, status);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t*)_sock;
    uv_close((uv_handle_t*)sock->uv.stream, sock->uv.close_cb);
    free(sock);
}

void do_read_start(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t*)_sock;

    if (sock->super.ssl == NULL)
        uv_read_start(sock->uv.stream, alloc_inbuf_tcp, on_read_tcp);
    else
        uv_read_start(sock->uv.stream, alloc_inbuf_ssl, on_read_ssl);
}

void do_read_stop(h2o_socket_t *_sock)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t*)_sock;
    uv_read_stop(sock->uv.stream);
}

void do_write(h2o_socket_t *_sock, h2o_buf_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock = (struct st_h2o_uv_socket_t*)_sock;

    assert(sock->super._cb.write == NULL);
    sock->super._cb.write = cb;

    uv_write(&sock->_wreq, sock->uv.stream, (uv_buf_t*)bufs, (int)bufcnt, on_do_write_complete);
}

h2o_socket_t *h2o_uv_socket_create(uv_stream_t *stream, struct sockaddr *addr, socklen_t addrlen, uv_close_cb close_cb)
{
    struct st_h2o_uv_socket_t *sock = h2o_malloc(sizeof(*sock));

    memset(sock, 0, sizeof(*sock));
    h2o_init_input_buffer(&sock->super.input);
    if (addr != NULL) {
        memcpy(&sock->super.peername.addr, addr, addrlen);
        sock->super.peername.len = addrlen;
    } else {
        int addrlen = sizeof(sock->super.peername.addr);
        if (uv_tcp_getpeername((uv_tcp_t*)stream, (void*)&sock->super.peername.addr, &addrlen) == 0) {
            sock->super.peername.len = addrlen;
        } else {
            memset(&sock->super.peername.addr, 0, sizeof(sock->super.peername.addr));
            sock->super.peername.len = 0;
        }
    }
    sock->uv.stream = stream;
    sock->uv.close_cb = close_cb;
    stream->data = sock;
    return &sock->super;
}

static void on_connect(uv_connect_t *conn, int status)
{
    struct st_h2o_uv_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_uv_socket_t, _creq, conn);
    h2o_socket_cb cb = sock->super._cb.write;
    sock->super._cb.write = NULL;
    cb(&sock->super, status);
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, int proto, h2o_socket_cb cb)
{
    struct st_h2o_uv_socket_t *sock;
    uv_tcp_t *tcp = h2o_malloc(sizeof(*tcp));

    // TODO: support unix domain socket with libuv
    if (addr->sa_family == AF_UNIX) {
        assert(!"unix domain socket is not supported when libuv is used");
    }

    if (uv_tcp_init(loop, tcp) != 0) {
        free(tcp);
        return NULL;
    }
    sock = (void*)h2o_uv_socket_create((void*)tcp, addr, addrlen, (void*)free);
    if (uv_tcp_connect(&sock->_creq, tcp, addr, on_connect) != 0) {
        h2o_socket_close(&sock->super);
        return NULL;
    }
    sock->super._cb.write = cb;
    return &sock->super;
}

static void on_timeout(uv_timer_t *timer)
{
    h2o_timeout_t *timeout = H2O_STRUCT_FROM_MEMBER(h2o_timeout_t, _backend.timer, timer);

    h2o_timeout_run(timeout, h2o_now(timer->loop));
    if (! h2o_linklist_is_empty(&timeout->_entries))
        schedule_timer(timeout);
}

void schedule_timer(h2o_timeout_t *timeout)
{
    h2o_timeout_entry_t *entry = H2O_STRUCT_FROM_MEMBER(h2o_timeout_entry_t, _link, timeout->_entries.next);
    uv_timer_start(&timeout->_backend.timer, on_timeout, entry->registered_at + timeout->timeout - h2o_now(timeout->_backend.timer.loop), 0);
}

void h2o_timeout__do_init(h2o_loop_t *loop, h2o_timeout_t *timeout)
{
    uv_timer_init(loop, &timeout->_backend.timer);
}

void h2o_timeout__do_dispose(h2o_loop_t *loop, h2o_timeout_t *timeout)
{
    uv_close((uv_handle_t*)&timeout->_backend.timer, NULL);
}

void h2o_timeout__do_link(h2o_loop_t *loop, h2o_timeout_t *timeout, h2o_timeout_entry_t *entry)
{
    /* register the timer if the entry just being added is the only entry */
    if (timeout->_entries.next == &entry->_link)
        schedule_timer(timeout);
}
