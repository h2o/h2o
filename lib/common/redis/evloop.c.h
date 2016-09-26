/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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


typedef struct redisEvloopEvents {
    redisAsyncContext* context;
    h2o_socket_t       *socket;
} redisEvloopEvents;


static void on_read(h2o_socket_t* sock, const char *err)
{
    redisEvloopEvents* p = (redisEvloopEvents*)sock->data;
    redisAsyncHandleRead(p->context);
}

static void on_write(h2o_socket_t *sock, const char *err)
{
    redisEvloopEvents* p = (redisEvloopEvents*)sock->data;
    redisAsyncHandleWrite(p->context);
}

typedef void (*h2o_socket_cb)(h2o_socket_t *sock, const char *err);

static void redisEvloopAddRead(void *privdata) {
    redisEvloopEvents* p = (redisEvloopEvents*)privdata;
    h2o_socket_read_start(p->socket, on_read);
}


static void redisEvloopDelRead(void *privdata) {
    redisEvloopEvents* p = (redisEvloopEvents*)privdata;
    h2o_socket_read_stop(p->socket);
}


static void redisEvloopAddWrite(void *privdata) {
    redisEvloopEvents* p = (redisEvloopEvents*)privdata;
    if (! h2o_socket_is_writing(p->socket)) {
        h2o_socket_notify_write(p->socket, on_write);
    }
}

static void redisEvloopCleanup(void *privdata) {
    redisEvloopEvents* p = (redisEvloopEvents*)privdata;
    h2o_socket_close(p->socket);
    p->context->c.fd = -1; /* prevent hiredis from closing fd twice */
    free(p);
}


static int redisEvloopAttach(redisAsyncContext* ac, h2o_evloop_t* loop) {
    redisContext *c = &(ac->c);

    if (ac->ev.data != NULL) {
        return REDIS_ERR;
    }

    ac->ev.addRead  = redisEvloopAddRead;
    ac->ev.delRead  = redisEvloopDelRead;
    ac->ev.addWrite = redisEvloopAddWrite;
    ac->ev.cleanup  = redisEvloopCleanup;

    redisEvloopEvents* p = (redisEvloopEvents*)malloc(sizeof(*p));
    if (!p) {
        return REDIS_ERR;
    }
    memset(p, 0, sizeof(*p));

    ac->ev.data = p;
    p->socket = h2o_evloop_socket_create(loop, c->fd, H2O_SOCKET_FLAG_DONT_READ);
    p->socket->data = p;
    p->context = ac;

    return REDIS_OK;
}