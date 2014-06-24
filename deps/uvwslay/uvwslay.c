#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <nettle/base64.h>
#include <nettle/sha.h>
#include "uvwslay.h"

static void on_close(uvwslay_t *self)
{
    (*self->msg_cb)(self, NULL);
}

static uv_buf_t on_recv_alloc(uv_handle_t *handle, size_t suggested_size)
{
    uvwslay_t *self = handle->data;
    uv_buf_t ret;

    if (self->rbuf_start != 0 && self->rbuf_end != 0) {
        memmove(self->rbuf, self->rbuf + self->rbuf_start, self->rbuf_end - self->rbuf_start);
        self->rbuf_end -= self->rbuf_start;
        self->rbuf_start = 0;
    }

    assert(self->rbuf_end <= sizeof(self->rbuf));
    ret.base = self->rbuf + self->rbuf_end;
    ret.len = sizeof(self->rbuf) - self->rbuf_end;
    return ret;
}

static void on_recv_complete(uv_stream_t *stream, ssize_t nread, uv_buf_t _buf)
{
    uvwslay_t *self = stream->data;

    if (nread == -1) {
        /* error */
        on_close(self);
        return;
    }
    self->rbuf_end += nread;

    uvwslay_proceed(self);
}

static void on_send_complete(uv_write_t *_self, int status)
{
    uvwslay_t *self = (void*)_self;

    if (status != 0) {
        on_close(self);
        return;
    }

    free(self->wbuf.base);
    self->wbuf.base = NULL;
    uvwslay_proceed(self);
}

static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *_self)
{
    uvwslay_t *self = _self;
    size_t rbufsz;

    /* return WOULDBLOCK if no data */
    if (self->rbuf_end == 0) {
        wslay_event_set_error(self->ws_ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }

    rbufsz = self->rbuf_end - self->rbuf_start;
    if (rbufsz < len) {
        len = rbufsz;
    }
    memcpy(buf, self->rbuf + self->rbuf_start, len);
    if ((self->rbuf_start += len) == self->rbuf_end) {
        self->rbuf_start = self->rbuf_end = 0;
    }

    return len;
}

static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *_self)
{
    uvwslay_t *self = _self;

    /* return WOULDBLOCK if pending (TODO: queue fixed number of chunks, instead of only one) */
    if (self->wbuf.base != NULL) {
        wslay_event_set_error(self->ws_ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }

    /* copy data */
    if ((self->wbuf.base = malloc(len)) == NULL) {
        wslay_event_set_error(self->ws_ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }
    memcpy(self->wbuf.base, data, len);
    self->wbuf.len = len;

    /* send */
    uv_write(&self->wreq, self->stream, &self->wbuf, 1, on_send_complete);

    return len;
}

static void on_msg_callback(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *_self)
{
    uvwslay_t *self = _self;
    (*self->msg_cb)(self, arg);
}

uvwslay_t *uvwslay_new(uv_stream_t *stream, void *user_data, uvwslay_msg_callback msg_cb)
{
    uvwslay_t *self;

    if ((self = malloc(sizeof(uvwslay_t))) == NULL) {
        return NULL;
    }
    memset(self, 0, sizeof(*self));
    self->stream = stream;
    self->ws_callbacks.recv_callback = recv_callback;
    self->ws_callbacks.send_callback = send_callback;
    self->ws_callbacks.on_msg_recv_callback = on_msg_callback;
    self->user_data = user_data;
    self->msg_cb = msg_cb;
    stream->data = self;
    wslay_event_context_server_init(&self->ws_ctx, &self->ws_callbacks, self);
    return self;
}

void uvwslay_free(uvwslay_t *self)
{
    if (self->wbuf.base != NULL) {
        free(self->wbuf.base);
        self->wbuf.base = NULL;
    }
    wslay_event_context_free(self->ws_ctx);
    free(self);
}

void uvwslay_proceed(uvwslay_t *self)
{
    int handled;

    /* run the loop until getting to a point where no more progress can be achieved */
    do {
        handled = 0;
        if (self->wbuf.base == NULL && wslay_event_want_write(self->ws_ctx)) {
            if (wslay_event_send(self->ws_ctx) != 0) {
                goto Close;
            }
            handled = 1;
        }
        if (self->rbuf_end != 0 && wslay_event_want_read(self->ws_ctx)) {
            if (wslay_event_recv(self->ws_ctx) != 0) {
                goto Close;
            }
            handled = 1;
        }
    } while (handled);

    if (wslay_event_want_read(self->ws_ctx)) {
        /* start the reader if wslay wants to read */
        assert(self->rbuf_end == 0);
        uv_read_start(self->stream, on_recv_alloc, on_recv_complete);
    } else if (self->wbuf.base != NULL || wslay_event_want_write(self->ws_ctx)) {
        /* just stop the write stream if writing something */
        uv_read_stop(self->stream);
    } else {
        /* close the socket */
        goto Close;
    }

    return;

Close:
    on_close(self);
}

/* ----------------- STARTS HERE ------------------
 *
 * copied from wslay/examples/fork-echoserv.c under the following license
 *
 * Wslay - The WebSocket Library
 *
 * Copyright (c) 2011, 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/*
 * Calculates SHA-1 hash of *src*. The size of *src* is *src_length* bytes.
 * *dst* must be at least SHA1_DIGEST_SIZE.
 */
static void sha1(uint8_t *dst, const uint8_t *src, size_t src_length)
{
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (unsigned)src_length, src);
    sha1_digest(&ctx, SHA1_DIGEST_SIZE, dst);
}

/*
 * Base64-encode *src* and stores it in *dst*.
 * The size of *src* is *src_length*.
 * *dst* must be at least BASE64_ENCODE_RAW_LENGTH(src_length).
 */
static void base64(uint8_t *dst, const uint8_t *src, size_t src_length)
{
    struct base64_encode_ctx ctx;
    base64_encode_init(&ctx);
    base64_encode_raw(dst, (unsigned)src_length, src);
}

/*
 * Create Server's accept key in *dst*.
 * *client_key* is the value of |Sec-WebSocket-Key| header field in
 * client's handshake and it must be length of 24.
 * *dst* must be at least BASE64_ENCODE_RAW_LENGTH(20)+1.
 */
void uvwslay_create_accept_key(char *dst, const char *client_key)
{
    uint8_t sha1buf[20], key_src[60];
    memcpy(key_src, client_key, 24);
    memcpy(key_src+24, WS_GUID, 36);
    sha1(sha1buf, key_src, sizeof(key_src));
    base64((uint8_t*)dst, sha1buf, 20);
    dst[BASE64_ENCODE_RAW_LENGTH(20)] = '\0';
}
