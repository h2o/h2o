/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__hostinfo_h
#define h2o__hostinfo_h

#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o/multithread.h"

typedef struct st_h2o_hostinfo_getaddr_req_t h2o_hostinfo_getaddr_req_t;

typedef void (*h2o_hostinfo_getaddr_cb)(h2o_hostinfo_getaddr_req_t *req, const char *errstr, struct addrinfo *res);

struct st_h2o_hostinfo_getaddr_req_t {
    void *data;
    h2o_multithread_receiver_t *_receiver;
    h2o_hostinfo_getaddr_cb _cb;
    h2o_linklist_t _pending;
    union {
        struct {
            const char *name;
            const char *serv;
            struct addrinfo hints;
        } _in;
        struct {
            h2o_multithread_message_t message;
            const char *errstr;
            struct addrinfo *ai;
        } _out;
    };
};

/**
 * dispatches a (possibly) asynchronous hostname lookup
 */
static void h2o_hostinfo_getaddr(h2o_hostinfo_getaddr_req_t *req, void *data, h2o_multithread_receiver_t *receiver,
                                 const char *name, const char *serv, int family, int socktype, int protocol, int flags,
                                 h2o_hostinfo_getaddr_cb cb);
/**
 * 
 */
void h2o__hostinfo_getaddr_dispatch(h2o_hostinfo_getaddr_req_t *req);
/**
 * cancels the request
 */
void h2o_hostinfo_getaddr_cancel(h2o_hostinfo_getaddr_req_t *req);

/**
 * function that receives and dispatches the responses
 */
void h2o_hostinfo_getaddr_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages);

/* inline defs */

inline void h2o_hostinfo_getaddr(h2o_hostinfo_getaddr_req_t *req, void *data, h2o_multithread_receiver_t *receiver,
                                 const char *name, const char *serv, int family, int socktype, int protocol, int flags,
                                 h2o_hostinfo_getaddr_cb cb)
{
    req->data = data;
    req->_receiver = receiver;
    req->_cb = cb;
    memset(&req->_pending, 0, sizeof(req->_pending));
    req->_in.name = name;
    req->_in.serv = serv;
    memset(&req->_in.hints, 0, sizeof(req->_in.hints));
    req->_in.hints.ai_family = family;
    req->_in.hints.ai_socktype = socktype;
    req->_in.hints.ai_protocol = protocol;
    req->_in.hints.ai_flags = flags;

    h2o__hostinfo_getaddr_dispatch(req);
}

#endif
