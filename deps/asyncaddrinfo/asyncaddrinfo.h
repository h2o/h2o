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
#ifndef asyncaddrinfo_h
#define asyncaddrinfo_h

#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#if defined(__linux__)
#define ASYNCADDRINFO_IS_ASYNC 1
#if !defined(_GNU_SOURCE)
#error "you must have _GNU_SOURCE defined before including this file or netdb.h"
#endif
#else
#define ASYNCADDRINFO_IS_ASYNC 0
#endif

struct asyncaddrinfo_request_t;
typedef void (*asyncaddrinfo_cb)(struct asyncaddrinfo_request_t *req, const char *errstr, struct addrinfo *res);

/**
 * the request structure
 */
struct asyncaddrinfo_request_t {
    /**
     * pointer to user data, supplied as the 2nd argument to asyncaddrinfo
     */
    void *data;
    /**
     * the cancel callback; applications may call this callback to cancel a pending request
     */
    void (*cancel)(struct asyncaddrinfo_request_t *req);

#if ASYNCADDRINFO_IS_ASYNC
    struct {
        asyncaddrinfo_cb cb;
        struct gaicb *list[1];
        struct gaicb gaicb;
        struct addrinfo hints;
    } _linux;
#endif
};

#if ASYNCADDRINFO_IS_ASYNC

/**
 * should be defined by the user to indicate the signal number to be used for notification
 */
extern int asyncaddrinfo_linux_signo;

static void asyncaddrinfo__linux_cancel(struct asyncaddrinfo_request_t *req)
{
    if (gai_cancel(&req->_linux.gaicb) == 0) {
        free(req);
    } else {
        req->_linux.cb = NULL;
    }
}

static void asyncaddrinfo__linux(struct asyncaddrinfo_request_t **_req, void *data, const char *node, const char *service,
                                 int socktype, int protocol, int flags, asyncaddrinfo_cb cb)
{
    struct asyncaddrinfo_request_t *req = malloc(sizeof(*req));
    if (req == NULL) {
        struct asyncaddrinfo_request_t fakereq = {data};
        cb(&fakereq, "no memory", NULL);
        return;
    }

    *req = (struct asyncaddrinfo_request_t){data, asyncaddrinfo__linux_cancel, {cb, {&req->_linux.gaicb}}};
    req->_linux.gaicb.ar_name = node;
    req->_linux.gaicb.ar_service = service;
    req->_linux.hints.ai_socktype = socktype;
    req->_linux.hints.ai_protocol = protocol;
    req->_linux.hints.ai_flags = flags;

    struct sigevent sev = {};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = asyncaddrinfo_linux_signo;
    sev.sigev_value.sival_ptr = req;

    *_req = req;

    int ret;
    while ((ret = getaddrinfo_a(GAI_NOWAIT, req->_linux.list, 1, &sev)) == EAI_AGAIN)
        ;
    if (ret != 0) {
        cb(req, gai_strerror(ret), NULL);
        free(req);
        return;
    }
}

/**
 * (linux only) handles the SI_ASYNCNL signal and dispatches the asyncaddrinfo callbacks
 *
 * @param return whether if the signal has been handled
 */
static int asyncaddrinfo_linux_handle_signal(int sicode, void *siptr)
{
    if (sicode != SI_ASYNCNL)
        return 0;

    struct asyncaddrinfo_request_t *req = siptr;
    const char *errstr = NULL;
    int ret;

    if ((ret = gai_error(&req->_linux.gaicb)) != 0) {
        if (ret == EAI_INPROGRESS)
            return 0;
        errstr = gai_strerror(ret);
    }
    if (req->_linux.cb != NULL) {
        req->_linux.cb(req, errstr, req->_linux.gaicb.ar_result);
    } else {
        freeaddrinfo(req->_linux.gaicb.ar_result);
    }
    free(req);

    return 1;
}

#endif

/**
 * calls getaddrinfo(3) asynchronously if possible, depending on the platform.
 *
 * @param _req pointer to pointer where the address of the request object should be written
 * @param data user data
 * @param node 1st arg of getaddrinfo
 * @param service 2nd arg of getaddrinfo
 * @param cb callback to be called when the request has been handled
 * @note buffer pointed to by `node` and `service` must be maintained by the caller while the request is in action
 */
static void asyncaddrinfo(struct asyncaddrinfo_request_t **_req, void *data, const char *node, const char *service, int socktype,
                          int protocol, int flags, asyncaddrinfo_cb cb)
{
#if ASYNCADDRINFO_IS_ASYNC
    asyncaddrinfo__linux(_req, data, node, service, socktype, protocol, flags, cb);
#else
    /* the synchronous implementation */
    struct addrinfo hints = {}, *res;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    hints.ai_flags = flags;
    int ret = getaddrinfo(node, service, &hints, &res);

    struct asyncaddrinfo_request_t req = {data};
    *_req = &req;
    cb(&req, ret != 0 ? gai_strerror(ret) : NULL, res);
#endif
}

#endif
