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
#include "h2o/hostinfo.h"

struct st_h2o_hostinfo_getaddr_req_t {
    h2o_multithread_receiver_t *_receiver;
    h2o_hostinfo_getaddr_cb _cb;
    void *cbdata;
    h2o_linklist_t _pending;
    union {
        struct {
            char *name;
            char *serv;
            struct addrinfo hints;
        } _in;
        struct {
            h2o_multithread_message_t message;
            const char *errstr;
            struct addrinfo *ai;
        } _out;
    };
};

static struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    h2o_linklist_t pending; /* anchor of h2o_hostinfo_getaddr_req_t::_pending */
    size_t num_threads;
    size_t num_threads_idle;
} queue = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, {&queue.pending, &queue.pending}, 0, 0};

size_t h2o_hostinfo_max_threads = 1;

/* generic errors (https://tools.ietf.org/html/rfc8499#section-3) */
const char h2o_hostinfo_error_nxdomain[] = "hostname does not exist";
const char h2o_hostinfo_error_nodata[] = "no address associated with hostname";
const char h2o_hostinfo_error_refused[] = "non-recoverable failure in name resolution";
const char h2o_hostinfo_error_servfail[] = "temporary failure in name resolution";

/* errors specfic to getaddrinfo */
const char h2o_hostinfo_error_gai_addrfamily[] = "address family for hostname not supported";
const char h2o_hostinfo_error_gai_badflags[] = "bad value for ai_flags";
const char h2o_hostinfo_error_gai_family[] = "ai_family not supported";
const char h2o_hostinfo_error_gai_memory[] = "memory allocation failure";
const char h2o_hostinfo_error_gai_service[] = "servname not supported for ai_socktype";
const char h2o_hostinfo_error_gai_socktype[] = "ai_socktype not supported";
const char h2o_hostinfo_error_gai_system[] = "system error";
const char h2o_hostinfo_error_gai_other[] = "name resolution failed";

static void create_lookup_thread_if_necessary(void);

static const char *hostinfo_error_from_gai_error(int ret)
{
    switch (ret) {
    case EAI_NONAME:
        return h2o_hostinfo_error_nxdomain;
#ifdef EAI_NODATA /* obsoleted in RFC 3493 and not supported by FreeBSD */
    case EAI_NODATA:
        return h2o_hostinfo_error_nodata;
#endif
    case EAI_FAIL:
        return h2o_hostinfo_error_refused;
    case EAI_AGAIN:
        return h2o_hostinfo_error_servfail;
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
        return h2o_hostinfo_error_gai_addrfamily;
#endif
    case EAI_BADFLAGS:
        return h2o_hostinfo_error_gai_badflags;
    case EAI_FAMILY:
        return h2o_hostinfo_error_gai_family;
    case EAI_MEMORY:
        return h2o_hostinfo_error_gai_memory;
    case EAI_SERVICE:
        return h2o_hostinfo_error_gai_service;
    case EAI_SOCKTYPE:
        return h2o_hostinfo_error_gai_socktype;
    case EAI_SYSTEM:
        return h2o_hostinfo_error_gai_system;
    default:
        return h2o_hostinfo_error_gai_other;
    }
}

static void lookup_and_respond(h2o_hostinfo_getaddr_req_t *req)
{
    struct addrinfo *res;

    int ret = getaddrinfo(req->_in.name, req->_in.serv, &req->_in.hints, &res);
    req->_out.message = (h2o_multithread_message_t){{NULL}};
    if (ret != 0) {
        req->_out.errstr = hostinfo_error_from_gai_error(ret);
        req->_out.ai = NULL;
    } else {
        req->_out.errstr = NULL;
        req->_out.ai = res;
    }

    h2o_multithread_send_message(req->_receiver, &req->_out.message);
}

static void *lookup_thread_main(void *_unused)
{
    pthread_mutex_lock(&queue.mutex);

    while (1) {
        --queue.num_threads_idle;
        while (!h2o_linklist_is_empty(&queue.pending)) {
            h2o_hostinfo_getaddr_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_hostinfo_getaddr_req_t, _pending, queue.pending.next);
            h2o_linklist_unlink(&req->_pending);
            create_lookup_thread_if_necessary();
            pthread_mutex_unlock(&queue.mutex);
            lookup_and_respond(req);
            pthread_mutex_lock(&queue.mutex);
        }
        ++queue.num_threads_idle;
        pthread_cond_wait(&queue.cond, &queue.mutex);
    }

    h2o_fatal("unreachable");
    return NULL;
}

static void create_lookup_thread_if_necessary(void)
{
    /* do nothing if there's no need to, or if we are already at the maximum. */
    if (queue.num_threads_idle != 0 || h2o_linklist_is_empty(&queue.pending))
        return;
    if (queue.num_threads == h2o_hostinfo_max_threads)
        return;

    pthread_t tid;
    pthread_attr_t attr;
    int ret;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if ((ret = pthread_create(&tid, &attr, lookup_thread_main, NULL)) != 0) {
        char buf[128];
        if (queue.num_threads == 0) {
            h2o_fatal("failed to start first thread for getaddrinfo: %s", h2o_strerror_r(ret, buf, sizeof(buf)));
        } else {
            h2o_error_printf("pthread_create(for getaddrinfo): %s", h2o_strerror_r(ret, buf, sizeof(buf)));
        }
        return;
    }
    pthread_attr_destroy(&attr);

    ++queue.num_threads;
    ++queue.num_threads_idle;
}

static void dispatch_hostinfo_getaddr(h2o_hostinfo_getaddr_req_t *req)
{
    pthread_mutex_lock(&queue.mutex);

    h2o_linklist_insert(&queue.pending, &req->_pending);

    create_lookup_thread_if_necessary();

    pthread_cond_signal(&queue.cond);
    pthread_mutex_unlock(&queue.mutex);
}

h2o_hostinfo_getaddr_req_t *h2o_hostinfo_getaddr(h2o_multithread_receiver_t *receiver, h2o_iovec_t name, h2o_iovec_t serv,
                                                 int family, int socktype, int protocol, int flags, h2o_hostinfo_getaddr_cb cb,
                                                 void *cbdata)
{
    h2o_hostinfo_getaddr_req_t *req = h2o_mem_alloc(sizeof(*req) + name.len + 1 + serv.len + 1);
    req->_receiver = receiver;
    req->_cb = cb;
    req->cbdata = cbdata;
    req->_pending = (h2o_linklist_t){NULL};
    req->_in.name = (char *)req + sizeof(*req);
    memcpy(req->_in.name, name.base, name.len);
    req->_in.name[name.len] = '\0';
    req->_in.serv = req->_in.name + name.len + 1;
    memcpy(req->_in.serv, serv.base, serv.len);
    req->_in.serv[serv.len] = '\0';
    memset(&req->_in.hints, 0, sizeof(req->_in.hints));
    req->_in.hints.ai_family = family;
    req->_in.hints.ai_socktype = socktype;
    req->_in.hints.ai_protocol = protocol;
    req->_in.hints.ai_flags = flags;

    dispatch_hostinfo_getaddr(req);

    return req;
}

void h2o_hostinfo_getaddr_cancel(h2o_hostinfo_getaddr_req_t *req)
{
    int should_free = 0;

    pthread_mutex_lock(&queue.mutex);

    if (h2o_linklist_is_linked(&req->_pending)) {
        h2o_linklist_unlink(&req->_pending);
        should_free = 1;
    } else {
        req->_cb = NULL;
    }

    pthread_mutex_unlock(&queue.mutex);

    if (should_free)
        free(req);
}

void h2o_hostinfo_getaddr_receiver(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    while (!h2o_linklist_is_empty(messages)) {
        h2o_hostinfo_getaddr_req_t *req = H2O_STRUCT_FROM_MEMBER(h2o_hostinfo_getaddr_req_t, _out.message.link, messages->next);
        h2o_linklist_unlink(&req->_out.message.link);
        h2o_hostinfo_getaddr_cb cb = req->_cb;
        if (cb != NULL) {
            req->_cb = NULL;
            cb(req, req->_out.errstr, req->_out.ai, req->cbdata);
        }
        if (req->_out.ai != NULL)
            freeaddrinfo(req->_out.ai);
        free(req);
    }
}

static const char *fetch_aton_digit(const char *p, const char *end, unsigned char *value)
{
    size_t ndigits = 0;
    int v = 0;

    while (p != end && ('0' <= *p && *p <= '9')) {
        v = v * 10 + *p++ - '0';
        ++ndigits;
    }
    if (!(1 <= ndigits && ndigits <= 3))
        return NULL;
    if (v > 255)
        return NULL;
    *value = (unsigned char)v;
    return p;
}

int h2o_hostinfo_aton(h2o_iovec_t host, struct in_addr *addr)
{
    union {
        int32_t n;
        unsigned char c[4];
    } value;
    const char *p = host.base, *end = p + host.len;
    size_t ndots = 0;

    while (1) {
        if ((p = fetch_aton_digit(p, end, value.c + ndots)) == NULL)
            return -1;
        if (ndots == 3)
            break;
        if (p == end || !(*p == '.'))
            return -1;
        ++p;
        ++ndots;
    }
    if (p != end)
        return -1;

    addr->s_addr = value.n;
    return 0;
}
