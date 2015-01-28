/*
 * Copyright (c) 2015 DeNA Co., Ltd.
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
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include "yrmcds.h"
#include "h2o/linklist.h"
#include "h2o/memory.h"
#include "h2o/memcached.h"
#include "h2o/serverutil.h"

struct st_client_thread_t {
    pthread_t tid;
    pthread_mutex_t mutex;
    h2o_linklist_t responses; /* link-list of h2o_memcached_request_t */
};

struct st_h2o_memcached_request_t {
    h2o_linklist_t link; /* linklist connected to pending_reqs or st_client_thread_t::responses */
    uint32_t serial;
    void (*cb)(h2o_memcached_response_t *response); /* may be NULL (may become NULL if discard_response is called) */
    struct st_client_thread_t *resp_thread;         /* thread to respond to (immutable) */
    h2o_memcached_response_t response;
};

struct st_h2o_memcached_conn_t {
    yrmcds yrmcds;
    pthread_mutex_t mutex;
    h2o_linklist_t pending_reqs;
    pthread_t receiver_thd;
};

static __thread struct st_client_thread_t *client_thd;

static h2o_memcached_request_t *create_request(size_t sz, h2o_memcached_response_cb cb, void *app_data)
{
    h2o_memcached_request_t *req = h2o_mem_alloc(sz);
    memset(req, 0, sz);

    if (cb != NULL) {
        if (client_thd == NULL) {
            client_thd = h2o_mem_alloc(sizeof(*client_thd));
            client_thd->tid = pthread_self();
            pthread_mutex_init(&client_thd->mutex, NULL);
            h2o_linklist_init_anchor(&client_thd->responses);
        }
        req->cb = cb;
        req->resp_thread = client_thd;
        req->response.app_data = app_data;
    }

    return req;
}

static void destroy_request(h2o_memcached_request_t *req)
{
    assert(!h2o_linklist_is_linked(&req->link));

    switch (req->response.cmd) {
    case YRMCDS_CMD_GET:
        free(req->response.data.get.base);
        req->response.data.get.base = NULL;
        break;
    case YRMCDS_CMD_SET:
    case YRMCDS_CMD_DELETE:
        break;
    default:
        assert(!"FIXME");
        break;
    }

    free(req);
}

static void link_pending_request(h2o_memcached_conn_t *conn, h2o_memcached_request_t *req)
{
    assert(!h2o_linklist_is_linked(&req->link));

    pthread_mutex_lock(&conn->mutex);
    h2o_linklist_insert(&conn->pending_reqs, &req->link);
    pthread_mutex_unlock(&conn->mutex);
}

static h2o_memcached_request_t *pop_pending_request(h2o_memcached_conn_t *conn, uint32_t serial)
{
    h2o_linklist_t *link;
    h2o_memcached_request_t *req;

    pthread_mutex_lock(&conn->mutex);

    for (link = conn->pending_reqs.next; link != &conn->pending_reqs; link = link->next) {
        req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_request_t, link, link);
        if (req->serial == serial) {
            h2o_linklist_unlink(&req->link);
            goto Exit;
        }
    }
    /* not found */
    req = NULL;

Exit:
    pthread_mutex_unlock(&conn->mutex);
    return req;
}

static void link_response(h2o_memcached_request_t *req)
{
    int need_notify;

    assert(!h2o_linklist_is_linked(&req->link));

    pthread_mutex_lock(&req->resp_thread->mutex);
    need_notify = h2o_linklist_is_empty(&req->resp_thread->responses);
    h2o_linklist_insert(&req->resp_thread->responses, &req->link);
    if (need_notify)
        h2o_thread_notify(req->resp_thread->tid);
    pthread_mutex_unlock(&req->resp_thread->mutex);
}

static void *run_loop(void *_conn)
{
    h2o_memcached_conn_t *conn = _conn;
    yrmcds_response resp;
    yrmcds_error err;

    while (1) {
        /* handle response */
        while ((err = yrmcds_recv(&conn->yrmcds, &resp)) == YRMCDS_OK) {
            h2o_memcached_request_t *req = pop_pending_request(conn, resp.serial);
            if (req == NULL) {
                fprintf(stderr, "[memcached] received unknown serial\n");
                goto Error;
            }
            if (req->resp_thread != NULL) {
                req->response.err = YRMCDS_OK;
                req->response.status = resp.status;
                req->response.cmd = resp.command;
                switch (resp.command) {
                case YRMCDS_CMD_GET:
                    if (resp.status == YRMCDS_STATUS_OK) {
                        req->response.data.get = (h2o_iovec_t){h2o_mem_alloc(resp.data_len), resp.data_len};
                        memcpy(req->response.data.get.base, resp.data, resp.data_len);
                    }
                    break;
                case YRMCDS_CMD_SET:
                case YRMCDS_CMD_DELETE:
                    break;
                default:
                    fprintf(stderr, "[memcached] received response to unknown command: %u\n", resp.command);
                    goto Error;
                }
                link_response(req);
            } else {
                destroy_request(req);
            }
        }
        /* report the error */
        h2o_memcached_print_error(err);
    Error:
        /* reconnect */
        assert(!"reconnect");
    }

    return NULL;
}

h2o_memcached_conn_t *h2o_memcached_open(const char *host, uint16_t port)
{
    h2o_memcached_conn_t *conn = h2o_mem_alloc(sizeof(*conn));
    yrmcds_error err;

    pthread_mutex_init(&conn->mutex, NULL);
    h2o_linklist_init_anchor(&conn->pending_reqs);

    if ((err = yrmcds_connect(&conn->yrmcds, host, port)) != YRMCDS_OK) {
        h2o_memcached_print_error(err);
        goto Error;
    }
    if (pthread_create(&conn->receiver_thd, NULL, run_loop, conn) != 0) {
        perror("[memcached] failed to start the receiver thread");
        goto Error;
    }
    return conn;

Error:
    if (err != YRMCDS_OK)
        yrmcds_close(&conn->yrmcds);
    pthread_mutex_destroy(&conn->mutex);
    return NULL;
}

void h2o_memcached_dispatch_response(void)
{
    h2o_linklist_t responses;

    assert(client_thd != NULL);

    /* grab the requests */
    h2o_linklist_init_anchor(&responses);
    pthread_mutex_lock(&client_thd->mutex);
    h2o_linklist_insert_list(&responses, &client_thd->responses);
    pthread_mutex_unlock(&client_thd->mutex);

    /* dispatch */
    while (!h2o_linklist_is_empty(&responses)) {
        h2o_memcached_request_t *req = H2O_STRUCT_FROM_MEMBER(h2o_memcached_request_t, link, responses.next);
        h2o_linklist_unlink(&req->link);
        if (req->cb != NULL)
            req->cb(&req->response);
        destroy_request(req);
    }
}

h2o_memcached_request_t *h2o_memcached_get(h2o_memcached_conn_t *conn, const char *key, size_t keylen, h2o_memcached_response_cb cb,
                                           void *app_data)
{
    h2o_memcached_request_t *req = (void *)create_request(sizeof(*req), cb, app_data);

    assert(cb != NULL);

    if ((req->response.err = yrmcds_get(&conn->yrmcds, key, keylen, 0, &req->serial)) != YRMCDS_OK) {
        link_response(req);
        goto Exit;
    }

    link_pending_request(conn, req);

Exit:
    return req;
}

h2o_memcached_request_t *h2o_memcached_set(h2o_memcached_conn_t *conn, const char *key, size_t keylen, const char *data,
                                           size_t datalen, uint32_t expires, h2o_memcached_response_cb cb, void *app_data)
{
    h2o_memcached_request_t *req = (void *)create_request(sizeof(*req), cb, app_data);

    /* TODO use setq in case cb == NULL? */
    if ((req->response.err = yrmcds_set(&conn->yrmcds, key, keylen, data, datalen, 0, expires, 0, 0, &req->serial)) != YRMCDS_OK) {
        if (cb != NULL)
            link_response(req);
        goto Exit;
    }

    link_pending_request(conn, req);

Exit:
    return cb != NULL ? req : NULL;
}

h2o_memcached_request_t *h2o_memcached_remove(h2o_memcached_conn_t *conn, const char *key, size_t keylen,
                                              h2o_memcached_response_cb cb, void *app_data)
{
    h2o_memcached_request_t *req = (void *)create_request(sizeof(*req), cb, app_data);

    /* TODO use removeq in case cb == NULL? */
    if ((req->response.err = yrmcds_remove(&conn->yrmcds, key, keylen, 0, &req->serial)) != YRMCDS_OK) {
        if (cb != NULL)
            link_response(req);
        goto Exit;
    }

    link_pending_request(conn, req);

Exit:
    return cb != NULL ? req : NULL;
}

void h2o_memcached_discard_response(h2o_memcached_request_t *req)
{
    assert(req->resp_thread != NULL);
    req->cb = NULL;
}

void h2o_memcached_print_error(yrmcds_error err)
{
    if (err == YRMCDS_SYSTEM_ERROR) {
        perror("[memcached] libyrmcds: system error");
    } else {
        fprintf(stderr, "[memcached] libyrmcds: %s\n", yrmcds_strerror(err));
    }
}
