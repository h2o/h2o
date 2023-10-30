/*
 * Copyright (c) 2015 Kazuho Oku, DeNA Co., Ltd.
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
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#if defined(__linux__)
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <sys/ptrace.h>
#elif defined(__FreeBSD__)
#include <sys/procctl.h>
#elif defined(__sun)
#include <priv.h>
#endif

/* to maximize code-reuse between different stacks, we intentionally use API declared by OpenSSL as legacy */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

#if defined(LIBRESSL_VERSION_NUMBER) ? LIBRESSL_VERSION_NUMBER >= 0x3050000fL : OPENSSL_VERSION_NUMBER >= 0x1010000fL
/* RSA_METHOD is opaque, so RSA_meth* are used. */
#define NEVERBLEED_OPAQUE_RSA_METHOD
#endif

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined(OPENSSL_NO_EC) &&                                                            \
    (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER >= 0x2090100fL)
/* EC_KEY_METHOD and related APIs are avaliable, so ECDSA is enabled. */
#define NEVERBLEED_ECDSA
#endif

#include <openssl/bn.h>
#ifdef NEVERBLEED_ECDSA
#include <openssl/ec.h>
#endif
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#ifdef __linux
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL)
#define USE_OFFLOAD 1
#endif
#if defined(OPENSSL_IS_BORINGSSL) && defined(NEVERBLEED_BORINGSSL_USE_QAT)
#include "qat_bssl.h"
/* the mapping seems to be missing */
#ifndef ASYNC_WAIT_CTX_get_all_fds
extern int bssl_async_wait_ctx_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd, size_t *numfds);
#define ASYNC_WAIT_CTX_get_all_fds bssl_async_wait_ctx_get_all_fds
#endif
#define USE_OFFLOAD 1
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x1010000fL || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)

static void RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n) {
        *n = rsa->n;
    }

    if (e) {
        *e = rsa->e;
    }

    if (d) {
        *d = rsa->d;
    }
}

static int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if (n == NULL || e == NULL) {
        return 0;
    }

    BN_free(rsa->n);
    BN_free(rsa->e);
    BN_free(rsa->d);
    rsa->n = n;
    rsa->e = e;
    rsa->d = d;

    return 1;
}

static void RSA_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}

#define EVP_PKEY_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_EVP_PKEY)

#endif

#include "neverbleed.h"

enum neverbleed_type { NEVERBLEED_TYPE_ERROR, NEVERBLEED_TYPE_RSA, NEVERBLEED_TYPE_ECDSA };

struct st_neverbleed_rsa_exdata_t {
    neverbleed_t *nb;
    size_t key_index;
};

struct st_neverbleed_thread_data_t {
    pid_t self_pid;
    int fd;
};

/**
 * a variant of pthread_once, that does not require you to declare a callback, nor have a global variable
 */
#define NEVERBLEED_MULTITHREAD_ONCE(block)                                                                                                \
    do {                                                                                                                           \
        static volatile int lock = 0;                                                                                              \
        int lock_loaded = lock;                                                                                                    \
        __sync_synchronize();                                                                                                      \
        if (!lock_loaded) {                                                                                                        \
            static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;                                                              \
            pthread_mutex_lock(&mutex);                                                                                            \
            if (!lock) {                                                                                                           \
                do {                                                                                                               \
                    block                                                                                                          \
                } while (0);                                                                                                       \
                __sync_synchronize();                                                                                              \
                lock = 1;                                                                                                          \
            }                                                                                                                      \
            pthread_mutex_unlock(&mutex);                                                                                          \
        }                                                                                                                          \
    } while (0)

static void warnvf(const char *fmt, va_list args)
{
    char errbuf[256];

    if (errno != 0) {
        strerror_r(errno, errbuf, sizeof(errbuf));
    } else {
        errbuf[0] = '\0';
    }

    fprintf(stderr, "[openssl-privsep] ");
    vfprintf(stderr, fmt, args);
    if (errbuf[0] != '\0')
        fputs(errbuf, stderr);
    fputc('\n', stderr);
}

__attribute__((format(printf, 1, 2))) static void warnf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    warnvf(fmt, args);
    va_end(args);
}

__attribute__((format(printf, 1, 2), noreturn)) static void dief(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    warnvf(fmt, args);
    va_end(args);

    abort();
}

static char *dirname(const char *path)
{
    const char *last_slash = strrchr(path, '/');
    char *ret;

    if (last_slash == NULL) {
        errno = 0;
        dief("dirname: no slash in given path:%s", path);
    }
    if ((ret = malloc(last_slash + 1 - path)) == NULL)
        dief("no memory");
    memcpy(ret, path, last_slash - path);
    ret[last_slash - path] = '\0';
    return ret;
}

static void set_cloexec(int fd)
{
    if (fcntl(fd, F_SETFD, O_CLOEXEC) == -1)
        dief("failed to set O_CLOEXEC to fd %d", fd);
}

static int read_nbytes(int fd, void *p, size_t sz)
{
    while (sz != 0) {
        ssize_t r;
        while ((r = read(fd, p, sz)) == -1 && errno == EINTR)
            ;
        if (r == -1) {
            return -1;
        } else if (r == 0) {
            errno = 0;
            return -1;
        }
        p = (char *)p + r;
        sz -= r;
    }
    return 0;
}

/**
 * This function disposes of the memory allocated for `neverbleed_iobuf_t`, but retains the value of `next` and `processing` so that
 * the buffer can be "cleared" while in use by worker threads.
 */
static void iobuf_dispose(neverbleed_iobuf_t *buf)
{
    if (buf->capacity != 0)
        OPENSSL_cleanse(buf->buf, buf->capacity);
    free(buf->buf);
    buf->buf = NULL;
    buf->start = NULL;
    buf->end = NULL;
    buf->capacity = 0;
}

static void iobuf_reserve(neverbleed_iobuf_t *buf, size_t extra)
{
    size_t start_off, end_off;

    if (extra <= buf->buf - buf->end + buf->capacity)
        return;

    if (buf->capacity == 0)
        buf->capacity = 4096;
    while (buf->buf - buf->end + buf->capacity < extra)
        buf->capacity *= 2;

    if (buf->buf != NULL) {
        start_off = buf->start - buf->buf;
        end_off = buf->end - buf->buf;
    } else {
        /* C99 forbids us doing `buf->start - buf->buf` when both are NULL (undefined behavior) */
        start_off = 0;
        end_off = 0;
    }

    if ((buf->buf = realloc(buf->buf, buf->capacity)) == NULL)
        dief("realloc failed");
    buf->start = buf->buf + start_off;
    buf->end = buf->buf + end_off;
}

static void iobuf_push_num(neverbleed_iobuf_t *buf, size_t v)
{
    iobuf_reserve(buf, sizeof(v));
    memcpy(buf->end, &v, sizeof(v));
    buf->end += sizeof(v);
}

static void iobuf_push_str(neverbleed_iobuf_t *buf, const char *s)
{
    size_t l = strlen(s) + 1;
    iobuf_reserve(buf, l);
    memcpy(buf->end, s, l);
    buf->end += l;
}

static void iobuf_push_bytes(neverbleed_iobuf_t *buf, const void *p, size_t l)
{
    iobuf_push_num(buf, l);
    iobuf_reserve(buf, l);
    memcpy(buf->end, p, l);
    buf->end += l;
}

static int iobuf_shift_num(neverbleed_iobuf_t *buf, size_t *v)
{
    if (neverbleed_iobuf_size(buf) < sizeof(*v))
        return -1;
    memcpy(v, buf->start, sizeof(*v));
    buf->start += sizeof(*v);
    return 0;
}

static char *iobuf_shift_str(neverbleed_iobuf_t *buf)
{
    char *nul = memchr(buf->start, '\0', neverbleed_iobuf_size(buf)), *ret;
    if (nul == NULL)
        return NULL;
    ret = buf->start;
    buf->start = nul + 1;
    return ret;
}

static void *iobuf_shift_bytes(neverbleed_iobuf_t *buf, size_t *l)
{
    void *ret;
    if (iobuf_shift_num(buf, l) != 0)
        return NULL;
    if (neverbleed_iobuf_size(buf) < *l)
        return NULL;
    ret = buf->start;
    buf->start += *l;
    return ret;
}

static int iobuf_write(neverbleed_iobuf_t *buf, int fd)
{
    struct iovec vecs[2] = {{NULL}};
    size_t bufsz = neverbleed_iobuf_size(buf);
    int vecindex;
    ssize_t r;

    vecs[0].iov_base = &bufsz;
    vecs[0].iov_len = sizeof(bufsz);
    vecs[1].iov_base = buf->start;
    vecs[1].iov_len = bufsz;

    for (vecindex = 0; vecindex != sizeof(vecs) / sizeof(vecs[0]);) {
        while ((r = writev(fd, vecs + vecindex, sizeof(vecs) / sizeof(vecs[0]) - vecindex)) == -1 && errno == EINTR)
            ;
        if (r == -1)
            return -1;
        assert(r != 0);
        while (r != 0 && r >= vecs[vecindex].iov_len) {
            r -= vecs[vecindex].iov_len;
            ++vecindex;
        }
        if (r != 0) {
            vecs[vecindex].iov_base = (char *)vecs[vecindex].iov_base + r;
            vecs[vecindex].iov_len -= r;
        }
    }

    return 0;
}

static int iobuf_read(neverbleed_iobuf_t *buf, int fd)
{
    size_t sz;
    if (read_nbytes(fd, &sz, sizeof(sz)) != 0)
        return -1;
    iobuf_reserve(buf, sz);
    if (read_nbytes(fd, buf->end, sz) != 0)
        return -1;
    buf->end += sz;
    return 0;
}

void neverbleed_iobuf_dispose(neverbleed_iobuf_t *buf)
{
    iobuf_dispose(buf);
}

static int do_iobuf_transaction_write(neverbleed_iobuf_t *buf, struct st_neverbleed_thread_data_t *thdata) {
    return iobuf_write(buf, thdata->fd);
}

static void iobuf_transaction_write(neverbleed_iobuf_t *buf, struct st_neverbleed_thread_data_t *thdata)
{
    if (do_iobuf_transaction_write(buf, thdata) == -1) {
        if (errno != 0) {
            dief("write error (%d) %s", errno, strerror(errno));
        } else {
            dief("connection closed by daemon");
        }
    }
}

static int do_iobuf_transaction_read(neverbleed_iobuf_t *buf, struct st_neverbleed_thread_data_t *thdata)
{
    iobuf_dispose(buf);
    return iobuf_read(buf, thdata->fd);
}

static void iobuf_transaction_read(neverbleed_iobuf_t *buf, struct st_neverbleed_thread_data_t *thdata)
{
    if (do_iobuf_transaction_read(buf, thdata) == -1) {
        if (errno != 0) {
            dief("read error (%d) %s", errno, strerror(errno));
        } else {
            dief("connection closed by daemon");
        }
    }
}

/**
 * Only sends a request, does not read a response
 */
static void iobuf_transaction_no_response(neverbleed_iobuf_t *buf, struct st_neverbleed_thread_data_t *thdata)
{
    if (neverbleed_transaction_cb != NULL) {
        neverbleed_transaction_cb(buf, 1);
    } else {
        iobuf_transaction_write(buf, thdata);
        iobuf_dispose(buf);
    }
}

/**
 * Sends a request and reads a response.
 */
static void iobuf_transaction(neverbleed_iobuf_t *buf, struct st_neverbleed_thread_data_t *thdata)
{
    if (neverbleed_transaction_cb != NULL) {
        neverbleed_transaction_cb(buf, 0);
    } else {
        iobuf_transaction_write(buf, thdata);
        iobuf_transaction_read(buf, thdata);
    }
}

#if !defined(NAME_MAX) || defined(__linux__)
/* readdir(3) is known to be thread-safe on Linux and should be thread-safe on a platform that does not have a predefined value for
   NAME_MAX */
#define FOREACH_DIRENT(dp, dent)                                                                                                   \
    struct dirent *dent;                                                                                                           \
    while ((dent = readdir(dp)) != NULL)
#else
#define FOREACH_DIRENT(dp, dent)                                                                                                   \
    struct {                                                                                                                       \
        struct dirent d;                                                                                                           \
        char s[NAME_MAX + 1];                                                                                                      \
    } dent_;                                                                                                                       \
    struct dirent *dentp, *dent = &dent_.d;                                                                                        \
    int ret;                                                                                                                       \
    while ((ret = readdir_r(dp, dent, &dentp)) == 0 && dentp != NULL)
#endif /* FOREACH_DIRENT */

static void unlink_dir(const char *path)
{
    DIR *dp;
    char buf[PATH_MAX];

    if ((dp = opendir(path)) != NULL) {
        FOREACH_DIRENT(dp, entp)
        {
            if (strcmp(entp->d_name, ".") == 0 || strcmp(entp->d_name, "..") == 0)
                continue;
            snprintf(buf, sizeof(buf), "%s/%s", path, entp->d_name);
            unlink_dir(buf);
        }
        closedir(dp);
    }
    unlink(path);
    rmdir(path);
}

static void dispose_thread_data(void *_thdata)
{
    struct st_neverbleed_thread_data_t *thdata = _thdata;

    assert(thdata->fd >= 0);
    close(thdata->fd);
    thdata->fd = -1;
    free(thdata);
}

static struct st_neverbleed_thread_data_t *get_thread_data(neverbleed_t *nb)
{
    struct st_neverbleed_thread_data_t *thdata;
    pid_t self_pid = getpid();
    ssize_t r;

    if ((thdata = pthread_getspecific(nb->thread_key)) != NULL) {
        if (thdata->self_pid == self_pid)
            return thdata;
        /* we have been forked! */
        close(thdata->fd);
    } else {
        if ((thdata = malloc(sizeof(*thdata))) == NULL)
            dief("malloc failed");
    }

    thdata->self_pid = self_pid;
#ifdef SOCK_CLOEXEC
    if ((thdata->fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
        dief("socket(2) failed");
#else
    if ((thdata->fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
        dief("socket(2) failed");
    set_cloexec(thdata->fd);
#endif
    while (connect(thdata->fd, (void *)&nb->sun_, sizeof(nb->sun_)) != 0)
        if (errno != EINTR)
            dief("failed to connect to privsep daemon");
    while ((r = write(thdata->fd, nb->auth_token, sizeof(nb->auth_token))) == -1 && errno == EINTR)
        ;
    if (r != sizeof(nb->auth_token))
        dief("failed to send authentication token");
    pthread_setspecific(nb->thread_key, thdata);

    return thdata;
}

int neverbleed_get_fd(neverbleed_t *nb)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    return thdata->fd;
}

int neverbleed_transaction_read(neverbleed_t *nb, neverbleed_iobuf_t *buf)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    return do_iobuf_transaction_read(buf, thdata);
}

int neverbleed_transaction_write(neverbleed_t *nb, neverbleed_iobuf_t *buf)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    return do_iobuf_transaction_write(buf, thdata);
}

static void do_exdata_free_callback(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    /* when other engines are used, this callback gets called without neverbleed data */
    if (ptr == NULL)
        return;
    struct st_neverbleed_rsa_exdata_t *exdata = ptr;
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(exdata->nb);

    neverbleed_iobuf_t buf = {NULL};
    iobuf_push_str(&buf, "del_pkey");
    iobuf_push_num(&buf, exdata->key_index);
    // "del_pkey" command is fire-and-forget, it cannot fail, so doesn't have a response
    iobuf_transaction_no_response(&buf, thdata);

    free(exdata);
}

static int get_rsa_exdata_idx(void);
static void rsa_exdata_free_callback(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    assert(idx == get_rsa_exdata_idx());
    do_exdata_free_callback(parent, ptr, ad, idx, argl, argp);
}

static int get_rsa_exdata_idx(void)
{
    static volatile int index;
    NEVERBLEED_MULTITHREAD_ONCE({
        index = RSA_get_ex_new_index(0, NULL, NULL, NULL, rsa_exdata_free_callback);
    });
    return index;
}
static void get_privsep_data(const RSA *rsa, struct st_neverbleed_rsa_exdata_t **exdata,
                             struct st_neverbleed_thread_data_t **thdata)
{
    *exdata = RSA_get_ex_data(rsa, get_rsa_exdata_idx());
    if (*exdata == NULL) {
        errno = 0;
        dief("invalid internal ref");
    }
    *thdata = get_thread_data((*exdata)->nb);
}

static struct {
    struct {
        pthread_mutex_t lock;
        /**
         * if the slot is use contains a non-NULL key; if not in use, contains the index of the next empty slot or SIZE_MAX if there
         * are no more empty slots
         */
        union {
            EVP_PKEY *pkey;
            size_t next_empty;
        } *slots;
        size_t num_slots;
        size_t first_empty;
    } keys;
    neverbleed_t *nb;
} daemon_vars = {{.lock = PTHREAD_MUTEX_INITIALIZER, .first_empty = SIZE_MAX}};

static __thread struct {
    int sockfd;
#ifdef __linux
    int epollfd;
#endif
    struct {
        neverbleed_iobuf_t *first, **next;
    } responses;
} conn_ctx;

static int use_offload = 0;

#if USE_OFFLOAD

struct engine_request {
    neverbleed_iobuf_t *buf;
    int async_fd;
#ifdef OPENSSL_IS_BORINGSSL
    struct {
        RSA *rsa;
        uint8_t output[512];
        union {
            struct {
                uint8_t padded[512];
            } digestsign;
        };
    } data;
    async_ctx *async_ctx;
#else
    int (*stub)(neverbleed_iobuf_t *);
    struct {
        ASYNC_WAIT_CTX *ctx;
        ASYNC_JOB *job;
    } async;
#endif
};

static void offload_free_request(struct engine_request *req)
{
#ifdef OPENSSL_IS_BORINGSSL
    bssl_qat_async_finish_job(req->async_ctx);
    RSA_free(req->data.rsa);
#else
    ASYNC_WAIT_CTX_free(req->async.ctx);
#endif
    OPENSSL_cleanse(req, sizeof(*req));
    free(req);
}

static int do_epoll_ctl(int epollfd, int op, int fd, struct epoll_event *event)
{
    int ret;
    while ((ret = epoll_ctl(epollfd, op, fd, event) != 0) && errno == EINTR)
        ;
    return ret;
}

static void register_wait_fd(struct engine_request *req)
{
#ifdef OPENSSL_IS_BORINGSSL
    ASYNC_WAIT_CTX *ctx = req->async_ctx->currjob->waitctx;
#else
    ASYNC_WAIT_CTX *ctx = req->async.ctx;
#endif
    size_t numfds;

    if (!ASYNC_WAIT_CTX_get_all_fds(ctx, NULL, &numfds) || numfds != 1)
        dief("unexpected number of fds (%zu) requested in async mode\n", numfds);
    if (!ASYNC_WAIT_CTX_get_all_fds(ctx, &req->async_fd, &numfds))
        dief("ASYNC_WAIT_CTX_get_all_fds failed\n");
    struct epoll_event ev = {.events = EPOLLIN, .data.ptr = req};
    if (do_epoll_ctl(conn_ctx.epollfd, EPOLL_CTL_ADD, req->async_fd, &ev) != 0)
        dief("epoll_ctl failed:%d\n", errno);
}

#endif

static int send_responses(int cleanup)
{
    neverbleed_iobuf_t *buf;
    int result = 0;

    /* Send all buffers that have data being filled. The lock is held until everything is being done, as this function can be called
     * from multiple threads simultaneously. */
    while ((buf = conn_ctx.responses.first) != NULL && !buf->processing) {
        if ((conn_ctx.responses.first = buf->next) == NULL)
            conn_ctx.responses.next = &conn_ctx.responses.first;
        if (!cleanup && iobuf_write(buf, conn_ctx.sockfd) != 0) {
            warnf(errno != 0 ? "write error" : "connection closed by client");
            result = -1;
        }
        iobuf_dispose(buf);
        free(buf);
        if (result != 0)
            break;
    }

    return result;
}

static RSA *daemon_get_rsa(size_t key_index)
{
    RSA *rsa = NULL;

    pthread_mutex_lock(&daemon_vars.keys.lock);
    if (key_index < daemon_vars.keys.num_slots)
        rsa = EVP_PKEY_get1_RSA(daemon_vars.keys.slots[key_index].pkey);
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return rsa;
}

size_t allocate_slot(void)
{
    /* expand if all slots are in use */
    if (daemon_vars.keys.first_empty == SIZE_MAX) {
        size_t new_capacity = (daemon_vars.keys.num_slots < 4 ? 4 : daemon_vars.keys.num_slots) * 2;
        if ((daemon_vars.keys.slots = realloc(daemon_vars.keys.slots, sizeof(daemon_vars.keys.slots[0]) * new_capacity)) == NULL)
            dief("no memory");
        daemon_vars.keys.first_empty = daemon_vars.keys.num_slots;
        for (size_t i = daemon_vars.keys.num_slots; i < new_capacity - 1; ++i)
            daemon_vars.keys.slots[i].next_empty = i + 1;
        daemon_vars.keys.slots[new_capacity - 1].next_empty = SIZE_MAX;
        daemon_vars.keys.num_slots = new_capacity;
    }

    /* detach the first empty slot from the empty list */
    size_t slot_index = daemon_vars.keys.first_empty;
    daemon_vars.keys.first_empty = daemon_vars.keys.slots[slot_index].next_empty;

    /* set bogus value in the allocated slot to help figure out what happened upon crash */
    daemon_vars.keys.slots[slot_index].next_empty = SIZE_MAX - 1;

    return slot_index;
}

static size_t daemon_set_pkey(EVP_PKEY *pkey)
{
    assert(pkey != NULL);

    pthread_mutex_lock(&daemon_vars.keys.lock);

    size_t index = allocate_slot();
    daemon_vars.keys.slots[index].pkey = pkey;
    EVP_PKEY_up_ref(pkey);

    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return index;
}

static int priv_encdec_proxy(const char *cmd, int flen, const unsigned char *from, unsigned char *_to, RSA *rsa, int padding)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    neverbleed_iobuf_t buf = {NULL};
    size_t ret;
    unsigned char *to;
    size_t tolen;

    get_privsep_data(rsa, &exdata, &thdata);

    iobuf_push_str(&buf, cmd);
    iobuf_push_bytes(&buf, from, flen);
    iobuf_push_num(&buf, exdata->key_index);
    iobuf_push_num(&buf, padding);

    iobuf_transaction(&buf, thdata);

    if (iobuf_shift_num(&buf, &ret) != 0 || (to = iobuf_shift_bytes(&buf, &tolen)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    memcpy(_to, to, tolen);
    iobuf_dispose(&buf);

    return (int)ret;
}

static int priv_encdec_stub(const char *name,
                            int (*func)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding),
                            neverbleed_iobuf_t *buf)
{
    unsigned char *from, to[4096];
    size_t flen;
    size_t key_index, padding;
    RSA *rsa;
    int ret;

    if ((from = iobuf_shift_bytes(buf, &flen)) == NULL || iobuf_shift_num(buf, &key_index) != 0 ||
        iobuf_shift_num(buf, &padding) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", name);
        return -1;
    }
    if ((rsa = daemon_get_rsa(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu\n", name, key_index);
        return -1;
    }
    ret = func((int)flen, from, to, rsa, (int)padding);
    iobuf_dispose(buf);
    RSA_free(rsa);

    iobuf_push_num(buf, ret);
    iobuf_push_bytes(buf, to, ret > 0 ? ret : 0);

    return 0;
}

#if !defined(OPENSSL_IS_BORINGSSL)

static int priv_enc_proxy(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return priv_encdec_proxy("priv_enc", flen, from, to, rsa, padding);
}

static int priv_enc_stub(neverbleed_iobuf_t *buf)
{
    return priv_encdec_stub(__FUNCTION__, RSA_private_encrypt, buf);
}

static int priv_dec_proxy(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return priv_encdec_proxy("priv_dec", flen, from, to, rsa, padding);
}

static int priv_dec_stub(neverbleed_iobuf_t *buf)
{
    return priv_encdec_stub(__FUNCTION__, RSA_private_decrypt, buf);
}

static int sign_proxy(int type, const unsigned char *m, unsigned int m_len, unsigned char *_sigret, unsigned *_siglen,
                      const RSA *rsa)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    neverbleed_iobuf_t buf = {NULL};
    size_t ret, siglen;
    unsigned char *sigret;

    get_privsep_data(rsa, &exdata, &thdata);

    iobuf_push_str(&buf, "sign");
    iobuf_push_num(&buf, type);
    iobuf_push_bytes(&buf, m, m_len);
    iobuf_push_num(&buf, exdata->key_index);
    iobuf_transaction(&buf, thdata);

    if (iobuf_shift_num(&buf, &ret) != 0 || (sigret = iobuf_shift_bytes(&buf, &siglen)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    memcpy(_sigret, sigret, siglen);
    *_siglen = (unsigned)siglen;
    iobuf_dispose(&buf);

    return (int)ret;
}

static int sign_stub(neverbleed_iobuf_t *buf)
{
    unsigned char *m, sigret[4096];
    size_t type, m_len, key_index;
    RSA *rsa;
    unsigned siglen = 0;
    int ret;

    if (iobuf_shift_num(buf, &type) != 0 || (m = iobuf_shift_bytes(buf, &m_len)) == NULL || iobuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }
    if ((rsa = daemon_get_rsa(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu", __FUNCTION__, key_index);
        return -1;
    }
    ret = RSA_sign((int)type, m, (unsigned)m_len, sigret, &siglen, rsa);
    iobuf_dispose(buf);
    RSA_free(rsa);

    iobuf_push_num(buf, ret);
    iobuf_push_bytes(buf, sigret, ret == 1 ? siglen : 0);

    return 0;
}

#endif

static EVP_PKEY *create_pkey(neverbleed_t *nb, size_t key_index, const char *ebuf, const char *nbuf)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    RSA *rsa;
    EVP_PKEY *pkey;
    BIGNUM *e = NULL, *n = NULL;

    if ((exdata = malloc(sizeof(*exdata))) == NULL) {
        fprintf(stderr, "no memory\n");
        abort();
    }
    exdata->nb = nb;
    exdata->key_index = key_index;

    rsa = RSA_new_method(nb->engine);
    RSA_set_ex_data(rsa, get_rsa_exdata_idx(), exdata);
    if (BN_hex2bn(&e, ebuf) == 0) {
        fprintf(stderr, "failed to parse e:%s\n", ebuf);
        abort();
    }
    if (BN_hex2bn(&n, nbuf) == 0) {
        fprintf(stderr, "failed to parse n:%s\n", nbuf);
        abort();
    }
    RSA_set0_key(rsa, n, e, NULL);
#if !defined(OPENSSL_IS_BORINGSSL)
    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
#endif

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa);
    RSA_free(rsa);

    return pkey;
}

#ifdef NEVERBLEED_ECDSA

static EC_KEY *daemon_get_ecdsa(size_t key_index)
{
    EC_KEY *ec_key = NULL;

    pthread_mutex_lock(&daemon_vars.keys.lock);
    if (key_index < daemon_vars.keys.num_slots)
        ec_key = EVP_PKEY_get1_EC_KEY(daemon_vars.keys.slots[key_index].pkey);
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return ec_key;
}

static int ecdsa_sign_stub(neverbleed_iobuf_t *buf)
{
    unsigned char *m, sigret[4096];
    size_t type, m_len, key_index;
    EC_KEY *ec_key;
    unsigned siglen = 0;
    int ret;

    if (iobuf_shift_num(buf, &type) != 0 || (m = iobuf_shift_bytes(buf, &m_len)) == NULL || iobuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }
    if ((ec_key = daemon_get_ecdsa(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu", __FUNCTION__, key_index);
        return -1;
    }

    ret = ECDSA_sign((int)type, m, (unsigned)m_len, sigret, &siglen, ec_key);
    iobuf_dispose(buf);

    EC_KEY_free(ec_key);

    iobuf_push_num(buf, ret);
    iobuf_push_bytes(buf, sigret, ret == 1 ? siglen : 0);

    return 0;
}

static int get_ecdsa_exdata_idx(void);
static void ecdsa_exdata_free_callback(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    assert(idx == get_ecdsa_exdata_idx());
    do_exdata_free_callback(parent, ptr, ad, idx, argl, argp);
}

static int get_ecdsa_exdata_idx(void)
{
    static volatile int index;
    NEVERBLEED_MULTITHREAD_ONCE({
        index = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, ecdsa_exdata_free_callback);
    });
    return index;
}

static void ecdsa_get_privsep_data(const EC_KEY *ec_key, struct st_neverbleed_rsa_exdata_t **exdata,
                                   struct st_neverbleed_thread_data_t **thdata)
{
    *exdata = EC_KEY_get_ex_data(ec_key, get_ecdsa_exdata_idx());
    if (*exdata == NULL) {
        errno = 0;
        dief("invalid internal ref");
    }
    *thdata = get_thread_data((*exdata)->nb);
}

static int ecdsa_sign_proxy(int type, const unsigned char *m, int m_len, unsigned char *_sigret, unsigned int *_siglen,
                            const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *ec_key)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    neverbleed_iobuf_t buf = {NULL};
    size_t ret, siglen;
    unsigned char *sigret;

    ecdsa_get_privsep_data(ec_key, &exdata, &thdata);

    /* as far as I've tested so far, kinv and rp are always NULL.
       Looks like setup_sign will precompute this, but it is only
       called sign_sig, and it seems to be not used in TLS ECDSA */
    if (kinv != NULL || rp != NULL) {
        errno = 0;
        dief("unexpected non-NULL kinv and rp");
    }

    iobuf_push_str(&buf, "ecdsa_sign");
    iobuf_push_num(&buf, type);
    iobuf_push_bytes(&buf, m, m_len);
    iobuf_push_num(&buf, exdata->key_index);
    iobuf_transaction(&buf, thdata);

    if (iobuf_shift_num(&buf, &ret) != 0 || (sigret = iobuf_shift_bytes(&buf, &siglen)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    memcpy(_sigret, sigret, siglen);
    *_siglen = (unsigned)siglen;
    iobuf_dispose(&buf);

    return (int)ret;
}

static EVP_PKEY *ecdsa_create_pkey(neverbleed_t *nb, size_t key_index, int curve_name, const void *pubkey, size_t pubkey_len)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    EC_KEY *ec_key;
    EC_GROUP *ec_group;
    EC_POINT *ec_pubkey;
    EVP_PKEY *pkey;

    if ((exdata = malloc(sizeof(*exdata))) == NULL) {
        fprintf(stderr, "no memory\n");
        abort();
    }
    exdata->nb = nb;
    exdata->key_index = key_index;

    ec_key = EC_KEY_new_method(nb->engine);
    EC_KEY_set_ex_data(ec_key, get_ecdsa_exdata_idx(), exdata);

    ec_group = EC_GROUP_new_by_curve_name(curve_name);
    if (!ec_group) {
        fprintf(stderr, "could not create EC_GROUP\n");
        abort();
    }

    EC_KEY_set_group(ec_key, ec_group);

    ec_pubkey = EC_POINT_new(ec_group);
    assert(ec_pubkey != NULL);
    if (!EC_POINT_oct2point(ec_group, ec_pubkey, pubkey, pubkey_len, NULL)) {
        fprintf(stderr, "failed to get ECDSA ephemeral public key from BIGNUM\n");
        abort();
    }
    EC_KEY_set_public_key(ec_key, ec_pubkey);

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, ec_key);

    EC_POINT_free(ec_pubkey);
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_key);

    return pkey;
}

#endif

static EVP_PKEY *daemon_get_pkey(size_t key_index)
{
    EVP_PKEY *pkey = NULL;

    pthread_mutex_lock(&daemon_vars.keys.lock);
    if (key_index < daemon_vars.keys.num_slots) {
        pkey = daemon_vars.keys.slots[key_index].pkey;
        EVP_PKEY_up_ref(pkey);
    }
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return pkey;
}

#if USE_OFFLOAD && defined(OPENSSL_IS_BORINGSSL)

static struct engine_request *bssl_offload_create_request(neverbleed_iobuf_t *buf, EVP_PKEY *pkey)
{
    RSA *_rsa = EVP_PKEY_get1_RSA(pkey);

    struct engine_request *req = malloc(sizeof(*req));
    if (req == NULL)
        dief("no memory\n");
    *req = (struct engine_request){.buf = buf, .async_fd = -1, .async_ctx = bssl_qat_async_start_job(), .data.rsa = _rsa};

    if (req->async_ctx == NULL)
        dief("failed to initialize async job\n");
    if (RSA_size(req->data.rsa) > sizeof(req->data.output))
        dief("RSA key too large\n");

    return req;
}

static void bssl_offload_digestsign(neverbleed_iobuf_t *buf, EVP_PKEY *pkey, const EVP_MD *md, const void *signdata, size_t signlen,
                                    int rsa_pss)
{
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned digestlen;

    { /* generate digest of signdata */
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx == NULL)
            dief("no memory\n");
        if (!EVP_DigestInit_ex(mdctx, md, NULL) || !EVP_DigestUpdate(mdctx, signdata, signlen) ||
            !EVP_DigestFinal_ex(mdctx, digest, &digestlen))
            dief("digest calculation failed\n");
        EVP_MD_CTX_free(mdctx);
    }

    struct engine_request *req = bssl_offload_create_request(buf, pkey);
    size_t rsa_size = RSA_size(req->data.rsa), padded_len;
    int padding;

    /* generate padded octets to be signed */
    if (rsa_pss) {
        if (!RSA_padding_add_PKCS1_PSS_mgf1(req->data.rsa, req->data.digestsign.padded, digest, md, md, -1))
            dief("RSA_paddding_add_PKCS1_PSS_mgf1 failed\n");
        padded_len = rsa_size;
        padding = RSA_NO_PADDING;
    } else {
        /* PKCS1 padding */
        int hash_nid = EVP_MD_type(md), is_alloced;
        uint8_t *tbs;
        if (!RSA_add_pkcs1_prefix(&tbs, &padded_len, &is_alloced, hash_nid, digest, digestlen))
            dief("RSA_add_pkcs1_prefix failed\n");
        if (padded_len > rsa_size)
            dief("output of RSA_add_pkcs1_prefix is unexpectedly large\n");
        memcpy(req->data.digestsign.padded, tbs, padded_len);
        if (is_alloced)
            OPENSSL_free(tbs);
        padding = RSA_PKCS1_PADDING;
    }

    OPENSSL_cleanse(digest, sizeof(digest));

    /* dispatch RSA calculation */
    RSA_METHOD *meth = bssl_engine_get_rsa_method();
    if (meth == NULL)
        dief("failed to obtain QAT RSA method table\n");
    size_t siglen;
    if (!meth->sign_raw(req->data.rsa, &siglen, req->data.output, rsa_size, req->data.digestsign.padded, padded_len, padding))
        dief("sign_raw failure\n");
    if (siglen != 0)
        dief("sign_raw completed synchronously unexpectedly\n");

    buf->processing = 1;
    register_wait_fd(req);
}

static int bssl_offload_decrypt(neverbleed_iobuf_t *buf, EVP_PKEY *pkey, const void *src, size_t len)
{
    struct engine_request *req = bssl_offload_create_request(buf, pkey);

    /* dispatch RSA calculation */
    RSA_METHOD *meth = bssl_engine_get_rsa_method();
    if (meth == NULL)
        dief("failed to obtain QAT RSA method table\n");
    size_t outlen;
    if (!meth->decrypt(req->data.rsa, &outlen, req->data.output, sizeof(req->data.output), src, len, RSA_NO_PADDING)) {
        warnf("RSA decrypt failure\n");
        goto Exit;
    }
    if (outlen != 0)
        dief("RSA decrypt completed synchronously unexpectedly\n");

    buf->processing = 1;
    register_wait_fd(req);
    return 1;

Exit:
    offload_free_request(req);
    return 0;
}

#endif

static int digestsign_stub(neverbleed_iobuf_t *buf)
{
    size_t key_index, md_nid, signlen;
    void *signdata;
    size_t rsa_pss;
    EVP_PKEY *pkey;
    const EVP_MD *md;

    /* parse input */
    if (iobuf_shift_num(buf, &key_index) != 0 || iobuf_shift_num(buf, &md_nid) != 0 ||
        (signdata = iobuf_shift_bytes(buf, &signlen)) == NULL || iobuf_shift_num(buf, &rsa_pss) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }
    if ((pkey = daemon_get_pkey(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu", __FUNCTION__, key_index);
        return -1;
    }
    if (md_nid != SIZE_MAX) {
        if ((md = EVP_get_digestbynid((int)md_nid)) == NULL) {
            errno = 0;
            warnf("%s: invalid EVP_MD nid", __FUNCTION__);
            return -1;
        }
    } else {
        md = NULL;
    }

#if USE_OFFLOAD && defined(OPENSSL_IS_BORINGSSL)
    if (use_offload && EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        bssl_offload_digestsign(buf, pkey, md, signdata, signlen, rsa_pss);
        goto Exit;
    }
#endif

    /* generate signature */
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    unsigned char digestbuf[4096];
    size_t digestlen;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
        goto Softfail;
    if (EVP_DigestSignInit(mdctx, &pkey_ctx, md, NULL, pkey) != 1)
        goto Softfail;
    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA && rsa_pss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1)
            goto Softfail;
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md) != 1)
            goto Softfail;
    }
    /* ED25519 keys can never be loaded, so use the Update -> Final call chain without worrying about backward compatibility */
    if (EVP_DigestSignUpdate(mdctx, signdata, signlen) != 1)
        goto Softfail;
    if (EVP_DigestSignFinal(mdctx, NULL, &digestlen) != 1)
        goto Softfail;
    if (sizeof(digestbuf) < digestlen) {
        warnf("%s: digest unexpectedly long as %zu bytes", __FUNCTION__, digestlen);
        goto Softfail;
    }
    if (EVP_DigestSignFinal(mdctx, digestbuf, &digestlen) != 1)
        goto Softfail;

Respond: /* build response */
    iobuf_dispose(buf);
    iobuf_push_bytes(buf, digestbuf, digestlen);
    if (mdctx != NULL)
        EVP_MD_CTX_destroy(mdctx);
Exit:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    return 0;

Softfail:
    digestlen = 0;
    goto Respond;
}

void neverbleed_start_digestsign(neverbleed_iobuf_t *buf, EVP_PKEY *pkey, const EVP_MD *md, const void *input, size_t len,
                                 int rsa_pss)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    const char *cmd = "digestsign";

    /* obtain reference */
    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_RSA: {
        RSA *rsa = EVP_PKEY_get1_RSA(pkey); /* get0 is available not available in OpenSSL 1.0.2 */
        get_privsep_data(rsa, &exdata, &thdata);
        RSA_free(rsa);
        cmd = "digestsign-rsa";
    } break;
#ifdef NEVERBLEED_ECDSA
    case EVP_PKEY_EC:
        ecdsa_get_privsep_data(EVP_PKEY_get0_EC_KEY(pkey), &exdata, &thdata);
        break;
#endif
    default:
        dief("unexpected private key");
        break;
    }

    *buf = (neverbleed_iobuf_t){NULL};
    iobuf_push_str(buf, cmd);
    iobuf_push_num(buf, exdata->key_index);
    iobuf_push_num(buf, md != NULL ? (size_t)EVP_MD_nid(md) : SIZE_MAX);
    iobuf_push_bytes(buf, input, len);
    iobuf_push_num(buf, rsa_pss);
}

void neverbleed_finish_digestsign(neverbleed_iobuf_t *buf, void **digest, size_t *digest_len)
{
    const void *src;

    if ((src = iobuf_shift_bytes(buf, digest_len)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    if ((*digest = malloc(*digest_len)) == NULL)
        dief("no memory");
    memcpy(*digest, src, *digest_len);

    iobuf_dispose(buf);
}

static int decrypt_stub(neverbleed_iobuf_t *buf)
{
    size_t key_index, srclen;
    void *src;
    EVP_PKEY *pkey;
    RSA *rsa;
    uint8_t decryptbuf[1024];
    int decryptlen;

    /* parse input */
    if (iobuf_shift_num(buf, &key_index) != 0 || (src = iobuf_shift_bytes(buf, &srclen)) == NULL) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }
    if ((pkey = daemon_get_pkey(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu", __FUNCTION__, key_index);
        return -1;
    }

    rsa = EVP_PKEY_get1_RSA(pkey); /* get0 is available not available in OpenSSL 1.0.2 */
    assert(rsa != NULL);
    assert(sizeof(decryptbuf) >= RSA_size(rsa));

#if USE_OFFLOAD && defined(OPENSSL_IS_BORINGSSL)
    if (use_offload) {
        if (!bssl_offload_decrypt(buf, pkey, src, srclen))
            goto Softfail;

        goto Exit;
    }
#endif

    if ((decryptlen = RSA_private_decrypt(srclen, src, decryptbuf, rsa, RSA_NO_PADDING)) == -1) {
        errno = 0;
        warnf("RSA decryption error");
        goto Softfail;
    }

Respond:
    iobuf_dispose(buf);
    iobuf_push_bytes(buf, decryptbuf, decryptlen);
Exit:
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return 0;

Softfail:
    decryptlen = 0;
    goto Respond;
}

void neverbleed_start_decrypt(neverbleed_iobuf_t *buf, EVP_PKEY *pkey, const void *input, size_t len)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;

    {
        RSA *rsa = EVP_PKEY_get1_RSA(pkey); /* get0 is available not available in OpenSSL 1.0.2 */
        assert(rsa != NULL);
        get_privsep_data(rsa, &exdata, &thdata);
        RSA_free(rsa);
    }

    *buf = (neverbleed_iobuf_t){NULL};
    iobuf_push_str(buf, "decrypt");
    iobuf_push_num(buf, exdata->key_index);
    iobuf_push_bytes(buf, input, len);
}

void neverbleed_finish_decrypt(neverbleed_iobuf_t *buf, void **digest, size_t *digest_len)
{
    neverbleed_finish_digestsign(buf, digest, digest_len);
}

int neverbleed_load_private_key_file(neverbleed_t *nb, SSL_CTX *ctx, const char *fn, char *errbuf)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    neverbleed_iobuf_t buf = {NULL};
    int ret = 1;
    size_t index, type;
    EVP_PKEY *pkey;

    iobuf_push_str(&buf, "load_key");
    iobuf_push_str(&buf, fn);
    iobuf_transaction(&buf, thdata);

    if (iobuf_shift_num(&buf, &type) != 0 || iobuf_shift_num(&buf, &index) != 0) {
        errno = 0;
        dief("failed to parse response");
    }

    switch (type) {
    case NEVERBLEED_TYPE_RSA: {
        char *estr, *nstr;

        if ((estr = iobuf_shift_str(&buf)) == NULL || (nstr = iobuf_shift_str(&buf)) == NULL) {
            errno = 0;
            dief("failed to parse response");
        }
        pkey = create_pkey(nb, index, estr, nstr);
        break;
    }
#ifdef NEVERBLEED_ECDSA
    case NEVERBLEED_TYPE_ECDSA: {
        size_t curve_name, pubkey_len;
        void *pubkey_bytes;

        if (iobuf_shift_num(&buf, &curve_name) != 0 || (pubkey_bytes = iobuf_shift_bytes(&buf, &pubkey_len)) == NULL) {
            errno = 0;
            dief("failed to parse response");
        }
        pkey = ecdsa_create_pkey(nb, index, (int)curve_name, pubkey_bytes, pubkey_len);
        break;
    }
#endif
    default: {
        char *errstr;

        if ((errstr = iobuf_shift_str(&buf)) == NULL) {
            errno = 0;
            dief("failed to parse response");
        }

        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "%s", errstr);
        return -1;
    }
    }

    iobuf_dispose(&buf);

    /* success */
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "SSL_CTX_use_PrivateKey failed");
        ret = 0;
    }

    EVP_PKEY_free(pkey);
    return ret;
}

static int load_key_stub(neverbleed_iobuf_t *buf)
{
    char *fn;
    FILE *fp = NULL;
    RSA *rsa = NULL;
    size_t key_index = SIZE_MAX;
    char *estr = NULL, *nstr = NULL, errbuf[NEVERBLEED_ERRBUF_SIZE] = "";
    size_t type = NEVERBLEED_TYPE_ERROR;
    EVP_PKEY *pkey = NULL;
#ifdef NEVERBLEED_ECDSA
    const EC_GROUP *ec_group;
    void *ec_pubkeybytes = NULL;
    size_t ec_pubkeylen;
#endif

    if ((fn = iobuf_shift_str(buf)) == NULL) {
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    if ((fp = fopen(fn, "rt")) == NULL) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        goto Respond;
    }

    if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
        snprintf(errbuf, sizeof(errbuf), "failed to parse the private key");
        goto Respond;
    }

    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_RSA: {
        const BIGNUM *e, *n;

        rsa = EVP_PKEY_get1_RSA(pkey);
        type = NEVERBLEED_TYPE_RSA;
        RSA_get0_key(rsa, &n, &e, NULL);
        estr = BN_bn2hex(e);
        nstr = BN_bn2hex(n);
        break;
    }
    case EVP_PKEY_EC: {
#ifdef NEVERBLEED_ECDSA
        const EC_POINT *ec_pubkey;
        EC_KEY *ec_key;

        ec_key = (EC_KEY *)EVP_PKEY_get0_EC_KEY(pkey);
        type = NEVERBLEED_TYPE_ECDSA;
        ec_group = EC_KEY_get0_group(ec_key);
        ec_pubkey = EC_KEY_get0_public_key(ec_key);
        ec_pubkeylen = EC_POINT_point2oct(ec_group, ec_pubkey, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if (!(ec_pubkeylen > 0 && (ec_pubkeybytes = malloc(ec_pubkeylen)) != NULL &&
              EC_POINT_point2oct(ec_group, ec_pubkey, POINT_CONVERSION_UNCOMPRESSED, ec_pubkeybytes, ec_pubkeylen, NULL) ==
                  ec_pubkeylen))
            dief("failed to serialize EC public key");
        break;
#else
        snprintf(errbuf, sizeof(errbuf), "ECDSA support requires OpenSSL >= 1.1.0, LibreSSL >= 2.9.1, or BoringSSL");
        goto Respond;
#endif
    }
    default:
        snprintf(errbuf, sizeof(errbuf), "unsupported private key: %d", EVP_PKEY_base_id(pkey));
        goto Respond;
    }

    /* store the key */
    key_index = daemon_set_pkey(pkey);

Respond:
    iobuf_dispose(buf);
    iobuf_push_num(buf, type);
    iobuf_push_num(buf, key_index);
    switch (type) {
    case NEVERBLEED_TYPE_RSA:
        iobuf_push_str(buf, estr != NULL ? estr : "");
        iobuf_push_str(buf, nstr != NULL ? nstr : "");
        break;
#ifdef NEVERBLEED_ECDSA
    case NEVERBLEED_TYPE_ECDSA:
        iobuf_push_num(buf, EC_GROUP_get_curve_name(ec_group));
        iobuf_push_bytes(buf, ec_pubkeybytes, ec_pubkeylen);
        break;
#endif
    default:
        iobuf_push_str(buf, errbuf);
    }
    if (rsa != NULL)
        RSA_free(rsa);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (estr != NULL)
        OPENSSL_free(estr);
    if (nstr != NULL)
        OPENSSL_free(nstr);
#ifdef NEVERBLEED_ECDSA
    if (ec_pubkeybytes != NULL)
        free(ec_pubkeybytes);
#endif
    if (fp != NULL)
        fclose(fp);

    return 0;
}

int neverbleed_setuidgid(neverbleed_t *nb, const char *user, int change_socket_ownership)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    neverbleed_iobuf_t buf = {NULL};
    size_t ret;

    iobuf_push_str(&buf, "setuidgid");
    iobuf_push_str(&buf, user);
    iobuf_push_num(&buf, change_socket_ownership);
    iobuf_transaction(&buf, thdata);

    if (iobuf_shift_num(&buf, &ret) != 0) {
        errno = 0;
        dief("failed to parse response");
    }
    iobuf_dispose(&buf);

    return (int)ret;
}

static int setuidgid_stub(neverbleed_iobuf_t *buf)
{
    const char *user;
    size_t change_socket_ownership;
    struct passwd pwbuf, *pw;
    char pwstrbuf[65536]; /* should be large enough */
    int ret = -1;

    if ((user = iobuf_shift_str(buf)) == NULL || iobuf_shift_num(buf, &change_socket_ownership) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    errno = 0;
    if (getpwnam_r(user, &pwbuf, pwstrbuf, sizeof(pwstrbuf), &pw) != 0) {
        warnf("%s: getpwnam_r failed", __FUNCTION__);
        goto Respond;
    }
    if (pw == NULL) {
        warnf("%s: failed to obtain information of user:%s", __FUNCTION__, user);
        goto Respond;
    }

    if (change_socket_ownership) {
        char *dir;
        if (chown(daemon_vars.nb->sun_.sun_path, pw->pw_uid, pw->pw_gid) != 0)
            dief("chown failed for:%s", daemon_vars.nb->sun_.sun_path);
        dir = dirname(daemon_vars.nb->sun_.sun_path);
        if (chown(dir, pw->pw_uid, pw->pw_gid) != 0)
            dief("chown failed for:%s", dir);
        free(dir);
    }

    /* setuidgid */
    if (setgid(pw->pw_gid) != 0) {
        warnf("%s: setgid(%d) failed", __FUNCTION__, (int)pw->pw_gid);
        goto Respond;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        warnf("%s: initgroups(%s, %d) failed", __FUNCTION__, pw->pw_name, (int)pw->pw_gid);
        goto Respond;
    }
    if (setuid(pw->pw_uid) != 0) {
        warnf("%s: setuid(%d) failed\n", __FUNCTION__, (int)pw->pw_uid);
        goto Respond;
    }
    ret = 0;

Respond:
    iobuf_dispose(buf);
    iobuf_push_num(buf, ret);
    return 0;
}

#if NEVERBLEED_HAS_PTHREAD_SETAFFINITY_NP
int neverbleed_setaffinity(neverbleed_t *nb, NEVERBLEED_CPU_SET_T *cpuset)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    neverbleed_iobuf_t buf = {NULL};
    size_t ret;

    iobuf_push_str(&buf, "setaffinity");
    iobuf_push_bytes(&buf, cpuset, sizeof(*cpuset));
    iobuf_transaction(&buf, thdata);

    if (iobuf_shift_num(&buf, &ret) != 0) {
        errno = 0;
        dief("failed to parse response");
    }
    iobuf_dispose(&buf);

    return (int)ret;
}

static int setaffinity_stub(neverbleed_iobuf_t *buf)
{
    char *cpuset_bytes;
    size_t cpuset_len;
    NEVERBLEED_CPU_SET_T cpuset;
    int ret = 1;

    if ((cpuset_bytes = iobuf_shift_bytes(buf, &cpuset_len)) == NULL) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    assert(cpuset_len == sizeof(NEVERBLEED_CPU_SET_T));
    memcpy(&cpuset, cpuset_bytes, cpuset_len);

#ifdef __NetBSD__
    ret = pthread_setaffinity_np(pthread_self(), cpuset_size(cpuset), cpuset);
#else
    ret = pthread_setaffinity_np(pthread_self(), sizeof(NEVERBLEED_CPU_SET_T), &cpuset);
#endif
    if (ret != 0) {
        ret = 1;
        goto Respond;
    }

    ret = 0;

Respond:
    iobuf_dispose(buf);
    iobuf_push_num(buf, ret);
    return 0;
}
#endif

__attribute__((noreturn)) static void *daemon_close_notify_thread(void *_close_notify_fd)
{
    int close_notify_fd = (int)((char *)_close_notify_fd - (char *)NULL);
    char b;
    ssize_t r;

Redo:
    r = read(close_notify_fd, &b, 1);
    if (r == -1 && errno == EINTR)
        goto Redo;
    if (r > 0)
        goto Redo;
    /* close or error */

    /* unlink the temporary directory and socket file */
    unlink_dir(dirname(daemon_vars.nb->sun_.sun_path));

    _exit(0);
}

static int del_pkey_stub(neverbleed_iobuf_t *buf)
{
    size_t key_index;

    if (iobuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    pthread_mutex_lock(&daemon_vars.keys.lock);
    /* set slot as available */
    if (key_index < daemon_vars.keys.num_slots) {
        EVP_PKEY_free(daemon_vars.keys.slots[key_index].pkey);
        daemon_vars.keys.slots[key_index].next_empty = daemon_vars.keys.first_empty;
        daemon_vars.keys.first_empty = key_index;
    } else {
        warnf("%s: invalid key index %zu", __FUNCTION__, key_index);
    }
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return 0;
}

#define offload_start(stub, buf) ((stub)(buf))

#if USE_OFFLOAD
#ifdef OPENSSL_IS_BORINGSSL

static int offload_resume(struct engine_request *req)
{
    size_t outlen;

    if (do_epoll_ctl(conn_ctx.epollfd, EPOLL_CTL_DEL, req->async_fd, NULL) != 0)
        dief("epoll_ctl failed:%d\n", errno);

    /* get result */
    if (bssl_qat_async_ctx_copy_result(req->async_ctx, req->data.output, &outlen, sizeof(req->data.output)) != 0)
        dief("failed to obtain offload result\n");
    if (outlen > sizeof(req->data.output))
        dief("RSA output is unexpectedly large\n");
    /* save the result */
    iobuf_dispose(req->buf);
    iobuf_push_bytes(req->buf, req->data.output, outlen);

    req->buf->processing = 0;
    offload_free_request(req);

    return 0;
}

#else

static int offload_jobfunc(void *_req)
{
    struct engine_request *req = *(void **)_req;
    return req->stub(req->buf);
}

#undef offload_start
static int offload_start(int (*stub)(neverbleed_iobuf_t *), neverbleed_iobuf_t *buf)
{
    /* if engine is not used, run the stub synchronously */
    if (!use_offload)
        return stub(buf);

    buf->processing = 1;

    struct engine_request *req = malloc(sizeof(*req));
    if (req == NULL)
        dief("no memory");
    *req = (struct engine_request){.buf = buf, .async_fd = -1, .stub = stub};

    if ((req->async.ctx = ASYNC_WAIT_CTX_new()) == NULL)
        dief("failed to create ASYNC_WAIT_CTX\n");

    int ret;
    switch (ASYNC_start_job(&req->async.job, req->async.ctx, &ret, offload_jobfunc, &req, sizeof(req))) {
    case ASYNC_PAUSE: /* operation running async; register fd and bail out */
        register_wait_fd(req);
        return 0;
    case ASYNC_FINISH: /* completed synchronously */
        buf->processing = 0;
        break;
    default:
        dief("ASYNC_start_job errored\n");
        break;
    }

    offload_free_request(req);

    return ret;
}

static int offload_resume(struct engine_request *req)
{
    int ret;

    switch (ASYNC_start_job(&req->async.job, req->async.ctx, &ret, offload_jobfunc, &req, sizeof(req))) {
    case ASYNC_PAUSE:
        /* assume that wait fd is unchanged */
        return 0;
    case ASYNC_FINISH:
        if (do_epoll_ctl(conn_ctx.epollfd, EPOLL_CTL_DEL, req->async_fd, NULL) != 0)
            dief("epoll_ctl failed:%d\n", errno);
        break;
    default:
        dief("ASYNC_start_job failed\n");
        break;
    }

    /* job done */
    req->buf->processing = 0;
    offload_free_request(req);

    return ret;
}

#endif
#endif

/**
 * This function waits for the provided socket to become readable, then calls `nanosleep(1)` before returning.
 * The intention behind sleep is to provide the application to complete its event loop before the neverbleed process starts
 * spending CPU cycles on the time-consuming RSA operation.
 * In addition, when QAT is used, this function processes completion notifications from QAT and sends the responses.
 */
static int wait_for_data(int cleanup)
{
#if USE_OFFLOAD

    struct epoll_event events[20];
    int has_read = 0, num_events;

    do {
        while ((num_events = epoll_wait(conn_ctx.epollfd, events, sizeof(events) / sizeof(events[0]), -1)) == -1 &&
               (errno == EAGAIN || errno == EINTR))
            ;
        if (num_events == -1)
            dief("epoll_wait(2):%d\n", errno);
        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.ptr == NULL) {
                has_read = 1;
            } else {
                struct engine_request *req = events[i].data.ptr;
                int ret;
                if ((ret = offload_resume(req)) != 0)
                    return ret;
                if ((ret = send_responses(0)) != 0)
                    return ret;
            }
        }
    } while (!has_read);

#else

    fd_set rfds;
    int ret;
    FD_ZERO(&rfds);
    if (!cleanup)
        FD_SET(conn_ctx.sockfd, &rfds);

    while ((ret = select(conn_ctx.sockfd + 1, &rfds, NULL, NULL, NULL)) == -1 && (errno == EAGAIN || errno == EINTR))
        ;
    if (ret == -1)
        dief("select(2):%d\n", errno);

#endif

    // yield when data is available
    struct timespec tv = {.tv_nsec = 1};
    (void)nanosleep(&tv, NULL);

    return 0;
}

static void *daemon_conn_thread(void *_sock_fd)
{
    conn_ctx.sockfd = (int)((char *)_sock_fd - (char *)NULL);
    conn_ctx.responses.next = &conn_ctx.responses.first;
    neverbleed_iobuf_t *buf = NULL;

#if USE_OFFLOAD
    if ((conn_ctx.epollfd = epoll_create1(EPOLL_CLOEXEC)) == -1)
        dief("epoll_create1 failed:%d\n", errno);
    {
        struct epoll_event ev = {.events = EPOLLIN};
        if (do_epoll_ctl(conn_ctx.epollfd, EPOLL_CTL_ADD, conn_ctx.sockfd, &ev) != 0)
            dief("epoll_ctl failed:%d\n", errno);
    }
#endif

    { /* authenticate */
        unsigned char auth_token[NEVERBLEED_AUTH_TOKEN_SIZE];
        if (read_nbytes(conn_ctx.sockfd, &auth_token, sizeof(auth_token)) != 0) {
            warnf("failed to receive authencication token from client");
            goto Exit;
        }
        if (memcmp(auth_token, daemon_vars.nb->auth_token, NEVERBLEED_AUTH_TOKEN_SIZE) != 0) {
            warnf("client authentication failed");
            goto Exit;
        }
    }

    while (1) {
        if (wait_for_data(0) != 0)
            break;
        free(buf);
        buf = malloc(sizeof(*buf));
        if (buf == NULL)
            dief("no memory");
        *buf = (neverbleed_iobuf_t){};
        char *cmd;
        if (iobuf_read(buf, conn_ctx.sockfd) != 0) {
            if (errno != 0)
                warnf("read error");
            break;
        }
        if ((cmd = iobuf_shift_str(buf)) == NULL) {
            errno = 0;
            warnf("failed to parse request");
            break;
        }
#if !defined(OPENSSL_IS_BORINGSSL)
        if (strcmp(cmd, "priv_enc") == 0) {
            if (offload_start(priv_enc_stub, buf) != 0)
                break;
        } else if (strcmp(cmd, "priv_dec") == 0) {
            if (offload_start(priv_dec_stub, buf) != 0)
                break;
        } else if (strcmp(cmd, "sign") == 0) {
            if (offload_start(sign_stub, buf) != 0)
                break;
#ifdef NEVERBLEED_ECDSA
        } else if (strcmp(cmd, "ecdsa_sign") == 0) {
            if (ecdsa_sign_stub(buf) != 0)
                break;
#endif
        } else
#endif
            if (strcmp(cmd, "digestsign") == 0) {
            if (digestsign_stub(buf) != 0)
                break;
        } else if (strcmp(cmd, "digestsign-rsa") == 0) {
            if (offload_start(digestsign_stub, buf) != 0)
                break;
        } else if (strcmp(cmd, "decrypt") == 0) {
            if (offload_start(decrypt_stub, buf) != 0)
                break;
        } else if (strcmp(cmd, "load_key") == 0) {
            if (load_key_stub(buf) != 0)
                break;
        } else if (strcmp(cmd, "del_pkey") == 0) {
            if (del_pkey_stub(buf) != 0)
                break;
            iobuf_dispose(buf);
            // "del_pkey" command is fire-and-forget, it cannot fail, so doesn't have a response
            continue;
        } else if (strcmp(cmd, "setuidgid") == 0) {
            if (setuidgid_stub(buf) != 0)
                break;
#if NEVERBLEED_HAS_PTHREAD_SETAFFINITY_NP
        } else if (strcmp(cmd, "setaffinity") == 0) {
            if (setaffinity_stub(buf) != 0)
                break;
#endif
        } else {
            warnf("unknown command:%s", cmd);
            break;
        }
        /* add response to chain */
        *conn_ctx.responses.next = buf;
        conn_ctx.responses.next = &buf->next;
        buf = NULL; /* do not free */

        /* send responses if possible */
        if (send_responses(0) != 0)
            break;
    }

Exit:
    free(buf);
    /* run the loop while async ops are running */
    while (conn_ctx.responses.first != NULL)
        wait_for_data(1);

    close(conn_ctx.sockfd);
#ifdef __linux
    close(conn_ctx.epollfd);
#endif

    return NULL;
}

#if !(defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__))
#define closefrom my_closefrom
static void my_closefrom(int lowfd)
{
    /* On linux, try close_range (2), then fall back to the slow loop if it fails. */
#if defined(__linux__) && defined(__NR_close_range)
    if (syscall(__NR_close_range, lowfd, ~0, 0) == 0)
        return;
#endif

    for (int fd = (int)sysconf(_SC_OPEN_MAX) - 1; fd >= lowfd; --fd)
        (void)close(fd);
}
#endif

static void cleanup_fds(int listen_fd, int close_notify_fd)
{
    int maxfd, k;

    maxfd = 0;
    if (listen_fd > maxfd) {
        maxfd = listen_fd;
    }
    if (close_notify_fd > maxfd) {
        maxfd = close_notify_fd;
    }
    for (k = 0; k < maxfd; k++) {
        if (k == listen_fd || k == close_notify_fd)
            continue;
        switch (k) {
        case STDOUT_FILENO:
        case STDERR_FILENO:
        case STDIN_FILENO:
            break;
        default:
            (void)close(k);
        }
    }
    closefrom(maxfd + 1);
}

__attribute__((noreturn)) static void daemon_main(int listen_fd, int close_notify_fd, const char *tempdir)
{
    pthread_t tid;
    pthread_attr_t thattr;
    int sock_fd;

    cleanup_fds(listen_fd, close_notify_fd);
    pthread_attr_init(&thattr);
    pthread_attr_setdetachstate(&thattr, 1);

    switch (neverbleed_offload) {
    case NEVERBLEED_OFFLOAD_QAT_ON:
    case NEVERBLEED_OFFLOAD_QAT_AUTO: {
#if USE_OFFLOAD && defined(OPENSSL_IS_BORINGSSL)
        ENGINE_load_qat();
        bssl_qat_set_default_string("RSA");
        use_offload = ENGINE_QAT_PTR_GET() != NULL;
#elif USE_OFFLOAD && !defined(OPENSSL_IS_BORINGSSL)
        ENGINE *qat = ENGINE_by_id("qatengine");
        if (qat != NULL && ENGINE_init(qat)) {
            if (!ENGINE_set_default_RSA(qat))
                dief("failed to assign RSA operations to QAT\n");
            use_offload = 1;
        }
#endif
        if (!use_offload && neverbleed_offload == NEVERBLEED_OFFLOAD_QAT_ON)
            dief("use of QAT is forced but unavailable\n");
    } break;
    default:
        break;
    }

    if (pthread_create(&tid, &thattr, daemon_close_notify_thread, (char *)NULL + close_notify_fd) != 0)
        dief("pthread_create failed");

    while (1) {
        while ((sock_fd = accept(listen_fd, NULL, NULL)) == -1)
            ;
        if (pthread_create(&tid, &thattr, daemon_conn_thread, (char *)NULL + sock_fd) != 0)
            dief("pthread_create failed");
    }
}

static void set_signal_handler(int signo, void (*cb)(int signo))
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = cb;
    sigaction(signo, &action, NULL);
}

#ifndef NEVERBLEED_OPAQUE_RSA_METHOD

static RSA_METHOD static_rsa_method = {
    "privsep RSA method", /* name */
    NULL,                 /* rsa_pub_enc */
    NULL,                 /* rsa_pub_dec */
    priv_enc_proxy,       /* rsa_priv_enc */
    priv_dec_proxy,       /* rsa_priv_dec */
    NULL,                 /* rsa_mod_exp */
    NULL,                 /* bn_mod_exp */
    NULL,                 /* init */
    NULL,                 /* finish */
    RSA_FLAG_SIGN_VER,    /* flags */
    NULL,                 /* app data */
    sign_proxy,           /* rsa_sign */
    NULL,                 /* rsa_verify */
    NULL                  /* rsa_keygen */
};

#endif

int neverbleed_init(neverbleed_t *nb, char *errbuf)
{
    int pipe_fds[2] = {-1, -1}, listen_fd = -1;
    char *tempdir = NULL;

    /* setup the daemon */
    if (pipe(pipe_fds) != 0) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "pipe(2) failed:%s", strerror(errno));
        goto Fail;
    }
    set_cloexec(pipe_fds[1]);
    if ((tempdir = strdup("/tmp/openssl-privsep.XXXXXX")) == NULL) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "no memory");
        goto Fail;
    }
    if (mkdtemp(tempdir) == NULL) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "failed to create temporary directory under /tmp:%s", strerror(errno));
        goto Fail;
    }
    memset(&nb->sun_, 0, sizeof(nb->sun_));
    nb->sun_.sun_family = AF_UNIX;
    snprintf(nb->sun_.sun_path, sizeof(nb->sun_.sun_path), "%s/_", tempdir);
    RAND_bytes(nb->auth_token, sizeof(nb->auth_token));
    if ((listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "socket(2) failed:%s", strerror(errno));
        goto Fail;
    }
    if (bind(listen_fd, (void *)&nb->sun_, sizeof(nb->sun_)) != 0) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "failed to bind to %s:%s", nb->sun_.sun_path, strerror(errno));
        goto Fail;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "listen(2) failed:%s", strerror(errno));
        goto Fail;
    }
    nb->daemon_pid = fork();
    switch (nb->daemon_pid) {
    case -1:
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "fork(2) failed:%s", strerror(errno));
        goto Fail;
    case 0:
        close(pipe_fds[1]);
#if defined(__linux__)
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        prctl(PR_SET_PDEATHSIG, SIGTERM);
#elif defined(__FreeBSD__)
        int dumpable = PROC_TRACE_CTL_DISABLE;
        procctl(P_PID, 0, PROC_TRACE_CTL, &dumpable);
#elif defined(__sun)
        setpflags(__PROC_PROTECT, 1);
#elif defined(__APPLE__)
        ptrace(PT_DENY_ATTACH, 0, 0, 0);
#endif
        set_signal_handler(SIGTERM, SIG_IGN);
        if (neverbleed_post_fork_cb != NULL)
            neverbleed_post_fork_cb();
        daemon_vars.nb = nb;
        daemon_main(listen_fd, pipe_fds[0], tempdir);
        break;
    default:
        break;
    }
    close(listen_fd);
    listen_fd = -1;
    close(pipe_fds[0]);
    pipe_fds[0] = -1;

#if defined(OPENSSL_IS_BORINGSSL)
    nb->engine = NULL;
#else
    { /* setup engine */
        const RSA_METHOD *rsa_default_method;
        RSA_METHOD *rsa_method;
#ifdef NEVERBLEED_ECDSA
        const EC_KEY_METHOD *ecdsa_default_method;
        EC_KEY_METHOD *ecdsa_method;
#endif

#ifdef NEVERBLEED_OPAQUE_RSA_METHOD
        rsa_default_method = RSA_PKCS1_OpenSSL();
        rsa_method = RSA_meth_dup(rsa_default_method);

        RSA_meth_set1_name(rsa_method, "privsep RSA method");
        RSA_meth_set_priv_enc(rsa_method, priv_enc_proxy);
        RSA_meth_set_priv_dec(rsa_method, priv_dec_proxy);
        RSA_meth_set_sign(rsa_method, sign_proxy);
#else
        rsa_default_method = RSA_PKCS1_SSLeay();
        rsa_method = &static_rsa_method;

        rsa_method->rsa_pub_enc = rsa_default_method->rsa_pub_enc;
        rsa_method->rsa_pub_dec = rsa_default_method->rsa_pub_dec;
        rsa_method->rsa_verify = rsa_default_method->rsa_verify;
        rsa_method->bn_mod_exp = rsa_default_method->bn_mod_exp;
#endif

#ifdef NEVERBLEED_ECDSA
        ecdsa_default_method = EC_KEY_get_default_method();
        ecdsa_method = EC_KEY_METHOD_new(ecdsa_default_method);

        /* it seems sign_sig and sign_setup is not used in TLS ECDSA. */
        EC_KEY_METHOD_set_sign(ecdsa_method, ecdsa_sign_proxy, NULL, NULL);
#endif

        if ((nb->engine = ENGINE_new()) == NULL || !ENGINE_set_id(nb->engine, "neverbleed") ||
            !ENGINE_set_name(nb->engine, "privilege separation software engine") || !ENGINE_set_RSA(nb->engine, rsa_method)
#ifdef NEVERBLEED_ECDSA
            || !ENGINE_set_EC(nb->engine, ecdsa_method)
#endif
        ) {
            snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "failed to initialize the OpenSSL engine");
            goto Fail;
        }
        ENGINE_add(nb->engine);
    }
#endif

    /* setup thread key */
    pthread_key_create(&nb->thread_key, dispose_thread_data);

    free(tempdir);
    return 0;
Fail:
    if (pipe_fds[0] != -1)
        close(pipe_fds[0]);
    if (pipe_fds[1] != -1)
        close(pipe_fds[1]);
    if (tempdir != NULL) {
        unlink_dir(tempdir);
        free(tempdir);
    }
    if (listen_fd != -1)
        close(listen_fd);
    if (nb->engine != NULL) {
        ENGINE_free(nb->engine);
        nb->engine = NULL;
    }
    return -1;
}

void (*neverbleed_post_fork_cb)(void) = NULL;
void (*neverbleed_transaction_cb)(neverbleed_iobuf_t *, int) = NULL;
enum neverbleed_offload_type neverbleed_offload = NEVERBLEED_OFFLOAD_OFF;
