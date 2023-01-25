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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#if H2O_USE_KTLS
#include <linux/tls.h>
#endif
#if H2O_USE_IO_URING
#include <liburing.h>
#endif
#include "cloexec.h"
#include "h2o/linklist.h"

#if !defined(H2O_USE_ACCEPT4)
#ifdef __linux__
#if defined(__ANDROID__) && __ANDROID_API__ < 21
#define H2O_USE_ACCEPT4 0
#else
#define H2O_USE_ACCEPT4 1
#endif
#elif __FreeBSD__ >= 10
#define H2O_USE_ACCEPT4 1
#else
#define H2O_USE_ACCEPT4 0
#endif
#endif

struct st_h2o_evloop_socket_t {
    h2o_socket_t super;
    int fd;
    int _flags;
    h2o_evloop_t *loop;
    size_t max_read_size;
    struct st_h2o_evloop_socket_t *_next_pending;
    struct st_h2o_evloop_socket_t *_next_statechanged;
    struct {
        uint64_t prev_loop;
        uint64_t cur_loop;
        uint64_t cur_run_count;
    } bytes_written;
};

#if H2O_USE_IO_URING

struct st_h2o_evloop_read_file_cmd_t {
    h2o_socket_read_file_cmd_t super;
    h2o_filecache_ref_t *fileref;
    uint64_t offset;
    h2o_iovec_t vec;
    struct st_h2o_evloop_read_file_cmd_t *next;
};

struct st_h2o_evloop_read_file_queue_t {
    struct st_h2o_evloop_read_file_cmd_t *head;
    struct st_h2o_evloop_read_file_cmd_t **tail;
    size_t size;
};

struct st_h2o_evloop_read_file_t {
    h2o_evloop_t *loop;
    struct io_uring uring;
    struct st_h2o_evloop_socket_t *sock_notify;
    struct st_h2o_evloop_read_file_queue_t submission, completion;
    h2o_timer_t delayed;
    /**
     * Number of read commands to issue at once. Issuance of read commands are delayed until the number of entries in the
     * submission queue reaches this value, or when the event loop runs once.
     */
    size_t batch_size;
};

#endif

static void link_to_pending(struct st_h2o_evloop_socket_t *sock);
static void link_to_statechanged(struct st_h2o_evloop_socket_t *sock);
static int write_pending(struct st_h2o_evloop_socket_t *sock);
static int write_pending_post_send_buffers(struct st_h2o_evloop_socket_t *sock);
static h2o_evloop_t *create_evloop(size_t sz);
static void update_now(h2o_evloop_t *loop);
static int32_t adjust_max_wait(h2o_evloop_t *loop, int32_t max_wait);

/* functions to be defined in the backends */
static int evloop_do_proceed(h2o_evloop_t *loop, int32_t max_wait);
static void evloop_do_dispose(h2o_evloop_t *loop);
static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock);
static int evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock);
static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock);

#if H2O_USE_IO_URING
static void read_file_queue_init(struct st_h2o_evloop_read_file_queue_t *queue);
static void read_file_on_notify(h2o_socket_t *_sock, const char *err);
static void read_file_on_delayed(h2o_timer_t *timer);
#endif

#if H2O_USE_POLL || H2O_USE_EPOLL || H2O_USE_KQUEUE
/* explicitly specified */
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define H2O_USE_KQUEUE 1
#elif defined(__linux)
#define H2O_USE_EPOLL 1
#if defined(SO_ZEROCOPY) && defined(SO_EE_ORIGIN_ZEROCOPY)
#define H2O_USE_MSG_ZEROCOPY 1
#endif
#else
#define H2O_USE_POLL 1
#endif
#endif
#if !defined(H2O_USE_MSG_ZEROCOPY)
#define H2O_USE_MSG_ZEROCOPY 0
#endif

#if H2O_USE_POLL
#include "evloop/poll.c.h"
#elif H2O_USE_EPOLL
#include "evloop/epoll.c.h"
#elif H2O_USE_KQUEUE
#include "evloop/kqueue.c.h"
#else
#error "poller not specified"
#endif

size_t h2o_evloop_socket_max_read_size = 1024 * 1024;  /* by default, we read up to 1MB at once */
size_t h2o_evloop_socket_max_write_size = 1024 * 1024; /* by default, we write up to 1MB at once */

void link_to_pending(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_next_pending == sock) {
        struct st_h2o_evloop_socket_t **slot = (sock->_flags & H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION) != 0
                                                   ? &sock->loop->_pending_as_server
                                                   : &sock->loop->_pending_as_client;
        sock->_next_pending = *slot;
        *slot = sock;
    }
}

void link_to_statechanged(struct st_h2o_evloop_socket_t *sock)
{
    if (sock->_next_statechanged == sock) {
        sock->_next_statechanged = NULL;
        *sock->loop->_statechanged.tail_ref = sock;
        sock->loop->_statechanged.tail_ref = &sock->_next_statechanged;
    }
}

static const char *on_read_core(int fd, h2o_buffer_t **input, size_t max_bytes)
{
    ssize_t read_so_far = 0;

    while (1) {
        ssize_t rret;
        h2o_iovec_t buf = h2o_buffer_try_reserve(input, max_bytes < 4096 ? max_bytes : 4096);
        if (buf.base == NULL) {
            /* memory allocation failed */
            return h2o_socket_error_out_of_memory;
        }
        size_t read_size = buf.len <= INT_MAX / 2 ? buf.len : INT_MAX / 2 + 1;
        if (read_size > max_bytes)
            read_size = max_bytes;
        while ((rret = read(fd, buf.base, read_size)) == -1 && errno == EINTR)
            ;
        if (rret == -1) {
            if (errno == EAGAIN)
                break;
            else
                return h2o_socket_error_io;
        } else if (rret == 0) {
            if (read_so_far == 0)
                return h2o_socket_error_closed; /* TODO notify close */
            break;
        }
        (*input)->size += rret;
        if (buf.len != rret)
            break;
        read_so_far += rret;
        if (read_so_far >= max_bytes)
            break;
    }
    return NULL;
}

static size_t write_vecs(struct st_h2o_evloop_socket_t *sock, h2o_iovec_t **bufs, size_t *bufcnt, int sendmsg_flags)
{
    ssize_t wret;

    while (*bufcnt != 0) {
        /* write */
        int iovcnt = *bufcnt < IOV_MAX ? (int)*bufcnt : IOV_MAX;
        struct msghdr msg;
        do {
            msg = (struct msghdr){.msg_iov = (struct iovec *)*bufs, .msg_iovlen = iovcnt};
        } while ((wret = sendmsg(sock->fd, &msg, sendmsg_flags)) == -1 && errno == EINTR);
        SOCKET_PROBE(WRITEV, &sock->super, wret);

        if (wret == -1)
            return errno == EAGAIN ? 0 : SIZE_MAX;

        /* adjust the buffer, doing the write once again only if all IOV_MAX buffers being supplied were fully written */
        while ((*bufs)->len <= wret) {
            wret -= (*bufs)->len;
            ++*bufs;
            --*bufcnt;
            if (*bufcnt == 0) {
                assert(wret == 0);
                return 0;
            }
        }
        if (wret != 0) {
            return wret;
        } else if (iovcnt < IOV_MAX) {
            return 0;
        }
    }

    return 0;
}

static void write_core_async_read_on_complete(h2o_sendvec_puller_t *puller)
{
    struct st_h2o_evloop_socket_t *sock = H2O_STRUCT_FROM_MEMBER(struct st_h2o_evloop_socket_t, super._write_buf.puller, puller);

    if (sock->super._write_buf.puller.failed) {
        write_pending_post_send_buffers(sock);
    } else {
        link_to_statechanged(sock);
        write_pending(sock);
    }
}

static size_t write_core(struct st_h2o_evloop_socket_t *sock, h2o_iovec_t **bufs, size_t *bufcnt)
{
    /* flatten given vector if that has not been done yet */
    if (!h2o_sendvec_puller_read_is_complete(&sock->super._write_buf.puller)) {
        h2o_sendvec_puller_read(&sock->super._write_buf.puller);
        if (!h2o_sendvec_puller_read_is_complete(&sock->super._write_buf.puller)) {
            sock->super._write_buf.puller.on_async_read_complete = write_core_async_read_on_complete;
            link_to_statechanged(sock); /* might need to disable the write polling */
            return 0;
        } else if (sock->super._write_buf.puller.failed) {
            return SIZE_MAX;
        }
    }

    if (sock->super.ssl == NULL || sock->super.ssl->offload == H2O_SOCKET_SSL_OFFLOAD_ON) {
        if (sock->super.ssl != NULL)
            assert(!has_pending_ssl_bytes(sock->super.ssl));
        return write_vecs(sock, bufs, bufcnt, 0);
    }

    /* continue encrypting and writing, until we run out of data */
    size_t first_buf_written = 0;
    while (1) {
        /* write bytes already encrypted, if any */
        if (has_pending_ssl_bytes(sock->super.ssl)) {
            h2o_iovec_t encbuf = h2o_iovec_init(sock->super.ssl->output.buf.base + sock->super.ssl->output.pending_off,
                                                sock->super.ssl->output.buf.off - sock->super.ssl->output.pending_off);
            h2o_iovec_t *encbufs = &encbuf;
            size_t encbufcnt = 1, enc_written;
            int sendmsg_flags = 0;
#if H2O_USE_MSG_ZEROCOPY
            /* Use zero copy if amount of data to be written is no less than 4KB, and if the memory can be returned to
             * `h2o_socket_zerocopy_buffer_allocator`. Latter is a short-cut. It is only under exceptional conditions (e.g., TLS
             * stack adding a post-handshake message) that we'd see the buffer grow to a size that cannot be returned to the
             * recycling allocator.
             * Even though https://www.kernel.org/doc/html/v5.17/networking/msg_zerocopy.html recommends 10KB, 4KB has been chosen
             * as the threshold, because we are likely to be using the non-temporal aesgcm engine and tx-nocache-copy, in which case
             * copying sendmsg is going to be more costly than what the kernel documentation assumes. In a synthetic benchmark,
             * changing from 16KB to 4KB increased the throughput by ~10%. */
            if (sock->super.ssl->output.allocated_for_zerocopy && encbuf.len >= 4096 &&
                sock->super.ssl->output.buf.capacity == h2o_socket_zerocopy_buffer_allocator.conf->memsize)
                sendmsg_flags = MSG_ZEROCOPY;
#endif
            if ((enc_written = write_vecs(sock, &encbufs, &encbufcnt, sendmsg_flags)) == SIZE_MAX) {
                dispose_ssl_output_buffer(sock->super.ssl);
                return SIZE_MAX;
            }
            if (sendmsg_flags != 0 && (encbufcnt == 0 || enc_written > 0)) {
                zerocopy_buffers_push(sock->super._zerocopy, sock->super.ssl->output.buf.base);
                if (!sock->super.ssl->output.zerocopy_owned) {
                    sock->super.ssl->output.zerocopy_owned = 1;
                    ++h2o_socket_num_zerocopy_buffers_inflight;
                }
            }
            /* if write is incomplete, record the advance and bail out */
            if (encbufcnt != 0) {
                sock->super.ssl->output.pending_off += enc_written;
                break;
            }
            /* succeeded in writing all the encrypted data; free the buffer */
            dispose_ssl_output_buffer(sock->super.ssl);
        }
        /* bail out if complete */
        if (*bufcnt == 0)
            break;
        /* convert more cleartext to TLS records if possible, or bail out on fatal error */
        if ((first_buf_written = generate_tls_records(&sock->super, bufs, bufcnt, first_buf_written)) == SIZE_MAX)
            break;
        /* as an optimization, if we have a flattened vector, release memory as soon as they have been encrypted */
        if (*bufcnt == 0) {
            assert(h2o_sendvec_puller_send_is_complete(&sock->super._write_buf.puller));
            h2o_sendvec_puller_dispose(&sock->super._write_buf.puller);
        }
    }

    return first_buf_written;
}

int write_pending(struct st_h2o_evloop_socket_t *sock)
{
    assert(sock->super._cb.write != NULL);

    /* write from buffer, if we have anything */
    if (sock->super._write_buf.cnt != 0 || has_pending_ssl_bytes(sock->super.ssl)) {
        size_t first_buf_written;
        if ((first_buf_written = write_core(sock, &sock->super._write_buf.bufs, &sock->super._write_buf.cnt)) != SIZE_MAX) {
            /* return if there's still pending data, adjusting buf[0] if necessary */
            if (sock->super._write_buf.cnt != 0) {
                sock->super._write_buf.bufs[0].base += first_buf_written;
                sock->super._write_buf.bufs[0].len -= first_buf_written;
                return 0;
            } else if (has_pending_ssl_bytes(sock->super.ssl)) {
                return 0;
            }
        }
    }

    return write_pending_post_send_buffers(sock);
}

int write_pending_post_send_buffers(struct st_h2o_evloop_socket_t *sock)
{
    /* either completed or failed */
    dispose_write_buf(&sock->super);

    /* send the vector, if all buffered writes are complete and if we have some */
    if (sock->super._write_buf.cnt == 0 && !has_pending_ssl_bytes(sock->super.ssl) &&
        !h2o_sendvec_puller_send_is_complete(&sock->super._write_buf.puller)) {
        assert(!sock->super._write_buf.puller.failed); /* if read had failed, _write_buf.cnt cannot be zero */
        h2o_sendvec_puller_send(&sock->super._write_buf.puller, sock->fd);
        if (!sock->super._write_buf.puller.failed && !h2o_sendvec_puller_send_is_complete(&sock->super._write_buf.puller))
            return 0;
    }

    /* operation completed or failed; dispose puller, schedule notification */
    SOCKET_PROBE(WRITE_COMPLETE, &sock->super, sock->super._write_buf.cnt == 0 && !has_pending_ssl_bytes(sock->super.ssl));
    h2o_sendvec_puller_dispose(&sock->super._write_buf.puller);
    sock->bytes_written.cur_loop = sock->super.bytes_written;
    sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
    link_to_pending(sock);
    link_to_statechanged(sock); /* might need to disable the write polling */

    return 1;
}

static void read_on_ready(struct st_h2o_evloop_socket_t *sock)
{
    const char *err = 0;
    size_t prev_size = sock->super.input->size;

    if ((sock->_flags & H2O_SOCKET_FLAG_DONT_READ) != 0)
        goto Notify;

    if ((err = on_read_core(sock->fd, sock->super.ssl == NULL ? &sock->super.input : &sock->super.ssl->input.encrypted,
                            sock->max_read_size)) != NULL)
        goto Notify;

    if (sock->super.ssl != NULL && sock->super.ssl->handshake.cb == NULL)
        err = decode_ssl_input(&sock->super);

Notify:
    /* the application may get notified even if no new data is avaiable.  The
     * behavior is intentional; it is designed as such so that the applications
     * can update their timeout counters when a partial SSL record arrives.
     */
    sock->super.bytes_read += sock->super.input->size - prev_size;
    sock->super._cb.read(&sock->super, err);
}

void do_dispose_socket(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    dispose_write_buf(&sock->super);

    sock->_flags = H2O_SOCKET_FLAG_IS_DISPOSED | (sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED);

    /* Give backends chance to do the necessary cleanup, as well as giving them chance to switch to their own disposal method; e.g.,
     * shutdown(SHUT_RDWR) with delays to reclaim all zero copy buffers. */
    if (evloop_do_on_socket_close(sock))
        return;

    /* immediate close */
    if (sock->fd != -1) {
        close(sock->fd);
        sock->fd = -1;
    }
    link_to_statechanged(sock);
}

void do_write(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    /* Don't write too much; if more than 1MB have been already written in the current invocation of `h2o_evloop_run`, wait until
     * the event loop notifies us that the socket is writable. */
    if (sock->bytes_written.cur_run_count != sock->loop->run_count) {
        sock->bytes_written.prev_loop = sock->bytes_written.cur_loop;
        sock->bytes_written.cur_run_count = sock->loop->run_count;
    } else if (sock->bytes_written.cur_loop - sock->bytes_written.prev_loop >= h2o_evloop_socket_max_write_size) {
        link_to_statechanged(sock);
        return;
    }

    /* write, and if the operation is incomplete, mark the socket as write-inflight */
    if (!write_pending(sock))
        link_to_statechanged(sock);
}

static int can_tls_offload(h2o_socket_t *sock)
{
#if H2O_USE_KTLS
    if (sock->ssl->offload != H2O_SOCKET_SSL_OFFLOAD_NONE && sock->ssl->ptls != NULL) {
        ptls_cipher_suite_t *cipher = ptls_get_cipher(sock->ssl->ptls);
        switch (cipher->id) {
        case PTLS_CIPHER_SUITE_AES_128_GCM_SHA256:
        case PTLS_CIPHER_SUITE_AES_256_GCM_SHA384:
            return 1;
        default:
            break;
        }
    }
#endif

    return 0;
}

#if H2O_USE_KTLS
static void switch_to_ktls(struct st_h2o_evloop_socket_t *sock)
{
    assert(sock->super.ssl->offload == H2O_SOCKET_SSL_OFFLOAD_TBD);

    /* Postpone the decision, when we are still in the early stages of the connection, as we want to use userspace TLS for
     * generating small TLS records. TODO: integrate with TLS record size calculation logic. */
    if (sock->super.bytes_written < 65536)
        return;

    /* load the key to the kernel */
    struct {
        uint8_t key[PTLS_MAX_SECRET_SIZE];
        uint8_t iv[PTLS_MAX_DIGEST_SIZE];
        uint64_t seq;
        union {
            struct tls12_crypto_info_aes_gcm_128 aesgcm128;
            struct tls12_crypto_info_aes_gcm_256 aesgcm256;
        } tx_params;
        size_t tx_params_size;
    } keys;

    /* at the moment, only TLS/1.3 connections using aes-gcm is supported */
    if (sock->super.ssl->ptls == NULL)
        goto Fail;
    ptls_cipher_suite_t *cipher = ptls_get_cipher(sock->super.ssl->ptls);
    switch (cipher->id) {
    case PTLS_CIPHER_SUITE_AES_128_GCM_SHA256:
    case PTLS_CIPHER_SUITE_AES_256_GCM_SHA384:
        break;
    default:
        goto Fail;
    }
    if (ptls_get_traffic_keys(sock->super.ssl->ptls, 1, keys.key, keys.iv, &keys.seq) != 0)
        goto Fail;
    keys.seq = htobe64(keys.seq); /* converted to big endian ASAP */

#define SETUP_TX_PARAMS(target, type)                                                                                              \
    do {                                                                                                                           \
        keys.tx_params.target.info.version = TLS_1_3_VERSION;                                                                      \
        keys.tx_params.target.info.cipher_type = type;                                                                             \
        H2O_BUILD_ASSERT(sizeof(keys.tx_params.target.key) == cipher->aead->key_size);                                             \
        memcpy(keys.tx_params.target.key, keys.key, cipher->aead->key_size);                                                       \
        H2O_BUILD_ASSERT(cipher->aead->iv_size == 12);                                                                             \
        H2O_BUILD_ASSERT(sizeof(keys.tx_params.target.salt) == 4);                                                                 \
        memcpy(keys.tx_params.target.salt, keys.iv, 4);                                                                            \
        H2O_BUILD_ASSERT(sizeof(keys.tx_params.target.iv) == 8);                                                                   \
        memcpy(keys.tx_params.target.iv, keys.iv + 4, 8);                                                                          \
        H2O_BUILD_ASSERT(sizeof(keys.tx_params.target.rec_seq) == sizeof(keys.seq));                                               \
        memcpy(keys.tx_params.target.rec_seq, &keys.seq, sizeof(keys.seq));                                                        \
        keys.tx_params_size = sizeof(keys.tx_params.target);                                                                       \
    } while (0)
    switch (cipher->id) {
    case PTLS_CIPHER_SUITE_AES_128_GCM_SHA256:
        SETUP_TX_PARAMS(aesgcm128, TLS_CIPHER_AES_GCM_128);
        break;
    case PTLS_CIPHER_SUITE_AES_256_GCM_SHA384:
        SETUP_TX_PARAMS(aesgcm256, TLS_CIPHER_AES_GCM_256);
        break;
    default:
        goto Fail;
    }
#undef SETUP_TX_PARAMS

    /* set to kernel */
    if (setsockopt(sock->fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) != 0)
        goto Fail;
    if (setsockopt(sock->fd, SOL_TLS, TLS_TX, &keys.tx_params, keys.tx_params_size) != 0)
        goto Fail;
    sock->super.ssl->offload = H2O_SOCKET_SSL_OFFLOAD_ON;

Exit:
    ptls_clear_memory(&keys, sizeof(keys));
    return;

Fail:
    sock->super.ssl->offload = H2O_SOCKET_SSL_OFFLOAD_NONE;
    goto Exit;
}
#endif

/**
 * `bufs` should be an array capable of storing `bufcnt + 1` objects, as we will be flattening `sendvec` at the end of `bufs` before
 * encryption; see `write_core`.
 */
static int can_use_sendfile(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    if (sock->super.ssl == NULL)
        return 1;

        /* If TLS in use, sendfile can be used only if kTLS is active. We attempt to turn it on here. */
#if H2O_USE_KTLS
    if (sock->super.ssl->offload == H2O_SOCKET_SSL_OFFLOAD_TBD)
        switch_to_ktls(sock);
#endif
    return sock->super.ssl->offload == H2O_SOCKET_SSL_OFFLOAD_ON;
}

int h2o_socket_get_fd(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    return sock->fd;
}

void do_read_start(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    link_to_statechanged(sock);
}

void do_read_stop(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
    link_to_statechanged(sock);
}

void h2o_socket_dont_read(h2o_socket_t *_sock, int dont_read)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;

    if (dont_read) {
        sock->_flags |= H2O_SOCKET_FLAG_DONT_READ;
    } else {
        sock->_flags &= ~H2O_SOCKET_FLAG_DONT_READ;
    }
}

int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;

    assert((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) == 0);
    evloop_do_on_socket_export(sock);
    sock->_flags = H2O_SOCKET_FLAG_IS_DISPOSED | (sock->_flags & H2O_SOCKET_FLAG__EPOLL_IS_REGISTERED);

    info->fd = sock->fd;
    sock->fd = -1;

    return 0;
}

h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    return h2o_evloop_socket_create(loop, info->fd, 0);
}

h2o_loop_t *h2o_socket_get_loop(h2o_socket_t *_sock)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    return sock->loop;
}

socklen_t get_sockname_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    socklen_t len = sizeof(struct sockaddr_storage);
    if (getsockname(sock->fd, sa, &len) != 0)
        return 0;
    return len;
}

socklen_t get_peername_uncached(h2o_socket_t *_sock, struct sockaddr *sa)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    socklen_t len = sizeof(struct sockaddr_storage);
    if (getpeername(sock->fd, sa, &len) != 0)
        return 0;
    return len;
}

static struct st_h2o_evloop_socket_t *create_socket(h2o_evloop_t *loop, int fd, int flags)
{
    struct st_h2o_evloop_socket_t *sock;

    sock = h2o_mem_alloc(sizeof(*sock));
    memset(sock, 0, sizeof(*sock));
    h2o_buffer_init(&sock->super.input, &h2o_socket_buffer_prototype);
    sock->loop = loop;
    sock->fd = fd;
    sock->_flags = flags;
    sock->max_read_size = h2o_evloop_socket_max_read_size; /* by default, we read up to 1MB at once */
    sock->_next_pending = sock;
    sock->_next_statechanged = sock;

    evloop_do_on_socket_create(sock);

    return sock;
}

/**
 * Sets TCP_NODELAY if the given file descriptor is likely to be a TCP socket. The intent of this function isto reduce number of
 * unnecessary system calls. Therefore, we skip setting TCP_NODELAY when it is certain that the socket is not a TCP socket,
 * otherwise call setsockopt.
 */
static void set_nodelay_if_likely_tcp(int fd, struct sockaddr *sa)
{
    if (sa != NULL && !(sa->sa_family == AF_INET || sa->sa_family == AF_INET6))
        return;

    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

h2o_socket_t *h2o_evloop_socket_create(h2o_evloop_t *loop, int fd, int flags)
{
    /* It is the reponsibility of the event loop to modify the properties of a socket for its use (e.g., set O_NONBLOCK). */
    fcntl(fd, F_SETFL, O_NONBLOCK);
    set_nodelay_if_likely_tcp(fd, NULL);

    return &create_socket(loop, fd, flags)->super;
}

h2o_socket_t *h2o_evloop_socket_accept(h2o_socket_t *_listener)
{
    struct st_h2o_evloop_socket_t *listener = (struct st_h2o_evloop_socket_t *)_listener;
    int fd;
    h2o_socket_t *sock;

    /* cache the remote address, if we know that we are going to use the value (in h2o_socket_ebpf_lookup_flags) */
#if H2O_USE_EBPF_MAP
    struct {
        struct sockaddr_storage storage;
        socklen_t len;
    } _peeraddr;
    _peeraddr.len = sizeof(_peeraddr.storage);
    struct sockaddr_storage *peeraddr = &_peeraddr.storage;
    socklen_t *peeraddrlen = &_peeraddr.len;
#else
    struct sockaddr_storage *peeraddr = NULL;
    socklen_t *peeraddrlen = NULL;
#endif

#if H2O_USE_ACCEPT4
    /* the anticipation here is that a socket returned by `accept4` will inherit the TCP_NODELAY flag from the listening socket */
    if ((fd = accept4(listener->fd, (struct sockaddr *)peeraddr, peeraddrlen, SOCK_NONBLOCK | SOCK_CLOEXEC)) == -1)
        return NULL;
    sock = &create_socket(listener->loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION)->super;
#else
    if ((fd = cloexec_accept(listener->fd, (struct sockaddr *)peeraddr, peeraddrlen)) == -1)
        return NULL;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    sock = &create_socket(listener->loop, fd, H2O_SOCKET_FLAG_IS_ACCEPTED_CONNECTION)->super;
#endif
    set_nodelay_if_likely_tcp(fd, (struct sockaddr *)peeraddr);

    if (peeraddr != NULL && *peeraddrlen <= sizeof(*peeraddr))
        h2o_socket_setpeername(sock, (struct sockaddr *)peeraddr, *peeraddrlen);
    uint64_t flags = h2o_socket_ebpf_lookup_flags(listener->loop, h2o_socket_ebpf_init_key, sock);
    if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) != 0)
        sock->_skip_tracing = 1;
    return sock;
}

h2o_socket_t *h2o_socket_connect(h2o_loop_t *loop, struct sockaddr *addr, socklen_t addrlen, h2o_socket_cb cb, const char **err)
{
    int fd, connect_ret;
    struct st_h2o_evloop_socket_t *sock;

    if ((fd = cloexec_socket(addr->sa_family, SOCK_STREAM, 0)) == -1) {
        if (err != NULL) {
            *err = h2o_socket_error_socket_fail;
        }
        return NULL;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);

    if (!((connect_ret = connect(fd, addr, addrlen)) == 0 || errno == EINPROGRESS)) {
        if (err != NULL)
            *err = h2o_socket_get_error_string(errno, h2o_socket_error_conn_fail);
        close(fd);
        return NULL;
    }

    sock = create_socket(loop, fd, H2O_SOCKET_FLAG_IS_CONNECTING);
    set_nodelay_if_likely_tcp(fd, addr);

    if (connect_ret == 0) {
        /* connection has been established synchronously; notify the fact without going back to epoll */
        sock->_flags |= H2O_SOCKET_FLAG_IS_WRITE_NOTIFY | H2O_SOCKET_FLAG_IS_CONNECTING_CONNECTED;
        sock->super._cb.write = cb;
        link_to_pending(sock);
    } else {
        h2o_socket_notify_write(&sock->super, cb);
    }
    return &sock->super;
}

void h2o_evloop_socket_set_max_read_size(h2o_socket_t *_sock, size_t max_size)
{
    struct st_h2o_evloop_socket_t *sock = (void *)_sock;
    sock->max_read_size = max_size;
}

h2o_evloop_t *create_evloop(size_t sz)
{
    h2o_evloop_t *loop = h2o_mem_alloc(sz);

    memset(loop, 0, sz);
    loop->_statechanged.tail_ref = &loop->_statechanged.head;
    update_now(loop);
    /* 3 levels * 32-slots => 1 second goes into 2nd, becomes O(N) above approx. 31 seconds */
    loop->_timeouts = h2o_timerwheel_create(3, loop->_now_millisec);

#if H2O_USE_IO_URING
    {
        loop->_read_file = h2o_mem_alloc(sizeof(*loop->_read_file));
        loop->_read_file->loop = loop;

        int ret;
        if ((ret = io_uring_queue_init(16, &loop->_read_file->uring, 0)) != 0)
            h2o_fatal("io_uring_queue_init:%s", strerror(-ret));

        loop->_read_file->sock_notify = create_socket(loop, loop->_read_file->uring.ring_fd, H2O_SOCKET_FLAG_DONT_READ);
        h2o_socket_read_start(&loop->_read_file->sock_notify->super, read_file_on_notify);

        read_file_queue_init(&loop->_read_file->submission);
        read_file_queue_init(&loop->_read_file->completion);
        h2o_timer_init(&loop->_read_file->delayed, read_file_on_delayed);
        loop->_read_file->batch_size = 1; /* default is to run commands one by one (hoping that it completes synchronously) */
    }
#endif

    return loop;
}

void update_now(h2o_evloop_t *loop)
{
    gettimeofday(&loop->_tv_at, NULL);
    loop->_now_nanosec = ((uint64_t)loop->_tv_at.tv_sec * 1000000 + loop->_tv_at.tv_usec) * 1000;
    loop->_now_millisec = loop->_now_nanosec / 1000000;
}

int32_t adjust_max_wait(h2o_evloop_t *loop, int32_t max_wait)
{
    uint64_t wake_at = h2o_timerwheel_get_wake_at(loop->_timeouts);

    update_now(loop);

    /* Set max_wait depending on the timers and if there's pending read / write event. Even though `h2o_evloop_run` asserts that
     * the "pending" slots are empty when exitting, applications might invoke functions that cause them to be registered outside
     * of `h2o_evloop_run`. */
    if (wake_at <= loop->_now_millisec || loop->_pending_as_client != NULL || loop->_pending_as_server != NULL) {
        max_wait = 0;
    } else {
        uint64_t delta = wake_at - loop->_now_millisec;
        if (delta < max_wait)
            max_wait = (int32_t)delta;
    }

    return max_wait;
}

void h2o_socket_notify_write(h2o_socket_t *_sock, h2o_socket_cb cb)
{
    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    assert(sock->super._cb.write == NULL);
    assert(sock->super._write_buf.cnt == 0);
    assert(!has_pending_ssl_bytes(sock->super.ssl));

    sock->super._cb.write = cb;
    link_to_statechanged(sock);
}

static void run_socket(struct st_h2o_evloop_socket_t *sock)
{
    if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
        /* is freed in updatestates phase */
        return;
    }

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_READ_READY) != 0) {
        sock->_flags &= ~H2O_SOCKET_FLAG_IS_READ_READY;
        read_on_ready(sock);
    }

    if ((sock->_flags & H2O_SOCKET_FLAG_IS_WRITE_NOTIFY) != 0) {
        const char *err = NULL;
        assert(sock->super._cb.write != NULL);
        sock->_flags &= ~H2O_SOCKET_FLAG_IS_WRITE_NOTIFY;
        if (sock->super._write_buf.cnt != 0 || has_pending_ssl_bytes(sock->super.ssl) || sock->super._write_buf.puller.failed) {
            /* error */
            err = h2o_socket_error_io;
            sock->super._write_buf.cnt = 0;
            if (has_pending_ssl_bytes(sock->super.ssl))
                dispose_ssl_output_buffer(sock->super.ssl);
        } else if ((sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING) != 0) {
            /* completion of connect; determine error if we do not know whether the connection has been successfully estabilshed */
            if ((sock->_flags & H2O_SOCKET_FLAG_IS_CONNECTING_CONNECTED) == 0) {
                int so_err = 0;
                socklen_t l = sizeof(so_err);
                so_err = 0;
                if (getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_err, &l) != 0 || so_err != 0)
                    err = h2o_socket_get_error_string(so_err, h2o_socket_error_conn_fail);
            }
            sock->_flags &= ~(H2O_SOCKET_FLAG_IS_CONNECTING | H2O_SOCKET_FLAG_IS_CONNECTING_CONNECTED);
        }
        on_write_complete(&sock->super, err);
    }
}

static void run_pending(h2o_evloop_t *loop)
{
    struct st_h2o_evloop_socket_t *sock;

    while (loop->_pending_as_server != NULL || loop->_pending_as_client != NULL) {
        while ((sock = loop->_pending_as_client) != NULL) {
            loop->_pending_as_client = sock->_next_pending;
            sock->_next_pending = sock;
            run_socket(sock);
        }
        if ((sock = loop->_pending_as_server) != NULL) {
            loop->_pending_as_server = sock->_next_pending;
            sock->_next_pending = sock;
            run_socket(sock);
        }
    }
}

void h2o_evloop_destroy(h2o_evloop_t *loop)
{
    struct st_h2o_evloop_socket_t *sock;

    /* timeouts are governed by the application and MUST be destroyed prior to destroying the loop */
    assert(h2o_timerwheel_get_wake_at(loop->_timeouts) == UINT64_MAX);

    /* dispose all socket */
    while ((sock = loop->_pending_as_client) != NULL) {
        loop->_pending_as_client = sock->_next_pending;
        sock->_next_pending = sock;
        h2o_socket_close((h2o_socket_t *)sock);
    }
    while ((sock = loop->_pending_as_server) != NULL) {
        loop->_pending_as_server = sock->_next_pending;
        sock->_next_pending = sock;
        h2o_socket_close((h2o_socket_t *)sock);
    }

    /* now all socket are disposedand and placed in linked list statechanged
     * we can freeing memory in cycle by next_statechanged,
     */
    while ((sock = loop->_statechanged.head) != NULL) {
        loop->_statechanged.head = sock->_next_statechanged;
        free(sock);
    }

    /* dispose backend-specific data */
    evloop_do_dispose(loop);

    /* lastly we need to free loop memory */
    h2o_timerwheel_destroy(loop->_timeouts);
    free(loop);
}

int h2o_evloop_run(h2o_evloop_t *loop, int32_t max_wait)
{
    ++loop->run_count;

    /* update socket states, poll, set readable flags, perform pending writes */
    if (evloop_do_proceed(loop, max_wait) != 0)
        return -1;

    /* run the pending callbacks */
    run_pending(loop);

    /* run the expired timers at the same time invoking pending callbacks for every timer callback. This is an locality
     * optimization; handles things like timeout -> write -> on_write_complete for each object. */
    while (1) {
        h2o_linklist_t expired;
        h2o_linklist_init_anchor(&expired);
        h2o_timerwheel_get_expired(loop->_timeouts, loop->_now_millisec, &expired);
        if (h2o_linklist_is_empty(&expired))
            break;
        do {
            h2o_timerwheel_entry_t *timer = H2O_STRUCT_FROM_MEMBER(h2o_timerwheel_entry_t, _link, expired.next);
            h2o_linklist_unlink(&timer->_link);
            timer->cb(timer);
            run_pending(loop);
        } while (!h2o_linklist_is_empty(&expired));
    }

    assert(loop->_pending_as_client == NULL);
    assert(loop->_pending_as_server == NULL);

    if (h2o_sliding_counter_is_running(&loop->exec_time_nanosec_counter)) {
        update_now(loop);
        h2o_sliding_counter_stop(&loop->exec_time_nanosec_counter, loop->_now_nanosec);
    }

    return 0;
}

#if H2O_USE_IO_URING

void h2o_evloop_set_io_uring_batch_size(h2o_evloop_t *loop, size_t batch_size)
{
    assert(batch_size != 0);
    loop->_read_file->batch_size = batch_size;
}

void read_file_queue_init(struct st_h2o_evloop_read_file_queue_t *queue)
{
    queue->head = NULL;
    queue->tail = &queue->head;
    queue->size = 0;
}

static void read_file_queue_insert(struct st_h2o_evloop_read_file_queue_t *queue, struct st_h2o_evloop_read_file_cmd_t *cmd)
{
    assert(cmd->next == NULL);
    *queue->tail = cmd;
    queue->tail = &cmd->next;
    ++queue->size;
}

static struct st_h2o_evloop_read_file_cmd_t *read_file_queue_pop(struct st_h2o_evloop_read_file_queue_t *queue)
{
    struct st_h2o_evloop_read_file_cmd_t *popped;

    if ((popped = queue->head) != NULL) {
        if ((queue->head = popped->next) == NULL)
            queue->tail = &queue->head;
        --queue->size;
        popped->next = NULL;
    }
    return popped;
}

static int read_file_submit(h2o_evloop_t *loop, int can_delay)
{
    if (can_delay && loop->_read_file->submission.size < loop->_read_file->batch_size)
        return 0;

    int made_progress = 0;

    while (loop->_read_file->submission.head != NULL) {
        struct io_uring_sqe *sqe;
        if ((sqe = io_uring_get_sqe(&loop->_read_file->uring)) == NULL)
            break;
        struct st_h2o_evloop_read_file_cmd_t *cmd = read_file_queue_pop(&loop->_read_file->submission);
        assert(cmd != NULL);
        io_uring_prep_read(sqe, cmd->fileref->fd, cmd->vec.base, cmd->vec.len, cmd->offset);
        sqe->user_data = (uint64_t)cmd;
        made_progress = 1;
    }

    if (made_progress) {
        int ret;
        while ((ret = io_uring_submit(&loop->_read_file->uring)) == -EINTR)
            ;
        if (ret < 0)
            h2o_fatal("io_uring_submit:%s", strerror(-ret));
    }

    return made_progress;
}

static int read_file_check_completion(h2o_evloop_t *loop, struct st_h2o_evloop_read_file_cmd_t *cmd_sync)
{
    int cmd_sync_done = 0, ret;

    while (1) {
        struct st_h2o_evloop_read_file_cmd_t *cmd;
        int res;

        { /* obtain completed command and its result */
            struct io_uring_cqe *cqe;
            while ((ret = io_uring_peek_cqe(&loop->_read_file->uring, &cqe)) == -EINTR)
                ;
            if (ret != 0)
                break;
            cmd = (struct st_h2o_evloop_read_file_cmd_t *)cqe->user_data;
            res = cqe->res;
            io_uring_cqe_seen(&loop->_read_file->uring, cqe);
        }

        /* Check error. Or if partial read, schedule read of the remainder. */
        if (res != cmd->vec.len) {
            assert(res < cmd->vec.len);
            if (res > 0) {
                cmd->offset += res;
                cmd->vec.base += res;
                cmd->vec.len -= res;
                read_file_queue_insert(&loop->_read_file->submission, cmd);
                if (!h2o_timer_is_linked(&loop->_read_file->delayed))
                    h2o_timer_link(loop, 0, &loop->_read_file->delayed);
                continue;
            } else {
                cmd->super.err = h2o_socket_error_io; /* TODO notify partial read / eos? */
            }
        }

        /* link to completion list or indicate to the caller that `cmd_sync` has completed */
        if (cmd == cmd_sync) {
            cmd_sync_done = 1;
        } else {
            read_file_queue_insert(&loop->_read_file->completion, cmd);
        }
    }

    return cmd_sync_done;
}

static int read_file_dispatch_completed(h2o_evloop_t *loop)
{
    if (loop->_read_file->completion.head == NULL)
        return 0;

    do {
        struct st_h2o_evloop_read_file_cmd_t *cmd = read_file_queue_pop(&loop->_read_file->completion);
        H2O_PROBE(SOCKET_READ_FILE_ASYNC_END, cmd);
        h2o_filecache_close_file(cmd->fileref);
        cmd->super.cb.func(&cmd->super);
        free(cmd);
    } while (loop->_read_file->completion.head != NULL);
    return 1;
}

void h2o_socket_read_file(h2o_socket_read_file_cmd_t **_cmd, h2o_loop_t *loop, h2o_filecache_ref_t *_fileref, uint64_t _offset,
                          h2o_iovec_t _dst, h2o_socket_read_file_cb _cb, void *_data)
{
    /* build command and register */
    struct st_h2o_evloop_read_file_cmd_t *cmd = h2o_mem_alloc(sizeof(*cmd));
    *cmd = (struct st_h2o_evloop_read_file_cmd_t){
        .super = {.cb = {.func = _cb, .data = _data}},
        .fileref = _fileref,
        .offset = _offset,
        .vec = _dst,
    };
    h2o_filecache_addref(cmd->fileref);
    read_file_queue_insert(&loop->_read_file->submission, cmd);

    /* Submit enqueued commands as much as possible, then read completed ones as much as possible. The hope here is that the read
     * command generated right above gets issued and completes synchronously, which would be likely when the file is buffer cache.
     * If that is the case, call the callback synchronously. */
    if (read_file_submit(loop, 1)) {
        if (read_file_check_completion(loop, cmd)) {
            h2o_filecache_close_file(cmd->fileref);
            cmd->super.cb.func(&cmd->super);
            free(cmd);
            cmd = NULL;
        }
    } else if (!h2o_timer_is_linked(&loop->_read_file->delayed)) {
        h2o_timer_link(loop, 0, &loop->_read_file->delayed);
    }

    *_cmd = &cmd->super;

    if (cmd != NULL)
        H2O_PROBE(SOCKET_READ_FILE_ASYNC_START, cmd);
}

static void read_file_run(h2o_evloop_t *loop)
{
    /* Repeatedly read cqe, until we bocome certain we haven't issued more read commands. */
    do {
        read_file_check_completion(loop, NULL);
    } while (read_file_dispatch_completed(loop) || read_file_submit(loop, 0));

    assert(loop->_read_file->completion.head == NULL);
}

void read_file_on_notify(h2o_socket_t *_sock, const char *err)
{
    assert(err == NULL);

    struct st_h2o_evloop_socket_t *sock = (struct st_h2o_evloop_socket_t *)_sock;
    h2o_evloop_t *loop = sock->loop;

    read_file_run(loop);
}

void read_file_on_delayed(h2o_timer_t *_timer)
{
    struct st_h2o_evloop_read_file_t *_read_file = H2O_STRUCT_FROM_MEMBER(struct st_h2o_evloop_read_file_t, delayed, _timer);
    h2o_evloop_t *loop = _read_file->loop;

    read_file_run(loop);
}

#endif
