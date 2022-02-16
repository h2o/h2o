/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku, Justin Zhu
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
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <openssl/err.h>
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/ioctl.h>
#endif
#include "picotls.h"
#include "quicly.h"
#include "h2o/socket.h"
#include "h2o/multithread.h"
#include "../probes_.h"

#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifndef IOV_MAX
#define IOV_MAX UIO_MAXIOV
#endif

/* kernel-headers bundled with Ubuntu 14.04 does not have the constant defined in netinet/tcp.h */
#if defined(__linux__) && !defined(TCP_NOTSENT_LOWAT)
#define TCP_NOTSENT_LOWAT 25
#endif

#if H2O_USE_DTRACE && defined(__linux__)
#define H2O_USE_EBPF_MAP 1
#endif

#define OPENSSL_HOSTNAME_VALIDATION_LINKAGE static
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#include "../../deps/ssl-conservatory/openssl/openssl_hostname_validation.c"
#pragma GCC diagnostic pop

#define SOCKET_PROBE(label, sock, ...)                                                                                             \
    do {                                                                                                                           \
        h2o_socket_t *_sock = (sock);                                                                                              \
        if (!_sock->_skip_tracing)                                                                                                 \
        H2O_PROBE(SOCKET_##label, sock, __VA_ARGS__);                                                                              \
    } while (0)

struct st_h2o_socket_ssl_t {
    SSL_CTX *ssl_ctx;
    SSL *ossl;
    ptls_t *ptls;
    int *did_write_in_read; /* used for detecting and closing the connection upon renegotiation (FIXME implement renegotiation) */
    size_t record_overhead;
    struct {
        h2o_socket_cb cb;
        union {
            struct {
                struct {
                    enum {
                        ASYNC_RESUMPTION_STATE_COMPLETE = 0, /* just pass thru */
                        ASYNC_RESUMPTION_STATE_RECORD,       /* record first input, restore SSL state if it changes to REQUEST_SENT
                                                              */
                        ASYNC_RESUMPTION_STATE_REQUEST_SENT  /* async request has been sent, and is waiting for response */
                    } state;
                    SSL_SESSION *session_data;
                } async_resumption;
            } server;
            struct {
                char *server_name;
                h2o_cache_t *session_cache;
                h2o_iovec_t session_cache_key;
                h2o_cache_hashcode_t session_cache_key_hash;
            } client;
        };
    } handshake;
    struct {
        h2o_buffer_t *encrypted;
    } input;
    /**
     * Pending TLS data to be sent.
     */
    struct {
        /**
         * This buffer is initialized when and only when pending data is stored. Otherwise, all the members are zero-cleared; see
         * `has_pending_ssl_data`.
         * To reduce the cost of repeated memory allocation, expansion, and release, this buffer points to a chunk of memory being
         * allocated from `h2o_socket_ssl_buffer_allocator` when initialized. Upon disposal, the memory chunk being used by this
         * buffer is returned to that memory pool, unless the chunk has been expanded. It is designed as such because sometimes it
         * is hard to limit the amount of TLS records being generated at once (who knows how large the server's handshake messages
         * will be, or when it has to send a KeyUpdate message?). But for most of the case, handshake messages will be smaller than
         * the default size (H2O_SOCKET_DEFAULT_SSL_BUFFER_SIZE), and application traffic will not cause expansion (see
         * * `generate_tls_records`). Therefore, the memory chunk will be recycled.
         */
        ptls_buffer_t buf;
        size_t pending_off;
    } output;
};

struct st_h2o_ssl_context_t {
    SSL_CTX *ctx;
    const h2o_iovec_t *protocols;
    h2o_iovec_t _npn_list_of_protocols;
};

/* backend functions */
static void init_write_buf(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, size_t first_buf_written);
static void dispose_write_buf(h2o_socket_t *sock);
static void dispose_ssl_output_buffer(struct st_h2o_socket_ssl_t *ssl);
static int has_pending_ssl_bytes(struct st_h2o_socket_ssl_t *ssl);
static size_t generate_tls_records(h2o_socket_t *sock, h2o_iovec_t **bufs, size_t *bufcnt, size_t first_buf_written);
static void do_dispose_socket(h2o_socket_t *sock);
static void do_write(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
static void do_read_start(h2o_socket_t *sock);
static void do_read_stop(h2o_socket_t *sock);
static int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info);
static h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info);
static socklen_t get_peername_uncached(h2o_socket_t *sock, struct sockaddr *sa);
static socklen_t get_sockname_uncached(h2o_socket_t *sock, struct sockaddr *sa);

/* internal functions called from the backend */
static const char *decode_ssl_input(h2o_socket_t *sock);
static void on_write_complete(h2o_socket_t *sock, const char *err);

#if H2O_USE_LIBUV
#include "socket/uv-binding.c.h"
#else
#include "socket/evloop.c.h"
#endif

h2o_buffer_mmap_settings_t h2o_socket_buffer_mmap_settings = {
    32 * 1024 * 1024, /* 32MB, should better be greater than max frame size of HTTP2 for performance reasons */
    "/tmp/h2o.b.XXXXXX"};

h2o_buffer_prototype_t h2o_socket_buffer_prototype = {
    {H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE}, /* minimum initial capacity; actual initial size is ~8KB, see h2o_buffer_reserve */
    &h2o_socket_buffer_mmap_settings};

size_t h2o_socket_ssl_buffer_size = H2O_SOCKET_DEFAULT_SSL_BUFFER_SIZE;
__thread h2o_mem_recycle_t h2o_socket_ssl_buffer_allocator = {1024};

const char h2o_socket_error_out_of_memory[] = "out of memory";
const char h2o_socket_error_io[] = "I/O error";
const char h2o_socket_error_closed[] = "socket closed by peer";
const char h2o_socket_error_conn_fail[] = "connection failure";
const char h2o_socket_error_conn_refused[] = "connection refused";
const char h2o_socket_error_conn_timed_out[] = "connection timed out";
const char h2o_socket_error_network_unreachable[] = "network unreachable";
const char h2o_socket_error_host_unreachable[] = "host unreachable";
const char h2o_socket_error_socket_fail[] = "socket creation failed";
const char h2o_socket_error_ssl_no_cert[] = "no certificate";
const char h2o_socket_error_ssl_cert_invalid[] = "invalid certificate";
const char h2o_socket_error_ssl_cert_name_mismatch[] = "certificate name mismatch";
const char h2o_socket_error_ssl_decode[] = "SSL decode error";
const char h2o_socket_error_ssl_handshake[] = "ssl handshake failure";

static void (*resumption_get_async)(h2o_socket_t *sock, h2o_iovec_t session_id);
static void (*resumption_new)(h2o_socket_t *sock, h2o_iovec_t session_id, h2o_iovec_t session_data);

static int read_bio(BIO *b, char *out, int len)
{
    h2o_socket_t *sock = BIO_get_data(b);

    if (len == 0)
        return 0;

    if (sock->ssl->input.encrypted->size == 0) {
        BIO_set_retry_read(b);
        return -1;
    }

    if (sock->ssl->input.encrypted->size < len) {
        len = (int)sock->ssl->input.encrypted->size;
    }
    memcpy(out, sock->ssl->input.encrypted->bytes, len);
    h2o_buffer_consume(&sock->ssl->input.encrypted, len);

    return len;
}

static void init_write_buf(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, size_t first_buf_written)
{
    if (bufcnt < PTLS_ELEMENTSOF(sock->_write_buf.smallbufs)) {
        sock->_write_buf.bufs = sock->_write_buf.smallbufs;
    } else {
        sock->_write_buf.bufs = h2o_mem_alloc(sizeof(sock->_write_buf.bufs[0]) * bufcnt);
        sock->_write_buf.alloced_ptr = sock->_write_buf.bufs;
    }
    if (bufcnt != 0) {
        sock->_write_buf.bufs[0].base = bufs[0].base + first_buf_written;
        sock->_write_buf.bufs[0].len = bufs[0].len - first_buf_written;
        for (size_t i = 1; i < bufcnt; ++i)
            sock->_write_buf.bufs[i] = bufs[i];
    }
    sock->_write_buf.cnt = bufcnt;
}

static void dispose_write_buf(h2o_socket_t *sock)
{
    if (sock->_write_buf.smallbufs <= sock->_write_buf.bufs &&
        sock->_write_buf.bufs <=
            sock->_write_buf.smallbufs + sizeof(sock->_write_buf.smallbufs) / sizeof(sock->_write_buf.smallbufs[0])) {
        /* no need to free */
    } else {
        free(sock->_write_buf.alloced_ptr);
        sock->_write_buf.bufs = sock->_write_buf.smallbufs;
    }
}

static void init_ssl_output_buffer(struct st_h2o_socket_ssl_t *ssl)
{
    ptls_buffer_init(&ssl->output.buf, h2o_mem_alloc_recycle(&h2o_socket_ssl_buffer_allocator, h2o_socket_ssl_buffer_size),
                     h2o_socket_ssl_buffer_size);
    ssl->output.buf.is_allocated = 1; /* set to true, so that the allocated memory is freed when the buffer is expanded */
    ssl->output.pending_off = 0;
}

static void dispose_ssl_output_buffer(struct st_h2o_socket_ssl_t *ssl)
{
    /* The destruction logic that we have here are different from `ptls_buffer_dispose` in following two aspects:
     * - returns the allocated memory to the pool if possible
     * - does not zero-clear the memory (there's no need to, because the content is something to be sent in clear) */

    assert(ssl->output.buf.is_allocated);

    if (ssl->output.buf.capacity == h2o_socket_ssl_buffer_size) {
        h2o_mem_free_recycle(&h2o_socket_ssl_buffer_allocator, ssl->output.buf.base);
    } else {
        free(ssl->output.buf.base);
    }
    ssl->output.buf = (ptls_buffer_t){};
    ssl->output.pending_off = 0;
}

static int has_pending_ssl_bytes(struct st_h2o_socket_ssl_t *ssl)
{
    /* for convenience, this function can be invoked for non-TLS connections too, in which case ssl will be NULL */
    if (ssl == NULL)
        return 0;

    /* the contract is that `dispose_ssl_output_buffer` is called immediately when all the data are written out */
    return ssl->output.buf.base != NULL;
}

static void write_ssl_bytes(h2o_socket_t *sock, const void *in, size_t len)
{
    if (len != 0) {
        if (!has_pending_ssl_bytes(sock->ssl))
            init_ssl_output_buffer(sock->ssl);
        if (ptls_buffer_reserve(&sock->ssl->output.buf, len) != 0)
            h2o_fatal("no memory; tried to allocate %zu bytes", len);
        memcpy(sock->ssl->output.buf.base + sock->ssl->output.buf.off, in, len);
        sock->ssl->output.buf.off += len;
    }
}

static int write_bio(BIO *b, const char *in, int len)
{
    h2o_socket_t *sock = BIO_get_data(b);

    /* FIXME no support for SSL renegotiation (yet) */
    if (sock->ssl->did_write_in_read != NULL) {
        *sock->ssl->did_write_in_read = 1;
        return -1;
    }

    write_ssl_bytes(sock, in, len);
    return len;
}

static int puts_bio(BIO *b, const char *str)
{
    return write_bio(b, str, (int)strlen(str));
}

static long ctrl_bio(BIO *b, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_GET_CLOSE:
        return BIO_get_shutdown(b);
    case BIO_CTRL_SET_CLOSE:
        BIO_set_shutdown(b, (int)num);
        return 1;
    case BIO_CTRL_FLUSH:
        return 1;
    default:
        return 0;
    }
}

static void setup_bio(h2o_socket_t *sock)
{
    static BIO_METHOD *volatile bio_methods = NULL;
    H2O_MULTITHREAD_ONCE({
        bio_methods = BIO_meth_new(BIO_TYPE_FD, "h2o_socket");
        BIO_meth_set_write(bio_methods, write_bio);
        BIO_meth_set_read(bio_methods, read_bio);
        BIO_meth_set_puts(bio_methods, puts_bio);
        BIO_meth_set_ctrl(bio_methods, ctrl_bio);
    });

    BIO *bio = BIO_new(bio_methods);
    if (bio == NULL)
        h2o_fatal("no memory");
    BIO_set_data(bio, sock);
    BIO_set_init(bio, 1);
    SSL_set_bio(sock->ssl->ossl, bio, bio);
}

const char *decode_ssl_input(h2o_socket_t *sock)
{
    assert(sock->ssl != NULL);
    assert(sock->ssl->handshake.cb == NULL);

    if (sock->ssl->ptls != NULL) {
        if (sock->ssl->input.encrypted->size != 0) {
            const char *src = sock->ssl->input.encrypted->bytes, *src_end = src + sock->ssl->input.encrypted->size;
            h2o_iovec_t reserved;
            ptls_buffer_t rbuf;
            int ret;
            if ((reserved = h2o_buffer_try_reserve(&sock->input, sock->ssl->input.encrypted->size)).base == NULL)
                return h2o_socket_error_out_of_memory;
            ptls_buffer_init(&rbuf, reserved.base, reserved.len);
            do {
                size_t consumed = src_end - src;
                if ((ret = ptls_receive(sock->ssl->ptls, &rbuf, src, &consumed)) != 0)
                    break;
                src += consumed;
            } while (src != src_end);
            h2o_buffer_consume(&sock->ssl->input.encrypted, sock->ssl->input.encrypted->size - (src_end - src));
            if (rbuf.is_allocated) {
                if ((reserved = h2o_buffer_try_reserve(&sock->input, rbuf.off)).base == NULL)
                    return h2o_socket_error_out_of_memory;
                memcpy(reserved.base, rbuf.base, rbuf.off);
                sock->input->size += rbuf.off;
                ptls_buffer_dispose(&rbuf);
            } else {
                sock->input->size += rbuf.off;
            }
            if (!(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
                return h2o_socket_error_ssl_decode;
        }
        return NULL;
    }

    while (sock->ssl->input.encrypted->size != 0 || SSL_pending(sock->ssl->ossl)) {
        int rlen;
        h2o_iovec_t buf = h2o_buffer_try_reserve(&sock->input, 4096);
        if (buf.base == NULL)
            return h2o_socket_error_out_of_memory;
        { /* call SSL_read (while detecting SSL renegotiation and reporting it as error) */
            int did_write_in_read = 0;
            sock->ssl->did_write_in_read = &did_write_in_read;
            ERR_clear_error();
            rlen = SSL_read(sock->ssl->ossl, buf.base, (int)buf.len);
            sock->ssl->did_write_in_read = NULL;
            if (did_write_in_read)
                return "ssl renegotiation not supported";
        }
        if (rlen == -1) {
            if (SSL_get_error(sock->ssl->ossl, rlen) != SSL_ERROR_WANT_READ) {
                return h2o_socket_error_ssl_decode;
            }
            break;
        } else if (rlen == 0) {
            break;
        } else {
            sock->input->size += rlen;
        }
    }

    return 0;
}

static void flush_pending_ssl(h2o_socket_t *sock, h2o_socket_cb cb)
{
    do_write(sock, NULL, 0, cb);
}

static void destroy_ssl(struct st_h2o_socket_ssl_t *ssl)
{
    if (ssl->ptls != NULL) {
        ptls_free(ssl->ptls);
        ssl->ptls = NULL;
    }
    if (ssl->ossl != NULL) {
        if (!SSL_is_server(ssl->ossl)) {
            free(ssl->handshake.client.server_name);
            free(ssl->handshake.client.session_cache_key.base);
        }
        SSL_free(ssl->ossl);
        ssl->ossl = NULL;
    }
    h2o_buffer_dispose(&ssl->input.encrypted);
    if (has_pending_ssl_bytes(ssl))
        dispose_ssl_output_buffer(ssl);
    free(ssl);
}

static void dispose_socket(h2o_socket_t *sock, const char *err)
{
    void (*close_cb)(void *data);
    void *close_cb_data;

    if (sock->ssl != NULL) {
        destroy_ssl(sock->ssl);
        sock->ssl = NULL;
    }
    h2o_buffer_dispose(&sock->input);
    if (sock->_peername != NULL) {
        free(sock->_peername);
        sock->_peername = NULL;
    }
    if (sock->_sockname != NULL) {
        free(sock->_sockname);
        sock->_sockname = NULL;
    }

    close_cb = sock->on_close.cb;
    close_cb_data = sock->on_close.data;

    do_dispose_socket(sock);

    if (close_cb != NULL)
        close_cb(close_cb_data);
}

static void shutdown_ssl(h2o_socket_t *sock, const char *err)
{
    if (err != NULL)
        goto Close;

    if (sock->_cb.write != NULL) {
        /* note: libuv calls the write callback after the socket is closed by uv_close (with status set to 0 if the write succeeded)
         */
        sock->_cb.write = NULL;
        goto Close;
    }

    if (sock->ssl->ptls != NULL) {
        ptls_buffer_t wbuf;
        uint8_t wbuf_small[32];
        ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
        if (ptls_send_alert(sock->ssl->ptls, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY) != 0)
            goto Close;
        write_ssl_bytes(sock, wbuf.base, wbuf.off);
        ptls_buffer_dispose(&wbuf);
    } else if (sock->ssl->ossl != NULL) {
        ERR_clear_error();
        if (SSL_shutdown(sock->ssl->ossl) == -1)
            goto Close;
    } else {
        goto Close;
    }

    if (has_pending_ssl_bytes(sock->ssl)) {
        h2o_socket_read_stop(sock);
        flush_pending_ssl(sock, dispose_socket);
        return;
    }

Close:
    dispose_socket(sock, err);
}

void h2o_socket_dispose_export(h2o_socket_export_t *info)
{
    assert(info->fd != -1);
    if (info->ssl != NULL) {
        destroy_ssl(info->ssl);
        info->ssl = NULL;
    }
    h2o_buffer_dispose(&info->input);
    close(info->fd);
    info->fd = -1;
}

int h2o_socket_export(h2o_socket_t *sock, h2o_socket_export_t *info)
{
    static h2o_buffer_prototype_t nonpooling_prototype;

    assert(!h2o_socket_is_writing(sock));

    if (do_export(sock, info) == -1)
        return -1;

    if ((info->ssl = sock->ssl) != NULL) {
        sock->ssl = NULL;
        h2o_buffer_set_prototype(&info->ssl->input.encrypted, &nonpooling_prototype);
    }
    info->input = sock->input;
    h2o_buffer_set_prototype(&info->input, &nonpooling_prototype);
    h2o_buffer_init(&sock->input, &h2o_socket_buffer_prototype);

    h2o_socket_close(sock);

    return 0;
}

h2o_socket_t *h2o_socket_import(h2o_loop_t *loop, h2o_socket_export_t *info)
{
    h2o_socket_t *sock;

    assert(info->fd != -1);

    sock = do_import(loop, info);
    info->fd = -1; /* just in case */
    if ((sock->ssl = info->ssl) != NULL) {
        setup_bio(sock);
        h2o_buffer_set_prototype(&sock->ssl->input.encrypted, &h2o_socket_buffer_prototype);
    }
    sock->input = info->input;
    h2o_buffer_set_prototype(&sock->input, &h2o_socket_buffer_prototype);
    return sock;
}

void h2o_socket_close(h2o_socket_t *sock)
{
    if (sock->ssl == NULL) {
        dispose_socket(sock, 0);
    } else {
        shutdown_ssl(sock, 0);
    }
}

static uint16_t calc_suggested_tls_payload_size(h2o_socket_t *sock, uint16_t suggested_tls_record_size)
{
    uint16_t ps = suggested_tls_record_size;
    if (sock->ssl != NULL && sock->ssl->record_overhead < ps)
        ps -= sock->ssl->record_overhead;
    return ps;
}

static void disable_latency_optimized_write(h2o_socket_t *sock, int (*adjust_notsent_lowat)(h2o_socket_t *, unsigned))
{
    if (sock->_latency_optimization.notsent_is_minimized) {
        adjust_notsent_lowat(sock, 0);
        sock->_latency_optimization.notsent_is_minimized = 0;
    }
    sock->_latency_optimization.state = H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DISABLED;
    sock->_latency_optimization.suggested_tls_payload_size = SIZE_MAX;
    sock->_latency_optimization.suggested_write_size = SIZE_MAX;
}

static inline void prepare_for_latency_optimized_write(h2o_socket_t *sock,
                                                       const h2o_socket_latency_optimization_conditions_t *conditions, uint32_t rtt,
                                                       uint32_t mss, uint32_t cwnd_size, uint32_t cwnd_avail, uint64_t loop_time,
                                                       int (*adjust_notsent_lowat)(h2o_socket_t *, unsigned))
{
    /* check RTT */
    if (rtt < conditions->min_rtt * (uint64_t)1000)
        goto Disable;
    if (rtt * conditions->max_additional_delay < loop_time * 1000 * 100)
        goto Disable;

    /* latency-optimization is enabled */
    sock->_latency_optimization.state = H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DETERMINED;

    /* no need to:
     *   1) adjust the write size if single_write_size << cwnd_size
     *   2) align TLS record boundary to TCP packet boundary if packet loss-rate is low and BW isn't small (implied by cwnd size)
     */
    if (mss * cwnd_size < conditions->max_cwnd) {
        if (!sock->_latency_optimization.notsent_is_minimized) {
            if (adjust_notsent_lowat(sock, 1 /* cannot be set to zero on Linux */) != 0)
                goto Disable;
            sock->_latency_optimization.notsent_is_minimized = 1;
        }
        sock->_latency_optimization.suggested_tls_payload_size = calc_suggested_tls_payload_size(sock, mss);
        sock->_latency_optimization.suggested_write_size =
            cwnd_avail * (size_t)sock->_latency_optimization.suggested_tls_payload_size;
    } else {
        if (sock->_latency_optimization.notsent_is_minimized) {
            if (adjust_notsent_lowat(sock, 0) != 0)
                goto Disable;
            sock->_latency_optimization.notsent_is_minimized = 0;
        }
        sock->_latency_optimization.suggested_tls_payload_size = SIZE_MAX;
        sock->_latency_optimization.suggested_write_size = SIZE_MAX;
    }
    return;

Disable:
    disable_latency_optimized_write(sock, adjust_notsent_lowat);
}

/**
 * Obtains RTT, MSS, size of CWND (in the number of packets).
 * Also writes to cwnd_avail minimum number of packets (of MSS size) sufficient to shut up poll-for-write under the precondition
 * that TCP_NOTSENT_LOWAT is set to 1.
 */
static int obtain_tcp_info(int fd, uint32_t *rtt, uint32_t *mss, uint32_t *cwnd_size, uint32_t *cwnd_avail)
{
#define CALC_CWND_PAIR_FROM_BYTE_UNITS(cwnd_bytes, inflight_bytes)                                                                 \
    do {                                                                                                                           \
        *cwnd_size = (cwnd_bytes + *mss / 2) / *mss;                                                                               \
        *cwnd_avail = cwnd_bytes > inflight_bytes ? (cwnd_bytes - inflight_bytes) / *mss + 2 : 2;                                  \
    } while (0)

#if defined(__linux__) && defined(TCP_INFO)

    struct tcp_info tcpi;
    socklen_t tcpisz = sizeof(tcpi);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcpi, &tcpisz) != 0)
        return -1;
    *rtt = tcpi.tcpi_rtt;
    *mss = tcpi.tcpi_snd_mss;
    *cwnd_size = tcpi.tcpi_snd_cwnd;
    *cwnd_avail = tcpi.tcpi_snd_cwnd > tcpi.tcpi_unacked ? tcpi.tcpi_snd_cwnd - tcpi.tcpi_unacked + 2 : 2;
    return 0;

#elif defined(__FreeBSD__) && defined(TCP_INFO) && 0 /* disabled since we wouldn't use it anyways; OS lacks TCP_NOTSENT_LOWAT */

    struct tcp_info tcpi;
    socklen_t tcpisz = sizeof(tcpi);
    int bytes_inflight;
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcpi, &tcpisz) != 0 || ioctl(fd, FIONWRITE, &bytes_inflight) == -1)
        return -1;
    *rtt = tcpi.tcpi_rtt;
    *mss = tcpi.tcpi_snd_mss;
    CALC_CWND_PAIR_FROM_BYTE_UNITS(tcpi.tcpi_snd_cwnd, bytes_inflight);
    return 0;

#elif defined(__APPLE__) && defined(TCP_CONNECTION_INFO)

    struct tcp_connection_info tcpi;
    socklen_t tcpisz = sizeof(tcpi);
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &tcpi, &tcpisz) != 0 || tcpi.tcpi_maxseg == 0)
        return -1;
    *rtt = tcpi.tcpi_srtt * 1000;
    *mss = tcpi.tcpi_maxseg;
    CALC_CWND_PAIR_FROM_BYTE_UNITS(tcpi.tcpi_snd_cwnd, tcpi.tcpi_snd_sbbytes);
    return 0;

#else
    /* TODO add support for NetBSD; note that the OS returns the number of packets for tcpi_snd_cwnd; see
     * http://twitter.com/n_soda/status/740719125878575105
     */
    return -1;
#endif

#undef CALC_CWND_PAIR_FROM_BYTE_UNITS
}

#ifdef TCP_NOTSENT_LOWAT
static int adjust_notsent_lowat(h2o_socket_t *sock, unsigned notsent_lowat)
{
    return setsockopt(h2o_socket_get_fd(sock), IPPROTO_TCP, TCP_NOTSENT_LOWAT, &notsent_lowat, sizeof(notsent_lowat));
}
#else
#define adjust_notsent_lowat NULL
#endif

size_t h2o_socket_do_prepare_for_latency_optimized_write(h2o_socket_t *sock,
                                                         const h2o_socket_latency_optimization_conditions_t *conditions)
{
    uint32_t rtt = 0, mss = 0, cwnd_size = 0, cwnd_avail = 0;
    uint64_t loop_time = UINT64_MAX;
    int can_prepare = 1;

#if !defined(TCP_NOTSENT_LOWAT)
    /* the feature cannot be setup unless TCP_NOTSENT_LOWAT is available */
    can_prepare = 0;
#endif

#if H2O_USE_LIBUV
    /* poll-then-write is impossible with libuv */
    can_prepare = 0;
#else
    if (can_prepare)
        loop_time = h2o_evloop_get_execution_time_millisec(h2o_socket_get_loop(sock));
#endif

    /* obtain TCP states */
    if (can_prepare && obtain_tcp_info(h2o_socket_get_fd(sock), &rtt, &mss, &cwnd_size, &cwnd_avail) != 0)
        can_prepare = 0;

    /* determine suggested_write_size, suggested_tls_record_size and adjust TCP_NOTSENT_LOWAT based on the obtained information */
    if (can_prepare) {
        prepare_for_latency_optimized_write(sock, conditions, rtt, mss, cwnd_size, cwnd_avail, loop_time, adjust_notsent_lowat);
    } else {
        disable_latency_optimized_write(sock, adjust_notsent_lowat);
    }

    return sock->_latency_optimization.suggested_write_size;

#undef CALC_CWND_PAIR_FROM_BYTE_UNITS
}

static size_t calc_tls_write_size(h2o_socket_t *sock, size_t bufsize)
{
    size_t recsize;

    /* set recsize to the maximum TLS record size by using the latency optimizer, or if the optimizer is not in action, based on the
     * number of bytes that have already been sent */
    switch (sock->_latency_optimization.state) {
    case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD:
    case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DISABLED:
        recsize = sock->bytes_written < 64 * 1024 ? calc_suggested_tls_payload_size(sock, 1400) : SIZE_MAX;
        break;
    case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DETERMINED:
        sock->_latency_optimization.state = H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE;
    /* fallthru */
    default:
        recsize = sock->_latency_optimization.suggested_tls_payload_size;
        break;
    }

    return recsize < bufsize ? recsize : bufsize;
}

/**
 * Given a vector, generate at least one TLS record if there's enough space in the buffer, and return the size of application data
 * being encrypted. Otherwise, returns zero.
 */
static size_t generate_tls_records_from_one_vec(h2o_socket_t *sock, const void *input, size_t inlen)
{
    static const size_t MAX_RECORD_PAYLOAD_SIZE = 16 * 1024, LARGE_RECORD_OVERHEAD = 5 + 32;

    size_t tls_write_size = calc_tls_write_size(sock, inlen);
    size_t space_left = sock->ssl->output.buf.capacity - sock->ssl->output.buf.off;

    if (tls_write_size < inlen) {
        /* Writing small TLS records, one by one. Bail out if we might fail to do so. */
        if (space_left < tls_write_size + LARGE_RECORD_OVERHEAD)
            return 0;
    } else {
        /* Writing full-sized records. Adjust tls_write_size to a multiple of full-sized TLS records, or bail out if we cannot
         * write one. */
        size_t rec_capacity = space_left / (MAX_RECORD_PAYLOAD_SIZE + LARGE_RECORD_OVERHEAD);
        if (rec_capacity == 0)
            return 0;
        tls_write_size = MAX_RECORD_PAYLOAD_SIZE * rec_capacity;
        if (tls_write_size > inlen)
            tls_write_size = inlen;
    }

    /* Generate TLS record(s). */
    if (sock->ssl->ptls != NULL) {
        int ret = ptls_send(sock->ssl->ptls, &sock->ssl->output.buf, input, tls_write_size);
        assert(ret == 0);
    } else {
        int ret = SSL_write(sock->ssl->ossl, input, (int)tls_write_size);
        /* The error happens if SSL_write is called after SSL_read returns a fatal error (e.g. due to corrupt TCP packet being
         * received). We might be converting more and more TLS records on this side as read errors occur. */
        if (ret <= 0)
            return SIZE_MAX;
        assert(ret == tls_write_size);
    }

    SOCKET_PROBE(WRITE_TLS_RECORD, sock, tls_write_size, sock->ssl->output.buf.off);
    return tls_write_size;
}

/**
 * Generate as many TLS records as possible, given a list of vectors. Upon return, `*bufs` and `*bufcnt` will be updated to point
 * the buffers that still have pending data, and the number of bytes being already written within `(*buf)[0]` will be returned.
 */
static size_t generate_tls_records(h2o_socket_t *sock, h2o_iovec_t **bufs, size_t *bufcnt, size_t first_buf_written)
{
    assert(!has_pending_ssl_bytes(sock->ssl) && "we are filling encrypted bytes from the front, with no existing buffer, always");

    while (*bufcnt != 0) {
        if ((*bufs)->len == 0) {
            ++*bufs;
            --*bufcnt;
            continue;
        }
        if (!has_pending_ssl_bytes(sock->ssl))
            init_ssl_output_buffer(sock->ssl);
        size_t bytes_newly_written =
            generate_tls_records_from_one_vec(sock, (*bufs)->base + first_buf_written, (*bufs)->len - first_buf_written);
        if (bytes_newly_written == SIZE_MAX) {
            return SIZE_MAX;
        } else if (bytes_newly_written == 0) {
            break;
        }
        first_buf_written += bytes_newly_written;
        if ((*bufs)->len == first_buf_written) {
            first_buf_written = 0;
            ++*bufs;
            --*bufcnt;
        }
    }

    return first_buf_written;
}

void h2o_socket_write(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    SOCKET_PROBE(WRITE, sock, bufs, bufcnt, cb);

    assert(sock->_cb.write == NULL);

    for (size_t i = 0; i != bufcnt; ++i) {
        sock->bytes_written += bufs[i].len;
#if H2O_SOCKET_DUMP_WRITE
        h2o_error_printf("writing %zu bytes to fd:%d\n", bufs[i].len, h2o_socket_get_fd(sock));
        h2o_dump_memory(stderr, bufs[i].base, bufs[i].len);
#endif
    }

    do_write(sock, bufs, bufcnt, cb);
}

void on_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_socket_cb cb;

    if (has_pending_ssl_bytes(sock->ssl))
        dispose_ssl_output_buffer(sock->ssl);

    cb = sock->_cb.write;
    sock->_cb.write = NULL;
    cb(sock, err);
}

void h2o_socket_read_start(h2o_socket_t *sock, h2o_socket_cb cb)
{
    sock->_cb.read = cb;
    do_read_start(sock);
}

void h2o_socket_read_stop(h2o_socket_t *sock)
{
    sock->_cb.read = NULL;
    do_read_stop(sock);
}

void h2o_socket_setpeername(h2o_socket_t *sock, struct sockaddr *sa, socklen_t len)
{
    free(sock->_peername);
    sock->_peername = h2o_mem_alloc(offsetof(struct st_h2o_socket_addr_t, addr) + len);
    sock->_peername->len = len;
    memcpy(&sock->_peername->addr, sa, len);
}

socklen_t h2o_socket_getpeername(h2o_socket_t *sock, struct sockaddr *sa)
{
    /* return cached, if exists */
    if (sock->_peername != NULL) {
        memcpy(sa, &sock->_peername->addr, sock->_peername->len);
        return sock->_peername->len;
    }
    /* call, copy to cache, and return */
    socklen_t len = get_peername_uncached(sock, sa);
    h2o_socket_setpeername(sock, sa, len);
    return len;
}

socklen_t h2o_socket_getsockname(h2o_socket_t *sock, struct sockaddr *sa)
{
    /* return cached, if exists */
    if (sock->_sockname != NULL) {
        memcpy(sa, &sock->_sockname->addr, sock->_sockname->len);
        return sock->_sockname->len;
    }
    /* call, copy to cache, and return */
    socklen_t len = get_sockname_uncached(sock, sa);
    sock->_sockname = h2o_mem_alloc(offsetof(struct st_h2o_socket_addr_t, addr) + len);
    sock->_sockname->len = len;
    memcpy(&sock->_sockname->addr, sa, len);
    return len;
}

ptls_t *h2o_socket_get_ptls(h2o_socket_t *sock)
{
    return sock->ssl != NULL ? sock->ssl->ptls : NULL;
}

const char *h2o_socket_get_ssl_protocol_version(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
        if (sock->ssl->ptls != NULL)
            return "TLSv1.3";
        if (sock->ssl->ossl != NULL)
            return SSL_get_version(sock->ssl->ossl);
    }
    return NULL;
}

int h2o_socket_get_ssl_session_reused(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
        if (sock->ssl->ptls != NULL)
            return ptls_is_psk_handshake(sock->ssl->ptls);
        if (sock->ssl->ossl != NULL)
            return (int)SSL_session_reused(sock->ssl->ossl);
    }
    return -1;
}

const char *h2o_socket_get_ssl_cipher(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
        if (sock->ssl->ptls != NULL) {
            ptls_cipher_suite_t *cipher = ptls_get_cipher(sock->ssl->ptls);
            if (cipher != NULL)
                return cipher->aead->name;
        } else if (sock->ssl->ossl != NULL) {
            return SSL_get_cipher_name(sock->ssl->ossl);
        }
    }
    return NULL;
}

int h2o_socket_get_ssl_cipher_bits(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
        if (sock->ssl->ptls != NULL) {
            ptls_cipher_suite_t *cipher = ptls_get_cipher(sock->ssl->ptls);
            if (cipher == NULL)
                return 0;
            return (int)cipher->aead->key_size;
        } else if (sock->ssl->ossl != NULL) {
            return SSL_get_cipher_bits(sock->ssl->ossl, NULL);
        }
    }
    return 0;
}

h2o_iovec_t h2o_socket_get_ssl_session_id(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
        if (sock->ssl->ptls != NULL) {
            /* FIXME */
        } else if (sock->ssl->ossl != NULL) {
            SSL_SESSION *session;
            if (sock->ssl->handshake.server.async_resumption.state == ASYNC_RESUMPTION_STATE_COMPLETE &&
                (session = SSL_get_session(sock->ssl->ossl)) != NULL) {
                unsigned id_len;
                const unsigned char *id = SSL_SESSION_get_id(session, &id_len);
                return h2o_iovec_init(id, id_len);
            }
        }
    }

    return h2o_iovec_init(NULL, 0);
}

const char *h2o_socket_get_ssl_server_name(const h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
        if (sock->ssl->ptls != NULL) {
            return ptls_get_server_name(sock->ssl->ptls);
        } else if (sock->ssl->ossl != NULL) {
            return SSL_get_servername(sock->ssl->ossl, TLSEXT_NAMETYPE_host_name);
        }
    }
    return NULL;
}

h2o_iovec_t h2o_socket_log_tcp_congestion_controller(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
#if defined(TCP_CONGESTION)
    int fd;
    if ((fd = h2o_socket_get_fd(sock)) >= 0) {
#define CC_BUFSIZE 32
        socklen_t buflen = CC_BUFSIZE;
        char *buf = pool != NULL ? h2o_mem_alloc_pool(pool, *buf, buflen) : h2o_mem_alloc(buflen);
        if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, buf, &buflen) == 0) {
            /* Upon return, linux sets `buflen` to some value greater than the size of the string. Therefore, we apply strlen after
             * making sure that the result does not overrun the buffer. */
            buf[CC_BUFSIZE - 1] = '\0';
            return h2o_iovec_init(buf, strlen(buf));
        }
#undef CC_BUFSIZE
    }
#endif
    return h2o_iovec_init(NULL, 0);
}

h2o_iovec_t h2o_socket_log_tcp_delivery_rate(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
#if defined(__linux__) && defined(TCP_INFO)
    int fd;
    if ((fd = h2o_socket_get_fd(sock)) >= 0) {
        /* A copy of `struct tcp_info` found in linux/tcp.h, up to `tcpi_delivery_rate`. Rest of the codebase uses netinet/tcp.h,
         * which does not provide access to `tcpi_delivery_rate`. */
        struct {
            uint8_t tcpi_state;
            uint8_t tcpi_ca_state;
            uint8_t tcpi_retransmits;
            uint8_t tcpi_probes;
            uint8_t tcpi_backoff;
            uint8_t tcpi_options;
            uint8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
            uint8_t tcpi_delivery_rate_app_limited : 1;

            uint32_t tcpi_rto;
            uint32_t tcpi_ato;
            uint32_t tcpi_snd_mss;
            uint32_t tcpi_rcv_mss;

            uint32_t tcpi_unacked;
            uint32_t tcpi_sacked;
            uint32_t tcpi_lost;
            uint32_t tcpi_retrans;
            uint32_t tcpi_fackets;

            /* Times. */
            uint32_t tcpi_last_data_sent;
            uint32_t tcpi_last_ack_sent; /* Not remembered, sorry. */
            uint32_t tcpi_last_data_recv;
            uint32_t tcpi_last_ack_recv;

            /* Metrics. */
            uint32_t tcpi_pmtu;
            uint32_t tcpi_rcv_ssthresh;
            uint32_t tcpi_rtt;
            uint32_t tcpi_rttvar;
            uint32_t tcpi_snd_ssthresh;
            uint32_t tcpi_snd_cwnd;
            uint32_t tcpi_advmss;
            uint32_t tcpi_reordering;

            uint32_t tcpi_rcv_rtt;
            uint32_t tcpi_rcv_space;

            uint32_t tcpi_total_retrans;

            uint64_t tcpi_pacing_rate;
            uint64_t tcpi_max_pacing_rate;
            uint64_t tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
            uint64_t tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
            uint32_t tcpi_segs_out;       /* RFC4898 tcpEStatsPerfSegsOut */
            uint32_t tcpi_segs_in;        /* RFC4898 tcpEStatsPerfSegsIn */

            uint32_t tcpi_notsent_bytes;
            uint32_t tcpi_min_rtt;
            uint32_t tcpi_data_segs_in;  /* RFC4898 tcpEStatsDataSegsIn */
            uint32_t tcpi_data_segs_out; /* RFC4898 tcpEStatsDataSegsOut */

            uint64_t tcpi_delivery_rate;
        } tcpi;
        socklen_t tcpisz = sizeof(tcpi);
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcpi, &tcpisz) == 0) {
            char *buf = (char *)(pool != NULL ? h2o_mem_alloc_pool(pool, char, sizeof(H2O_UINT64_LONGEST_STR))
                                              : h2o_mem_alloc(sizeof(H2O_UINT64_LONGEST_STR)));
            size_t len = sprintf(buf, "%" PRIu64, (uint64_t)tcpi.tcpi_delivery_rate);
            return h2o_iovec_init(buf, len);
        }
    }
#endif
    return h2o_iovec_init(NULL, 0);
}

h2o_iovec_t h2o_socket_log_ssl_session_id(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    h2o_iovec_t base64id, rawid = h2o_socket_get_ssl_session_id(sock);

    if (rawid.base == NULL)
        return h2o_iovec_init(NULL, 0);

    base64id.base = pool != NULL ? h2o_mem_alloc_pool(pool, char, h2o_base64_encode_capacity(rawid.len))
                                 : h2o_mem_alloc(h2o_base64_encode_capacity(rawid.len));
    base64id.len = h2o_base64_encode(base64id.base, rawid.base, rawid.len, 1);
    return base64id;
}

h2o_iovec_t h2o_socket_log_ssl_cipher_bits(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    int bits = h2o_socket_get_ssl_cipher_bits(sock);
    if (bits != 0) {
        char *s = (char *)(pool != NULL ? h2o_mem_alloc_pool(pool, char, sizeof(H2O_INT16_LONGEST_STR))
                                        : h2o_mem_alloc(sizeof(H2O_INT16_LONGEST_STR)));
        size_t len = sprintf(s, "%" PRId16, (int16_t)bits);
        return h2o_iovec_init(s, len);
    } else {
        return h2o_iovec_init(NULL, 0);
    }
}

int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y, int check_port)
{
#define CMP(a, b)                                                                                                                  \
    do {                                                                                                                           \
        if (a != b)                                                                                                                \
            return a < b ? -1 : 1;                                                                                                 \
    } while (0)

    CMP(x->sa_family, y->sa_family);

    if (x->sa_family == AF_UNIX) {
        struct sockaddr_un *xun = (void *)x, *yun = (void *)y;
        int r = strcmp(xun->sun_path, yun->sun_path);
        if (r != 0)
            return r;
    } else if (x->sa_family == AF_INET) {
        struct sockaddr_in *xin = (void *)x, *yin = (void *)y;
        CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
        if (check_port)
            CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
    } else if (x->sa_family == AF_INET6) {
        struct sockaddr_in6 *xin6 = (void *)x, *yin6 = (void *)y;
        int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
        if (r != 0)
            return r;
        if (check_port)
            CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
        CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
        CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
    } else {
        assert(!"unknown sa_family");
    }

#undef CMP
    return 0;
}

size_t h2o_socket_getnumerichost(const struct sockaddr *sa, socklen_t salen, char *buf)
{
    if (sa->sa_family == AF_INET) {
        /* fast path for IPv4 addresses */
        struct sockaddr_in *sin = (void *)sa;
        uint32_t addr;
        addr = htonl(sin->sin_addr.s_addr);
        return sprintf(buf, "%d.%d.%d.%d", addr >> 24, (addr >> 16) & 255, (addr >> 8) & 255, addr & 255);
    }

    if (getnameinfo(sa, salen, buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
        return SIZE_MAX;
    return strlen(buf);
}

int32_t h2o_socket_getport(const struct sockaddr *sa)
{
    switch (sa->sa_family) {
    case AF_INET:
        return htons(((struct sockaddr_in *)sa)->sin_port);
    case AF_INET6:
        return htons(((struct sockaddr_in6 *)sa)->sin6_port);
    default:
        return -1;
    }
}

const char *h2o_socket_get_error_string(int errnum, const char *default_err)
{
    switch (errnum) {
    case ECONNREFUSED:
        return h2o_socket_error_conn_refused;
    case ETIMEDOUT:
        return h2o_socket_error_conn_timed_out;
    case ENETUNREACH:
        return h2o_socket_error_network_unreachable;
    case EHOSTUNREACH:
        return h2o_socket_error_host_unreachable;
    default:
        return default_err;
    }
}

static void create_ossl(h2o_socket_t *sock)
{
    sock->ssl->ossl = SSL_new(sock->ssl->ssl_ctx);
    /* set app data to be used in h2o_socket_ssl_new_session_cb */
    SSL_set_app_data(sock->ssl->ossl, sock);
    setup_bio(sock);
}

static SSL_SESSION *on_async_resumption_get(SSL *ssl,
#if !defined(LIBRESSL_VERSION_NUMBER) ? OPENSSL_VERSION_NUMBER >= 0x1010000fL : LIBRESSL_VERSION_NUMBER > 0x2070000f
                                            const
#endif
                                            unsigned char *data,
                                            int len, int *copy)
{
    h2o_socket_t *sock = BIO_get_data(SSL_get_rbio(ssl));

    switch (sock->ssl->handshake.server.async_resumption.state) {
    case ASYNC_RESUMPTION_STATE_RECORD:
        sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_REQUEST_SENT;
        resumption_get_async(sock, h2o_iovec_init(data, len));
        return NULL;
    case ASYNC_RESUMPTION_STATE_COMPLETE:
        *copy = 1;
        return sock->ssl->handshake.server.async_resumption.session_data;
    default:
        assert(!"FIXME");
        return NULL;
    }
}

int h2o_socket_ssl_new_session_cb(SSL *s, SSL_SESSION *sess)
{
    h2o_socket_t *sock = (h2o_socket_t *)SSL_get_app_data(s);
    assert(sock != NULL);
    assert(sock->ssl != NULL);

    if (!SSL_is_server(s) && sock->ssl->handshake.client.session_cache != NULL
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x1010100fL
        && SSL_SESSION_is_resumable(sess)
#endif
    ) {
        h2o_cache_set(sock->ssl->handshake.client.session_cache, h2o_now(h2o_socket_get_loop(sock)),
                      sock->ssl->handshake.client.session_cache_key, sock->ssl->handshake.client.session_cache_key_hash,
                      h2o_iovec_init(sess, 1));
        return 1; /* retain ref count */
    }

    return 0; /* drop ref count */
}

static int on_async_resumption_new(SSL *ssl, SSL_SESSION *session)
{
    h2o_socket_t *sock = BIO_get_data(SSL_get_rbio(ssl));

    h2o_iovec_t data;
    const unsigned char *id;
    unsigned id_len;
    unsigned char *p;

    /* build data */
    data.len = i2d_SSL_SESSION(session, NULL);
    data.base = alloca(data.len);
    p = (void *)data.base;
    i2d_SSL_SESSION(session, &p);

    id = SSL_SESSION_get_id(session, &id_len);
    resumption_new(sock, h2o_iovec_init(id, id_len), data);
    return 0;
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    if (err == NULL) {
        if (sock->ssl->ptls != NULL) {
            sock->ssl->record_overhead = ptls_get_record_overhead(sock->ssl->ptls);
        } else {
            const SSL_CIPHER *cipher = SSL_get_current_cipher(sock->ssl->ossl);
            switch (SSL_CIPHER_get_id(cipher)) {
            case TLS1_CK_RSA_WITH_AES_128_GCM_SHA256:
            case TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256:
            case TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            case TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            case TLS1_CK_RSA_WITH_AES_256_GCM_SHA384:
            case TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384:
            case TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            case TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
                sock->ssl->record_overhead = 5 /* header */ + 8 /* record_iv_length (RFC 5288 3) */ + 16 /* tag (RFC 5116 5.1) */;
                break;
#if defined(TLS1_CK_DHE_RSA_CHACHA20_POLY1305)
            case TLS1_CK_DHE_RSA_CHACHA20_POLY1305:
            case TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305:
            case TLS1_CK_ECDHE_ECDSA_CHACHA20_POLY1305:
                sock->ssl->record_overhead = 5 /* header */ + 16 /* tag */;
                break;
#endif
            default:
                sock->ssl->record_overhead = 32; /* sufficiently large number that can hold most payloads */
                break;
            }
        }
    }

    h2o_socket_cb handshake_cb = sock->ssl->handshake.cb;
    sock->_cb.write = NULL;
    sock->ssl->handshake.cb = NULL;
    if (err == NULL)
        err = decode_ssl_input(sock);
    handshake_cb(sock, err);
}

const char *get_handshake_error(struct st_h2o_socket_ssl_t *ssl)
{
    const char *err = h2o_socket_error_ssl_handshake;
    if (ssl->ossl != NULL) {
        long verify_result = SSL_get_verify_result(ssl->ossl);
        if (verify_result != X509_V_OK) {
            err = X509_verify_cert_error_string(verify_result);
            assert(err != NULL);
        }
    }
    return err;
}

static void on_handshake_fail_complete(h2o_socket_t *sock, const char *err)
{
    on_handshake_complete(sock, get_handshake_error(sock->ssl));
}

static void proceed_handshake(h2o_socket_t *sock, const char *err);

static void proceed_handshake_picotls(h2o_socket_t *sock)
{
    size_t consumed = sock->ssl->input.encrypted->size;
    ptls_buffer_t wbuf;
    ptls_buffer_init(&wbuf, "", 0);

    int ret = ptls_handshake(sock->ssl->ptls, &wbuf, sock->ssl->input.encrypted->bytes, &consumed, NULL);
    h2o_buffer_consume(&sock->ssl->input.encrypted, consumed);

    /* determine the next action */
    h2o_socket_cb next_cb;
    switch (ret) {
    case 0:
        next_cb = on_handshake_complete;
        break;
    case PTLS_ERROR_IN_PROGRESS:
        next_cb = proceed_handshake;
        break;
    default:
        next_cb = on_handshake_fail_complete;
        break;
    }

    /* When something is to be sent, send it and then take the next action. If there's nothing to be sent and the handshake is still
     * in progress, wait for more bytes to arrive; otherwise, take the action immediately. */
    if (wbuf.off != 0) {
        h2o_socket_read_stop(sock);
        write_ssl_bytes(sock, wbuf.base, wbuf.off);
        flush_pending_ssl(sock, next_cb);
    } else if (ret == PTLS_ERROR_IN_PROGRESS) {
        h2o_socket_read_start(sock, next_cb);
    } else {
        next_cb(sock, NULL);
    }

    ptls_buffer_dispose(&wbuf);
}

static void proceed_handshake_openssl(h2o_socket_t *sock)
{
    h2o_iovec_t first_input = {NULL};
    int ret = 0;
    const char *err = NULL;

    assert(sock->ssl->ossl != NULL);

    if (SSL_is_server(sock->ssl->ossl) && sock->ssl->handshake.server.async_resumption.state == ASYNC_RESUMPTION_STATE_RECORD) {
        if (sock->ssl->input.encrypted->size <= 1024) {
            /* retain a copy of input if performing async resumption */
            first_input = h2o_iovec_init(alloca(sock->ssl->input.encrypted->size), sock->ssl->input.encrypted->size);
            memcpy(first_input.base, sock->ssl->input.encrypted->bytes, first_input.len);
        } else {
            sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
        }
    }

Redo:
    ERR_clear_error();
    if (SSL_is_server(sock->ssl->ossl)) {
        ret = SSL_accept(sock->ssl->ossl);
        switch (sock->ssl->handshake.server.async_resumption.state) {
        case ASYNC_RESUMPTION_STATE_COMPLETE:
            break;
        case ASYNC_RESUMPTION_STATE_RECORD:
            /* async resumption has not been triggered; proceed the state to complete */
            sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
            break;
        case ASYNC_RESUMPTION_STATE_REQUEST_SENT: {
            /* sent async request, reset the ssl state, and wait for async response */
            assert(ret < 0);
            SSL_free(sock->ssl->ossl);
            create_ossl(sock);
            if (has_pending_ssl_bytes(sock->ssl))
                dispose_ssl_output_buffer(sock->ssl);
            h2o_buffer_consume(&sock->ssl->input.encrypted, sock->ssl->input.encrypted->size);
            h2o_buffer_reserve(&sock->ssl->input.encrypted, first_input.len);
            memcpy(sock->ssl->input.encrypted->bytes, first_input.base, first_input.len);
            sock->ssl->input.encrypted->size = first_input.len;
            h2o_socket_read_stop(sock);
            return;
        }
        default:
            h2o_fatal("unexpected async resumption state");
            break;
        }
    } else {
        ret = SSL_connect(sock->ssl->ossl);
    }

    if (ret == 0 || (ret < 0 && SSL_get_error(sock->ssl->ossl, ret) != SSL_ERROR_WANT_READ)) {
        /* OpenSSL 1.1.0 emits an alert immediately, we  send it now. 1.0.2 emits the error when SSL_shutdown is called in
         * shutdown_ssl. */
        if (has_pending_ssl_bytes(sock->ssl)) {
            h2o_socket_read_stop(sock);
            flush_pending_ssl(sock, on_handshake_fail_complete);
            return;
        }
        err = get_handshake_error(sock->ssl);
        goto Complete;
    }

    if (has_pending_ssl_bytes(sock->ssl)) {
        h2o_socket_read_stop(sock);
        flush_pending_ssl(sock, ret == 1 ? on_handshake_complete : proceed_handshake);
    } else {
        if (ret == 1) {
            if (!SSL_is_server(sock->ssl->ossl)) {
                X509 *cert = SSL_get_peer_certificate(sock->ssl->ossl);
                if (cert != NULL) {
                    switch (validate_hostname(sock->ssl->handshake.client.server_name, cert)) {
                    case MatchFound:
                        /* ok */
                        break;
                    case MatchNotFound:
                        err = h2o_socket_error_ssl_cert_name_mismatch;
                        break;
                    default:
                        err = h2o_socket_error_ssl_cert_invalid;
                        break;
                    }
                    X509_free(cert);
                } else {
                    err = h2o_socket_error_ssl_no_cert;
                }
            }
            goto Complete;
        }
        if (sock->ssl->input.encrypted->size != 0) {
            goto Redo;
        }
        h2o_socket_read_start(sock, proceed_handshake);
    }
    return;

Complete:
    h2o_socket_read_stop(sock);
    on_handshake_complete(sock, err);
}

/**
 * Called when it is still uncertain which of the two TLS stacks (picotls or OpenSSL) should handle the handshake.
 * The function first tries picotls without consuming the socket input buffer. Then, if picotls returns PTLS_ALERT_PROTOCOL_VERSION
 * indicating that the client is using TLS 1.2 or below, switches to using OpenSSL.
 */
static void proceed_handshake_undetermined(h2o_socket_t *sock)
{
    assert(sock->ssl->ossl == NULL && sock->ssl->ptls == NULL);

    ptls_context_t *ptls_ctx = h2o_socket_ssl_get_picotls_context(sock->ssl->ssl_ctx);
    assert(ptls_ctx != NULL);

    size_t consumed = sock->ssl->input.encrypted->size;
    ptls_buffer_t wbuf;
    ptls_buffer_init(&wbuf, "", 0);

#if PICOTLS_USE_DTRACE
    unsigned ptls_skip_tracing_backup = ptls_default_skip_tracing;
    ptls_default_skip_tracing = sock->_skip_tracing;
#endif
    ptls_t *ptls = ptls_new(ptls_ctx, 1);
#if PICOTLS_USE_DTRACE
    ptls_default_skip_tracing = ptls_skip_tracing_backup;
#endif
    if (ptls == NULL)
        h2o_fatal("no memory");
    *ptls_get_data_ptr(ptls) = sock;
    int ret = ptls_handshake(ptls, &wbuf, sock->ssl->input.encrypted->bytes, &consumed, NULL);

    if (ret == PTLS_ERROR_IN_PROGRESS && wbuf.off == 0) {
        /* we aren't sure if the picotls can process the handshake, retain handshake transcript and replay on next occasion */
        ptls_free(ptls);
    } else if (ret == PTLS_ALERT_PROTOCOL_VERSION) {
        /* the client cannot use tls1.3, fallback to openssl */
        ptls_free(ptls);
        create_ossl(sock);
        proceed_handshake_openssl(sock);
    } else {
        /* picotls is responsible for handling the handshake */
        sock->ssl->ptls = ptls;
        sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
        h2o_buffer_consume(&sock->ssl->input.encrypted, consumed);
        /* stop reading, send response */
        h2o_socket_read_stop(sock);
        write_ssl_bytes(sock, wbuf.base, wbuf.off);
        h2o_socket_cb cb;
        switch (ret) {
        case 0:
            cb = on_handshake_complete;
            break;
        case PTLS_ERROR_IN_PROGRESS:
            cb = proceed_handshake;
            break;
        default:
            assert(ret != PTLS_ERROR_STATELESS_RETRY && "stateless retry is never turned on by us for TCP");
            cb = on_handshake_fail_complete;
            break;
        }
        flush_pending_ssl(sock, cb);
    }
    ptls_buffer_dispose(&wbuf);
}

static void proceed_handshake(h2o_socket_t *sock, const char *err)
{
    sock->_cb.write = NULL;

    if (err != NULL) {
        h2o_socket_read_stop(sock);
        on_handshake_complete(sock, err);
        return;
    }

    if (sock->ssl->ptls != NULL) {
        proceed_handshake_picotls(sock);
    } else if (sock->ssl->ossl != NULL) {
        proceed_handshake_openssl(sock);
    } else if (h2o_socket_ssl_get_picotls_context(sock->ssl->ssl_ctx) == NULL) {
        create_ossl(sock);
        proceed_handshake_openssl(sock);
    } else {
        proceed_handshake_undetermined(sock);
    }
}

void h2o_socket_ssl_handshake(h2o_socket_t *sock, SSL_CTX *ssl_ctx, const char *server_name, h2o_iovec_t alpn_protos,
                              h2o_socket_cb handshake_cb)
{
    sock->ssl = h2o_mem_alloc(sizeof(*sock->ssl));
    *sock->ssl = (struct st_h2o_socket_ssl_t){};

    sock->ssl->ssl_ctx = ssl_ctx;

    /* setup the buffers; sock->input should be empty, sock->ssl->input.encrypted should contain the initial input, if any */
    h2o_buffer_init(&sock->ssl->input.encrypted, &h2o_socket_buffer_prototype);
    if (sock->input->size != 0) {
        h2o_buffer_t *tmp = sock->input;
        sock->input = sock->ssl->input.encrypted;
        sock->ssl->input.encrypted = tmp;
    }

    sock->ssl->handshake.cb = handshake_cb;
    if (server_name == NULL) {
        /* is server */
        if (SSL_CTX_sess_get_get_cb(sock->ssl->ssl_ctx) != NULL)
            sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_RECORD;
        if (sock->ssl->input.encrypted->size != 0)
            proceed_handshake(sock, 0);
        else
            h2o_socket_read_start(sock, proceed_handshake);
    } else {
        create_ossl(sock);
        if (alpn_protos.base != NULL)
            SSL_set_alpn_protos(sock->ssl->ossl, (const unsigned char *)alpn_protos.base, (unsigned)alpn_protos.len);
        h2o_cache_t *session_cache = h2o_socket_ssl_get_session_cache(sock->ssl->ssl_ctx);
        if (session_cache != NULL) {
            struct sockaddr_storage sa;
            int32_t port;
            if (h2o_socket_getpeername(sock, (struct sockaddr *)&sa) != 0 &&
                (port = h2o_socket_getport((struct sockaddr *)&sa)) != -1) {
                /* session cache is available */
                h2o_iovec_t session_cache_key;
                session_cache_key.base = h2o_mem_alloc(strlen(server_name) + sizeof(":" H2O_UINT16_LONGEST_STR));
                session_cache_key.len = sprintf(session_cache_key.base, "%s:%" PRIu16, server_name, (uint16_t)port);
                sock->ssl->handshake.client.session_cache = session_cache;
                sock->ssl->handshake.client.session_cache_key = session_cache_key;
                sock->ssl->handshake.client.session_cache_key_hash =
                    h2o_cache_calchash(session_cache_key.base, session_cache_key.len);

                /* fetch from session cache */
                h2o_cache_ref_t *cacheref = h2o_cache_fetch(session_cache, h2o_now(h2o_socket_get_loop(sock)),
                                                            sock->ssl->handshake.client.session_cache_key,
                                                            sock->ssl->handshake.client.session_cache_key_hash);
                if (cacheref != NULL) {
                    SSL_set_session(sock->ssl->ossl, (SSL_SESSION *)cacheref->value.base);
                    h2o_cache_release(session_cache, cacheref);
                }
            }
        }
        sock->ssl->handshake.client.server_name = h2o_strdup(NULL, server_name, SIZE_MAX).base;
        SSL_set_tlsext_host_name(sock->ssl->ossl, sock->ssl->handshake.client.server_name);
        proceed_handshake(sock, 0);
    }
}

void h2o_socket_ssl_resume_server_handshake(h2o_socket_t *sock, h2o_iovec_t session_data)
{
    if (session_data.len != 0) {
        const unsigned char *p = (void *)session_data.base;
        sock->ssl->handshake.server.async_resumption.session_data = d2i_SSL_SESSION(NULL, &p, (long)session_data.len);
        /* FIXME warn on failure */
    }

    sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
    proceed_handshake(sock, 0);

    if (sock->ssl->handshake.server.async_resumption.session_data != NULL) {
        SSL_SESSION_free(sock->ssl->handshake.server.async_resumption.session_data);
        sock->ssl->handshake.server.async_resumption.session_data = NULL;
    }
}

void h2o_socket_ssl_async_resumption_init(h2o_socket_ssl_resumption_get_async_cb get_async_cb,
                                          h2o_socket_ssl_resumption_new_cb new_cb)
{
    resumption_get_async = get_async_cb;
    resumption_new = new_cb;
}

void h2o_socket_ssl_async_resumption_setup_ctx(SSL_CTX *ctx)
{
    SSL_CTX_sess_set_get_cb(ctx, on_async_resumption_get);
    SSL_CTX_sess_set_new_cb(ctx, on_async_resumption_new);
    /* if necessary, it is the responsibility of the caller to disable the internal cache */
}

static int get_ptls_index(void)
{
    static volatile int index;
    H2O_MULTITHREAD_ONCE({ index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL); });
    return index;
}

ptls_context_t *h2o_socket_ssl_get_picotls_context(SSL_CTX *ossl)
{
    return SSL_CTX_get_ex_data(ossl, get_ptls_index());
}

void h2o_socket_ssl_set_picotls_context(SSL_CTX *ossl, ptls_context_t *ptls)
{
    SSL_CTX_set_ex_data(ossl, get_ptls_index(), ptls);
}

static void on_dispose_ssl_ctx_session_cache(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    h2o_cache_t *ssl_session_cache = (h2o_cache_t *)ptr;
    if (ssl_session_cache != NULL)
        h2o_cache_destroy(ssl_session_cache);
}

static int get_ssl_session_cache_index(void)
{
    static volatile int index;
    H2O_MULTITHREAD_ONCE({ index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, on_dispose_ssl_ctx_session_cache); });
    return index;
}

h2o_cache_t *h2o_socket_ssl_get_session_cache(SSL_CTX *ctx)
{
    return (h2o_cache_t *)SSL_CTX_get_ex_data(ctx, get_ssl_session_cache_index());
}

void h2o_socket_ssl_set_session_cache(SSL_CTX *ctx, h2o_cache_t *cache)
{
    SSL_CTX_set_ex_data(ctx, get_ssl_session_cache_index(), cache);
}

void h2o_socket_ssl_destroy_session_cache_entry(h2o_iovec_t value)
{
    SSL_SESSION *session = (SSL_SESSION *)value.base;
    SSL_SESSION_free(session);
}

h2o_iovec_t h2o_socket_ssl_get_selected_protocol(h2o_socket_t *sock)
{
    const unsigned char *data = NULL;
    unsigned len = 0;

    if (sock->ssl == NULL)
        return h2o_iovec_init(NULL, 0);

    if (sock->ssl->ptls != NULL) {
        const char *proto = ptls_get_negotiated_protocol(sock->ssl->ptls);
        return proto != NULL ? h2o_iovec_init(proto, strlen(proto)) : h2o_iovec_init(NULL, 0);
    }

#if H2O_USE_ALPN
    if (len == 0)
        SSL_get0_alpn_selected(sock->ssl->ossl, &data, &len);
#endif
#if H2O_USE_NPN
    if (len == 0)
        SSL_get0_next_proto_negotiated(sock->ssl->ossl, &data, &len);
#endif

    return h2o_iovec_init(data, len);
}

int h2o_socket_ssl_is_early_data(h2o_socket_t *sock)
{
    assert(sock->ssl != NULL);

    if (sock->ssl->ptls != NULL && !ptls_handshake_is_complete(sock->ssl->ptls))
        return 1;
    return 0;
}

static int on_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *_in, unsigned int inlen,
                          void *_protocols)
{
    const h2o_iovec_t *protocols = _protocols;
    size_t i;

    for (i = 0; protocols[i].len != 0; ++i) {
        const unsigned char *in = _in, *in_end = in + inlen;
        while (in != in_end) {
            size_t cand_len = *in++;
            if (in_end - in < cand_len) {
                /* broken request */
                return SSL_TLSEXT_ERR_NOACK;
            }
            if (cand_len == protocols[i].len && memcmp(in, protocols[i].base, cand_len) == 0) {
                goto Found;
            }
            in += cand_len;
        }
    }
    /* not found */
    return SSL_TLSEXT_ERR_NOACK;

Found:
    *out = (const unsigned char *)protocols[i].base;
    *outlen = (unsigned char)protocols[i].len;
    return SSL_TLSEXT_ERR_OK;
}

#if H2O_USE_ALPN

void h2o_ssl_register_alpn_protocols(SSL_CTX *ctx, const h2o_iovec_t *protocols)
{
    SSL_CTX_set_alpn_select_cb(ctx, on_alpn_select, (void *)protocols);
}

#endif

#if H2O_USE_NPN

static int on_npn_advertise(SSL *ssl, const unsigned char **out, unsigned *outlen, void *protocols)
{
    *out = protocols;
    *outlen = (unsigned)strlen(protocols);
    return SSL_TLSEXT_ERR_OK;
}

void h2o_ssl_register_npn_protocols(SSL_CTX *ctx, const char *protocols)
{
    SSL_CTX_set_next_protos_advertised_cb(ctx, on_npn_advertise, (void *)protocols);
}

#endif

int h2o_socket_set_df_bit(int fd, int domain)
{
#define SETSOCKOPT(ip, optname, _optvar)                                                                                           \
    do {                                                                                                                           \
        int optvar = _optvar;                                                                                                      \
        if (setsockopt(fd, ip, optname, &optvar, sizeof(optvar)) != 0) {                                                           \
            perror("failed to set the DF bit through setsockopt(" H2O_TO_STR(ip) ", " H2O_TO_STR(optname) ")");                    \
            return 0;                                                                                                              \
        }                                                                                                                          \
        return 1;                                                                                                                  \
    } while (0)

    switch (domain) {
    case AF_INET:
#if defined(IP_PMTUDISC_DO)
        SETSOCKOPT(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO);
#elif defined(IP_DONTFRAG)
        SETSOCKOPT(IPPROTO_IP, IP_DONTFRAG, 1);
#endif
        break;
    case AF_INET6:
#if defined(IPV6_PMTUDISC_DO)
        SETSOCKOPT(IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO);
#elif defined(IPV6_DONTFRAG)
        SETSOCKOPT(IPPROTO_IPV6, IPV6_DONTFRAG, 1);
#endif
        break;
    default:
        break;
    }

    return 1;

#undef SETSOCKOPT
}

void h2o_socket_set_skip_tracing(h2o_socket_t *sock, int skip_tracing)
{
    sock->_skip_tracing = skip_tracing;
    if (sock->ssl != NULL && sock->ssl->ptls != NULL)
        ptls_set_skip_tracing(sock->ssl->ptls, skip_tracing);
}

void h2o_sliding_counter_stop(h2o_sliding_counter_t *counter, uint64_t now)
{
    uint64_t elapsed;

    assert(counter->cur.start_at != 0);

    /* calculate the time used, and reset cur */
    if (now <= counter->cur.start_at)
        elapsed = 0;
    else
        elapsed = now - counter->cur.start_at;
    counter->cur.start_at = 0;

    /* adjust prev */
    counter->prev.sum += elapsed;
    counter->prev.sum -= counter->prev.slots[counter->prev.index];
    counter->prev.slots[counter->prev.index] = elapsed;
    if (++counter->prev.index >= sizeof(counter->prev.slots) / sizeof(counter->prev.slots[0]))
        counter->prev.index = 0;

    /* recalc average */
    counter->average = counter->prev.sum / (sizeof(counter->prev.slots) / sizeof(counter->prev.slots[0]));
}

#if H2O_USE_EBPF_MAP
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/stat.h>
#include "h2o/multithread.h"
#include "h2o-probes.h"

static int ebpf_map_create(uint32_t map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, const char *map_name)
{
    union bpf_attr attr = {
        .map_type = map_type,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entries,
    };
    strncpy(attr.map_name, map_name, sizeof(attr.map_name));
    return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int ebpf_obj_pin(int bpf_fd, const char *pathname)
{
    union bpf_attr attr = {
        .bpf_fd = (uint32_t)bpf_fd,
        .pathname = (uint64_t)pathname,
    };
    return syscall(SYS_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

static int ebpf_obj_get(const char *pathname)
{
    union bpf_attr attr = {
        .pathname = (uint64_t)pathname,
    };
    return syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int ebpf_obj_get_info_by_fd(int fd, struct bpf_map_info *info)
{
    union bpf_attr attr = {
        .info =
            {
                .bpf_fd = fd,
                .info = (uint64_t)info,
                .info_len = sizeof(*info),
            },
    };
    return syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
}

static int ebpf_map_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
        .value = (uint64_t)value,
    };
    return syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int ebpf_map_delete(int fd, const void *key)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key = (uint64_t)key,
    };
    return syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int return_map_fd = -1; // for h2o_return

int h2o_socket_ebpf_setup(void)
{
    const struct {
        int type;
        uint32_t key_size;
        uint32_t value_size;
    } map_attr = {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(pid_t),
        .value_size = sizeof(uint64_t),
    };

    int fd = -1;
    if (getuid() != 0) {
        h2o_error_printf("failed to set up eBPF maps because bpf(2) requires root privileges\n");
        goto Error;
    }

    fd = ebpf_obj_get(H2O_EBPF_RETURN_MAP_PATH);
    if (fd < 0) {
        if (errno != ENOENT) {
            h2o_perror("BPF_OBJ_GET failed");
            goto Error;
        }
        /* Pinned eBPF map does not exist. Create one and pin it to the BPF filesystem. */
        fd = ebpf_map_create(map_attr.type, map_attr.key_size, map_attr.value_size, H2O_EBPF_RETURN_MAP_SIZE,
                             H2O_EBPF_RETURN_MAP_NAME);
        if (fd < 0) {
            if (errno == EPERM) {
                h2o_error_printf("BPF_MAP_CREATE failed with EPERM, maybe because RLIMIT_MEMLOCK is too small.\n");
            } else {
                h2o_perror("BPF_MAP_CREATE failed");
            }
            goto Error;
        }
        if (ebpf_obj_pin(fd, H2O_EBPF_RETURN_MAP_PATH) != 0) {
            if (errno == ENOENT) {
                h2o_error_printf("BPF_OBJ_PIN failed with ENOENT, because /sys/fs/bpf is not mounted as a BPF filesystem.\n");
            } else {
                h2o_perror("BPF_OBJ_PIN failed");
            }
            goto Error;
        }
    } else {
        /* BPF_OBJ_GET successfully opened a pinned eBPF map. Make sure the critical attributes (type, key size, value size) are
         * correct, otherwise usdt-selective-tracing does not work. */
        struct bpf_map_info m;
        if (ebpf_obj_get_info_by_fd(fd, &m) != 0) {
            h2o_perror("BPF_OBJ_GET_INFO_BY_FD failed");
            goto Error;
        }
        if (m.type != map_attr.type) {
            h2o_error_printf(H2O_EBPF_RETURN_MAP_PATH " has an unexpected map type: expected %d but got %d\n", map_attr.type,
                             m.type);
            goto Error;
        }
        if (m.key_size != map_attr.key_size) {
            h2o_error_printf(H2O_EBPF_RETURN_MAP_PATH " has an unexpected map key size: expected %" PRIu32 " but got %" PRIu32 "\n",
                             map_attr.key_size, m.key_size);
            goto Error;
        }
        if (m.value_size != map_attr.value_size) {
            h2o_error_printf(H2O_EBPF_RETURN_MAP_PATH " has an unexpected map value size: expected %" PRIu32 " but got %" PRIu32
                                                      "\n",
                             map_attr.value_size, m.value_size);
            goto Error;
        }
    }

    /* success */
    return_map_fd = fd;
    return 1;

Error:
    if (fd >= 0)
        close(fd);
    return 0;
}

static void get_map_fd(h2o_loop_t *loop, const char *map_path, int *fd, uint64_t *last_attempt)
{
    // only check every second
    uint64_t now = h2o_now(loop);
    if (*last_attempt - now < 1000)
        return;

    *last_attempt = now;

    struct stat s;
    if (stat(map_path, &s) != 0) {
        // map path unavailable, cleanup fd if needed and leave
        if (*fd >= 0) {
            close(*fd);
            *fd = -1;
        }
        return;
    }

    if (*fd >= 0)
        return; // map still exists and we have a fd

    // map exists, try connect
    *fd = ebpf_obj_get(map_path);
    if (*fd < 0)
        h2o_perror("BPF_OBJ_GET failed");
}

static int get_tracing_map_fd(h2o_loop_t *loop)
{
    static __thread int fd = -1;
    static __thread uint64_t last_attempt = 0;
    get_map_fd(loop, H2O_EBPF_MAP_PATH, &fd, &last_attempt);
    return fd;
}

static inline int set_ebpf_map_key_tuples(const struct sockaddr *sa, h2o_ebpf_address_t *ea)
{
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (void *)sa;
        memcpy(ea->ip, &sin->sin_addr, sizeof(sin->sin_addr));
        ea->port = sin->sin_port;
        return 1;
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin = (void *)sa;
        memcpy(ea->ip, &sin->sin6_addr, sizeof(sin->sin6_addr));
        ea->port = sin->sin6_port;
        return 1;
    } else {
        return 0;
    }
}

int h2o_socket_ebpf_init_key_raw(h2o_ebpf_map_key_t *key, int sock_type, struct sockaddr *local, struct sockaddr *remote)
{
    memset(key, 0, sizeof(*key));
    if (!set_ebpf_map_key_tuples(local, &key->local))
        return 0;
    if (!set_ebpf_map_key_tuples(remote, &key->remote))
        return 0;
    key->family = local->sa_family == AF_INET6 ? 6 : 4;
    key->protocol = sock_type;
    return 1;
}

int h2o_socket_ebpf_init_key(h2o_ebpf_map_key_t *key, void *_sock)
{
    h2o_socket_t *sock = _sock;
    struct sockaddr_storage local, remote;
    unsigned int sock_type, sock_type_len = sizeof(sock_type_len);

    /* fetch info */
    if (h2o_socket_getsockname(sock, (void *)&local) == 0)
        return 0;
    if (h2o_socket_getpeername(sock, (void *)&remote) == 0)
        return 0;
    if (getsockopt(h2o_socket_get_fd(sock), SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len) != 0) /* can't the info be cached? */
        return 0;

    return h2o_socket_ebpf_init_key_raw(key, sock_type, (void *)&local, (void *)&remote);
}

static void report_ebpf_lookup_errors(h2o_error_reporter_t *reporter, uint64_t total_successes, uint64_t cur_successes)
{
    fprintf(stderr,
            "BPF_MAP_LOOKUP_ELEM failed with ENOENT %" PRIu64 " time%s, succeeded: %" PRIu64 " time%s, over the last minute.\n",
            reporter->cur_errors, reporter->cur_errors > 1 ? "s" : "", cur_successes, cur_successes > 1 ? "s" : "");
}

static h2o_error_reporter_t track_ebpf_lookup = H2O_ERROR_REPORTER_INITIALIZER(report_ebpf_lookup_errors);

#define DO_EBPF_RETURN_LOOKUP(func)                                                                                                \
    do {                                                                                                                           \
        if (return_map_fd >= 0) {                                                                                                  \
            pid_t tid = (pid_t)syscall(SYS_gettid); /* gettid() was not available until glibc 2.30 (2019) */                       \
            /* Make sure old flags do not exist, otherwise the subsequent logic will be unreliable. */                             \
            if (ebpf_map_delete(return_map_fd, &tid) == 0 || errno == ENOENT) {                                                    \
                do {                                                                                                               \
                    func                                                                                                           \
                } while (0);                                                                                                       \
                if (ebpf_map_lookup(return_map_fd, &tid, &flags) == 0) {                                                           \
                    h2o_error_reporter_record_success(&track_ebpf_lookup);                                                         \
                } else {                                                                                                           \
                    if (errno == ENOENT) {                                                                                         \
                        /* ENOENT could be issued in some reasons even if BPF tries to insert the entry, for example:              \
                         *  * the entry in LRU hash was evicted                                                                    \
                         *  * the insert operation in BPF program failed with ENOMEM                                               \
                         * We don't know the frequency for this ENOENT, so cap the number of logs.                                 \
                         *                                                                                                         \
                         * Other than the above reasons, ENOENT is issued when the tracer does not set the flags via h2o_return    \
                         * map, See h2o:_private_socket_lookup_flags handler in h2olog for details. */                             \
                        h2o_error_reporter_record_error(loop, &track_ebpf_lookup, 60000, 0);                                       \
                    } else {                                                                                                       \
                        h2o_perror("BPF_MAP_LOOKUP failed");                                                                       \
                    }                                                                                                              \
                }                                                                                                                  \
            } else {                                                                                                               \
                h2o_perror("BPF_MAP_DELETE failed");                                                                               \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

uint64_t h2o_socket_ebpf_lookup_flags(h2o_loop_t *loop, int (*init_key)(h2o_ebpf_map_key_t *key, void *cbdata), void *cbdata)
{
    uint64_t flags = 0;

    int tracing_map_fd = get_tracing_map_fd(loop);
    h2o_ebpf_map_key_t key;
    if ((tracing_map_fd >= 0 || H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_ENABLED()) && init_key(&key, cbdata)) {
        if (tracing_map_fd >= 0)
            ebpf_map_lookup(tracing_map_fd, &key, &flags);

        if (H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_ENABLED())
            DO_EBPF_RETURN_LOOKUP({ H2O__PRIVATE_SOCKET_LOOKUP_FLAGS(tid, flags, &key); });
    }

    return flags;
}

uint64_t h2o_socket_ebpf_lookup_flags_sni(h2o_loop_t *loop, uint64_t flags, const char *server_name, size_t server_name_len)
{
    if (H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_SNI_ENABLED())
        DO_EBPF_RETURN_LOOKUP({ H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_SNI(tid, flags, server_name, server_name_len); });
    return flags;
}

#undef DO_EBPF_RETURN_LOOKUP

#else

int h2o_socket_ebpf_setup(void)
{
    return 0;
}

int h2o_socket_ebpf_init_key_raw(h2o_ebpf_map_key_t *key, int sock_type, struct sockaddr *local, struct sockaddr *remote)
{
    h2o_fatal("unimplemented");
}

int h2o_socket_ebpf_init_key(h2o_ebpf_map_key_t *key, void *sock)
{
    h2o_fatal("unimplemented");
}

uint64_t h2o_socket_ebpf_lookup_flags(h2o_loop_t *loop, int (*init_key)(h2o_ebpf_map_key_t *key, void *cbdata), void *cbdata)
{
    return 0;
}

uint64_t h2o_socket_ebpf_lookup_flags_sni(h2o_loop_t *loop, uint64_t flags, const char *server_name, size_t server_name_len)
{
    return flags;
}

#endif
