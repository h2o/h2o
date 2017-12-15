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
#include <sys/un.h>
#include <unistd.h>
#include <openssl/err.h>
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/ioctl.h>
#endif
#if H2O_USE_PICOTLS
#include "picotls.h"
#endif
#include "h2o/socket.h"
#include "h2o/timeout.h"

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

#define OPENSSL_HOSTNAME_VALIDATION_LINKAGE static
#include "../../deps/ssl-conservatory/openssl/openssl_hostname_validation.c"

struct st_h2o_socket_ssl_t {
    SSL_CTX *ssl_ctx;
    SSL *ossl;
#if H2O_USE_PICOTLS
    ptls_t *ptls;
#endif
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
    struct {
        H2O_VECTOR(h2o_iovec_t) bufs;
        h2o_mem_pool_t pool; /* placed at the last */
    } output;
};

struct st_h2o_ssl_context_t {
    SSL_CTX *ctx;
    const h2o_iovec_t *protocols;
    h2o_iovec_t _npn_list_of_protocols;
};

/* backend functions */
static void do_dispose_socket(h2o_socket_t *sock);
static void do_write(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb);
static void do_read_start(h2o_socket_t *sock);
static void do_read_stop(h2o_socket_t *sock);
static int do_export(h2o_socket_t *_sock, h2o_socket_export_t *info);
static h2o_socket_t *do_import(h2o_loop_t *loop, h2o_socket_export_t *info);
static socklen_t get_peername_uncached(h2o_socket_t *sock, struct sockaddr *sa);

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

__thread h2o_buffer_prototype_t h2o_socket_buffer_prototype = {
    {16},                                       /* keep 16 recently used chunks */
    {H2O_SOCKET_INITIAL_INPUT_BUFFER_SIZE * 2}, /* minimum initial capacity */
    &h2o_socket_buffer_mmap_settings};

const char *h2o_socket_error_out_of_memory = "out of memory";
const char *h2o_socket_error_io = "I/O error";
const char *h2o_socket_error_closed = "socket closed by peer";
const char *h2o_socket_error_conn_fail = "connection failure";
const char *h2o_socket_error_ssl_no_cert = "no certificate";
const char *h2o_socket_error_ssl_cert_invalid = "invalid certificate";
const char *h2o_socket_error_ssl_cert_name_mismatch = "certificate name mismatch";
const char *h2o_socket_error_ssl_decode = "SSL decode error";

static void (*resumption_get_async)(h2o_socket_t *sock, h2o_iovec_t session_id);
static void (*resumption_new)(h2o_iovec_t session_id, h2o_iovec_t session_data);

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

static void write_ssl_bytes(h2o_socket_t *sock, const void *in, size_t len)
{
    if (len != 0) {
        void *bytes_alloced = h2o_mem_alloc_pool(&sock->ssl->output.pool, len);
        memcpy(bytes_alloced, in, len);
        h2o_vector_reserve(&sock->ssl->output.pool, &sock->ssl->output.bufs, sock->ssl->output.bufs.size + 1);
        sock->ssl->output.bufs.entries[sock->ssl->output.bufs.size++] = h2o_iovec_init(bytes_alloced, len);
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
    static BIO_METHOD *bio_methods = NULL;
    if (bio_methods == NULL) {
        static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&init_lock);
        if (bio_methods == NULL) {
            BIO_METHOD *biom = BIO_meth_new(BIO_TYPE_FD, "h2o_socket");
            BIO_meth_set_write(biom, write_bio);
            BIO_meth_set_read(biom, read_bio);
            BIO_meth_set_puts(biom, puts_bio);
            BIO_meth_set_ctrl(biom, ctrl_bio);
            __sync_synchronize();
            bio_methods = biom;
        }
	pthread_mutex_unlock(&init_lock);
    }

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

#if H2O_USE_PICOTLS
    if (sock->ssl->ptls != NULL) {
        if (sock->ssl->input.encrypted->size != 0) {
            const char *src = sock->ssl->input.encrypted->bytes, *src_end = src + sock->ssl->input.encrypted->size;
            h2o_iovec_t reserved;
            ptls_buffer_t rbuf;
            int ret;
            if ((reserved = h2o_buffer_reserve(&sock->input, sock->ssl->input.encrypted->size)).base == NULL)
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
                if ((reserved = h2o_buffer_reserve(&sock->input, rbuf.off)).base == NULL)
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
#endif

    while (sock->ssl->input.encrypted->size != 0 || SSL_pending(sock->ssl->ossl)) {
        int rlen;
        h2o_iovec_t buf = h2o_buffer_reserve(&sock->input, 4096);
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
    do_write(sock, sock->ssl->output.bufs.entries, sock->ssl->output.bufs.size, cb);
}

static void clear_output_buffer(struct st_h2o_socket_ssl_t *ssl)
{
    memset(&ssl->output.bufs, 0, sizeof(ssl->output.bufs));
    h2o_mem_clear_pool(&ssl->output.pool);
}

static void destroy_ssl(struct st_h2o_socket_ssl_t *ssl)
{
#if H2O_USE_PICOTLS
    if (ssl->ptls != NULL) {
        ptls_free(ssl->ptls);
        ssl->ptls = NULL;
    }
#endif
    if (ssl->ossl != NULL) {
        if (!SSL_is_server(ssl->ossl)) {
            free(ssl->handshake.client.server_name);
            free(ssl->handshake.client.session_cache_key.base);
        }
        SSL_free(ssl->ossl);
        ssl->ossl = NULL;
    }
    h2o_buffer_dispose(&ssl->input.encrypted);
    clear_output_buffer(ssl);
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

    close_cb = sock->on_close.cb;
    close_cb_data = sock->on_close.data;

    do_dispose_socket(sock);

    if (close_cb != NULL)
        close_cb(close_cb_data);
}

static void shutdown_ssl(h2o_socket_t *sock, const char *err)
{
    int ret;

    if (err != NULL)
        goto Close;

    if (sock->_cb.write != NULL) {
        /* note: libuv calls the write callback after the socket is closed by uv_close (with status set to 0 if the write succeeded)
         */
        sock->_cb.write = NULL;
        goto Close;
    }

#if H2O_USE_PICOTLS
    if (sock->ssl->ptls != NULL) {
        ptls_buffer_t wbuf;
        uint8_t wbuf_small[32];
        ptls_buffer_init(&wbuf, wbuf_small, sizeof(wbuf_small));
        if ((ret = ptls_send_alert(sock->ssl->ptls, &wbuf, PTLS_ALERT_LEVEL_WARNING, PTLS_ALERT_CLOSE_NOTIFY)) != 0)
            goto Close;
        write_ssl_bytes(sock, wbuf.base, wbuf.off);
        ptls_buffer_dispose(&wbuf);
        ret = 1; /* close the socket after sending close_notify */
    } else
#endif
        if (sock->ssl->ossl != NULL) {
        ERR_clear_error();
        if ((ret = SSL_shutdown(sock->ssl->ossl)) == -1)
            goto Close;
    } else {
        goto Close;
    }

    if (sock->ssl->output.bufs.size != 0) {
        h2o_socket_read_stop(sock);
        flush_pending_ssl(sock, ret == 1 ? dispose_socket : shutdown_ssl);
    } else if (ret == 2 && SSL_get_error(sock->ssl->ossl, ret) == SSL_ERROR_WANT_READ) {
        h2o_socket_read_start(sock, shutdown_ssl);
    } else {
        goto Close;
    }

    return;
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
    sock->_latency_optimization.suggested_tls_payload_size = 16384;
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
        sock->_latency_optimization.suggested_tls_payload_size = 16384;
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
        loop_time = h2o_evloop_get_execution_time(h2o_socket_get_loop(sock));
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

void h2o_socket_write(h2o_socket_t *sock, h2o_iovec_t *bufs, size_t bufcnt, h2o_socket_cb cb)
{
    size_t i, prev_bytes_written = sock->bytes_written;

    for (i = 0; i != bufcnt; ++i) {
        sock->bytes_written += bufs[i].len;
#if H2O_SOCKET_DUMP_WRITE
        fprintf(stderr, "writing %zu bytes to fd:%d\n", bufs[i].len, h2o_socket_get_fd(sock));
        h2o_dump_memory(stderr, bufs[i].base, bufs[i].len);
#endif
    }

    if (sock->ssl == NULL) {
        do_write(sock, bufs, bufcnt, cb);
    } else {
        assert(sock->ssl->output.bufs.size == 0);
        /* fill in the data */
        size_t ssl_record_size;
        switch (sock->_latency_optimization.state) {
        case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_TBD:
        case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DISABLED:
            ssl_record_size = prev_bytes_written < 200 * 1024 ? calc_suggested_tls_payload_size(sock, 1400) : 16384;
            break;
        case H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_DETERMINED:
            sock->_latency_optimization.state = H2O_SOCKET_LATENCY_OPTIMIZATION_STATE_NEEDS_UPDATE;
        /* fallthru */
        default:
            ssl_record_size = sock->_latency_optimization.suggested_tls_payload_size;
            break;
        }
        for (; bufcnt != 0; ++bufs, --bufcnt) {
            size_t off = 0;
            while (off != bufs[0].len) {
                int ret;
                size_t sz = bufs[0].len - off;
                if (sz > ssl_record_size)
                    sz = ssl_record_size;
#if H2O_USE_PICOTLS
                if (sock->ssl->ptls != NULL) {
                    size_t dst_size = sz + ptls_get_record_overhead(sock->ssl->ptls);
                    void *dst = h2o_mem_alloc_pool(&sock->ssl->output.pool, dst_size);
                    ptls_buffer_t wbuf;
                    ptls_buffer_init(&wbuf, dst, dst_size);
                    ret = ptls_send(sock->ssl->ptls, &wbuf, bufs[0].base + off, sz);
                    assert(ret == 0);
                    assert(!wbuf.is_allocated);
                    h2o_vector_reserve(&sock->ssl->output.pool, &sock->ssl->output.bufs, sock->ssl->output.bufs.size + 1);
                    sock->ssl->output.bufs.entries[sock->ssl->output.bufs.size++] = h2o_iovec_init(dst, wbuf.off);
                } else
#endif
                {
                    ret = SSL_write(sock->ssl->ossl, bufs[0].base + off, (int)sz);
                    if (ret != sz) {
                        /* The error happens if SSL_write is called after SSL_read returns a fatal error (e.g. due to corrupt TCP
                         * packet being received). We need to take care of this since some protocol implementations send data after
                         * the read-side of the connection gets closed (note that protocol implementations are (yet) incapable of
                         * distinguishing a normal shutdown and close due to an error using the `status` value of the read
                         * callback).
                         */
                        clear_output_buffer(sock->ssl);
                        flush_pending_ssl(sock, cb);
#ifndef H2O_USE_LIBUV
                        ((struct st_h2o_evloop_socket_t *)sock)->_flags |= H2O_SOCKET_FLAG_IS_WRITE_ERROR;
#endif
                        return;
                    }
                }
                off += sz;
            }
        }
        flush_pending_ssl(sock, cb);
    }
}

void on_write_complete(h2o_socket_t *sock, const char *err)
{
    h2o_socket_cb cb;

    if (sock->ssl != NULL)
        clear_output_buffer(sock->ssl);

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
    if (sock->_peername != NULL)
        free(sock->_peername);
    sock->_peername = h2o_mem_alloc(offsetof(struct st_h2o_socket_peername_t, addr) + len);
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

const char *h2o_socket_get_ssl_protocol_version(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
#if H2O_USE_PICOTLS
        if (sock->ssl->ptls != NULL)
            return "TLSv1.3";
#endif
        if (sock->ssl->ossl != NULL)
            return SSL_get_version(sock->ssl->ossl);
    }
    return NULL;
}

int h2o_socket_get_ssl_session_reused(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
#if H2O_USE_PICOTLS
        if (sock->ssl->ptls != NULL)
            return ptls_is_psk_handshake(sock->ssl->ptls);
#endif
        if (sock->ssl->ossl != NULL)
            return (int)SSL_session_reused(sock->ssl->ossl);
    }
    return -1;
}

const char *h2o_socket_get_ssl_cipher(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
#if H2O_USE_PICOTLS
        if (sock->ssl->ptls != NULL) {
            ptls_cipher_suite_t *cipher = ptls_get_cipher(sock->ssl->ptls);
            if (cipher != NULL)
                return cipher->aead->name;
        } else
#endif
            if (sock->ssl->ossl != NULL)
            return SSL_get_cipher_name(sock->ssl->ossl);
    }
    return NULL;
}

int h2o_socket_get_ssl_cipher_bits(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
#if H2O_USE_PICOTLS
        if (sock->ssl->ptls != NULL) {
            ptls_cipher_suite_t *cipher = ptls_get_cipher(sock->ssl->ptls);
            if (cipher == NULL)
                return 0;
            return (int)cipher->aead->key_size;
        } else
#endif
            if (sock->ssl->ossl != NULL)
            return SSL_get_cipher_bits(sock->ssl->ossl, NULL);
    }
    return 0;
}

h2o_iovec_t h2o_socket_get_ssl_session_id(h2o_socket_t *sock)
{
    if (sock->ssl != NULL) {
#if H2O_USE_PICOTLS
        if (sock->ssl->ptls != NULL) {
            /* FIXME */
        } else
#endif
            if (sock->ssl->ossl != NULL) {
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

h2o_iovec_t h2o_socket_log_ssl_session_id(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    h2o_iovec_t base64id, rawid = h2o_socket_get_ssl_session_id(sock);

    if (rawid.base == NULL)
        return h2o_iovec_init(NULL, 0);

    base64id.base = pool != NULL ? h2o_mem_alloc_pool(pool, h2o_base64_encode_capacity(rawid.len))
                                 : h2o_mem_alloc(h2o_base64_encode_capacity(rawid.len));
    base64id.len = h2o_base64_encode(base64id.base, rawid.base, rawid.len, 1);
    return base64id;
}

h2o_iovec_t h2o_socket_log_ssl_cipher_bits(h2o_socket_t *sock, h2o_mem_pool_t *pool)
{
    int bits = h2o_socket_get_ssl_cipher_bits(sock);
    if (bits != 0) {
        char *s = (char *)(pool != NULL ? h2o_mem_alloc_pool(pool, sizeof(H2O_INT16_LONGEST_STR))
                                        : h2o_mem_alloc(sizeof(H2O_INT16_LONGEST_STR)));
        size_t len = sprintf(s, "%" PRId16, (int16_t)bits);
        return h2o_iovec_init(s, len);
    } else {
        return h2o_iovec_init(NULL, 0);
    }
}

int h2o_socket_compare_address(struct sockaddr *x, struct sockaddr *y)
{
#define CMP(a, b)                                                                                                                  \
    if (a != b)                                                                                                                    \
    return a < b ? -1 : 1

    CMP(x->sa_family, y->sa_family);

    if (x->sa_family == AF_UNIX) {
        struct sockaddr_un *xun = (void *)x, *yun = (void *)y;
        int r = strcmp(xun->sun_path, yun->sun_path);
        if (r != 0)
            return r;
    } else if (x->sa_family == AF_INET) {
        struct sockaddr_in *xin = (void *)x, *yin = (void *)y;
        CMP(ntohl(xin->sin_addr.s_addr), ntohl(yin->sin_addr.s_addr));
        CMP(ntohs(xin->sin_port), ntohs(yin->sin_port));
    } else if (x->sa_family == AF_INET6) {
        struct sockaddr_in6 *xin6 = (void *)x, *yin6 = (void *)y;
        int r = memcmp(xin6->sin6_addr.s6_addr, yin6->sin6_addr.s6_addr, sizeof(xin6->sin6_addr.s6_addr));
        if (r != 0)
            return r;
        CMP(ntohs(xin6->sin6_port), ntohs(yin6->sin6_port));
        CMP(xin6->sin6_flowinfo, yin6->sin6_flowinfo);
        CMP(xin6->sin6_scope_id, yin6->sin6_scope_id);
    } else {
        assert(!"unknown sa_family");
    }

#undef CMP
    return 0;
}

size_t h2o_socket_getnumerichost(struct sockaddr *sa, socklen_t salen, char *buf)
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

int32_t h2o_socket_getport(struct sockaddr *sa)
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

static void create_ossl(h2o_socket_t *sock)
{
    sock->ssl->ossl = SSL_new(sock->ssl->ssl_ctx);
    setup_bio(sock);
}

static SSL_SESSION *on_async_resumption_get(SSL *ssl,
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL && !defined(LIBRESSL_VERSION_NUMBER)
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

static int on_async_resumption_new(SSL *ssl, SSL_SESSION *session)
{
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
    resumption_new(h2o_iovec_init(id, id_len), data);
    return 0;
}

static void on_handshake_complete(h2o_socket_t *sock, const char *err)
{
    if (err == NULL) {
#if H2O_USE_PICOTLS
        if (sock->ssl->ptls != NULL) {
            sock->ssl->record_overhead = ptls_get_record_overhead(sock->ssl->ptls);
        } else
#endif
        {
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

    /* set ssl session into the cache */
    if (sock->ssl->ossl != NULL && !SSL_is_server(sock->ssl->ossl) && sock->ssl->handshake.client.session_cache != NULL) {
        if (err == NULL || err == h2o_socket_error_ssl_cert_name_mismatch) {
            SSL_SESSION *session = SSL_get1_session(sock->ssl->ossl);
            h2o_cache_set(sock->ssl->handshake.client.session_cache, h2o_now(h2o_socket_get_loop(sock)),
                          sock->ssl->handshake.client.session_cache_key, sock->ssl->handshake.client.session_cache_key_hash,
                          h2o_iovec_init(session, 1));
        }
    }

    h2o_socket_cb handshake_cb = sock->ssl->handshake.cb;
    sock->_cb.write = NULL;
    sock->ssl->handshake.cb = NULL;
    if (err == NULL)
        decode_ssl_input(sock);
    handshake_cb(sock, err);
}

static void proceed_handshake(h2o_socket_t *sock, const char *err)
{
    h2o_iovec_t first_input = {NULL};
    int ret = 0;

    sock->_cb.write = NULL;

    if (err != NULL) {
        goto Complete;
    }

    if (sock->ssl->ossl == NULL) {
#if H2O_USE_PICOTLS
        /* prepare I/O */
        size_t consumed = sock->ssl->input.encrypted->size;
        ptls_buffer_t wbuf;
        ptls_buffer_init(&wbuf, "", 0);

        if (sock->ssl->ptls != NULL) {
            /* picotls in action, proceed the handshake */
            ret = ptls_handshake(sock->ssl->ptls, &wbuf, sock->ssl->input.encrypted->bytes, &consumed, NULL);
        } else {
            /* start using picotls if the first packet contains TLS 1.3 CH */
            ptls_context_t *ptls_ctx = h2o_socket_ssl_get_picotls_context(sock->ssl->ssl_ctx);
            if (ptls_ctx != NULL) {
                ptls_t *ptls = ptls_new(ptls_ctx, 1);
                if (ptls == NULL)
                    h2o_fatal("no memory");
                ret = ptls_handshake(ptls, &wbuf, sock->ssl->input.encrypted->bytes, &consumed, NULL);
                if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && wbuf.off != 0) {
                    sock->ssl->ptls = ptls;
                    sock->ssl->handshake.server.async_resumption.state = ASYNC_RESUMPTION_STATE_COMPLETE;
                } else {
                    ptls_free(ptls);
                }
            }
        }

        if (sock->ssl->ptls != NULL) {
            /* complete I/O done by picotls */
            h2o_buffer_consume(&sock->ssl->input.encrypted, consumed);
            switch (ret) {
            case 0:
            case PTLS_ERROR_IN_PROGRESS:
                if (wbuf.off != 0) {
                    h2o_socket_read_stop(sock);
                    write_ssl_bytes(sock, wbuf.base, wbuf.off);
                    flush_pending_ssl(sock, ret == 0 ? on_handshake_complete : proceed_handshake);
                } else {
                    h2o_socket_read_start(sock, proceed_handshake);
                }
                break;
            default:
                /* FIXME send alert in wbuf before calling the callback */
                on_handshake_complete(sock, "picotls handshake error");
                break;
            }
            ptls_buffer_dispose(&wbuf);
            return;
        }
        ptls_buffer_dispose(&wbuf);
#endif

        /* fallback to openssl if the attempt failed */
        create_ossl(sock);
    }

    if (sock->ssl->ossl != NULL && SSL_is_server(sock->ssl->ossl) &&
        sock->ssl->handshake.server.async_resumption.state == ASYNC_RESUMPTION_STATE_RECORD) {
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
            clear_output_buffer(sock->ssl);
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
        /* failed */
        long verify_result = SSL_get_verify_result(sock->ssl->ossl);
        if (verify_result != X509_V_OK) {
            err = X509_verify_cert_error_string(verify_result);
        } else {
            err = "ssl handshake failure";
        }
        goto Complete;
    }

    if (sock->ssl->output.bufs.size != 0) {
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
        if (sock->ssl->input.encrypted->size != 0)
            goto Redo;
        h2o_socket_read_start(sock, proceed_handshake);
    }
    return;

Complete:
    h2o_socket_read_stop(sock);
    on_handshake_complete(sock, err);
}

void h2o_socket_ssl_handshake(h2o_socket_t *sock, SSL_CTX *ssl_ctx, const char *server_name, h2o_socket_cb handshake_cb)
{
    sock->ssl = h2o_mem_alloc(sizeof(*sock->ssl));
    memset(sock->ssl, 0, offsetof(struct st_h2o_socket_ssl_t, output.pool));

    sock->ssl->ssl_ctx = ssl_ctx;

    /* setup the buffers; sock->input should be empty, sock->ssl->input.encrypted should contain the initial input, if any */
    h2o_buffer_init(&sock->ssl->input.encrypted, &h2o_socket_buffer_prototype);
    if (sock->input->size != 0) {
        h2o_buffer_t *tmp = sock->input;
        sock->input = sock->ssl->input.encrypted;
        sock->ssl->input.encrypted = tmp;
    }

    h2o_mem_init_pool(&sock->ssl->output.pool);

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

#if H2O_USE_PICOTLS

static int get_ptls_index(void)
{
    static int index = -1;

    if (index == -1) {
        static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_lock(&mutex);
        if (index == -1) {
            index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
            assert(index != -1);
        }
        pthread_mutex_unlock(&mutex);
    }

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

#endif

static void on_dispose_ssl_ctx_session_cache(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    h2o_cache_t *ssl_session_cache = (h2o_cache_t *)ptr;
    if (ssl_session_cache != NULL)
        h2o_cache_destroy(ssl_session_cache);
}

static int get_ssl_session_cache_index(void)
{
    static int index = -1;
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);
    if (index == -1) {
        index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, on_dispose_ssl_ctx_session_cache);
        assert(index != -1);
    }
    pthread_mutex_unlock(&mutex);
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

    assert(sock->ssl != NULL);

#if H2O_USE_PICOTLS
    if (sock->ssl->ptls != NULL) {
        const char *proto = ptls_get_negotiated_protocol(sock->ssl->ptls);
        return proto != NULL ? h2o_iovec_init(proto, strlen(proto)) : h2o_iovec_init(NULL, 0);
    }
#endif

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
