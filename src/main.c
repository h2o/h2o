/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Tatsuhiko Kubo,
 *                         Domingo Alvarez Duarte, Nick Desaulniers,
 *                         Jeff Marrison, Shota Fukumori, Fastly, Inc.
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
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 /* to use IPV6_RECVPKTINFO */
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#ifdef LIBC_HAS_BACKTRACE
#include <execinfo.h>
#include <quicly.h>

#endif
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"
#include "picotls/certificate_compression.h"
#include "cloexec.h"
#include "yoml-parser.h"
#include "neverbleed.h"
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/http3_server.h"
#include "h2o/serverutil.h"
#include "h2o/file.h"
#if H2O_USE_MRUBY
#include "h2o/mruby_.h"
#endif
#include "standalone.h"
#include "../lib/probes_.h"

#ifdef TCP_FASTOPEN
#define H2O_DEFAULT_LENGTH_TCP_FASTOPEN_QUEUE 4096
#else
#define H2O_DEFAULT_LENGTH_TCP_FASTOPEN_QUEUE 0
#endif

#if defined(__linux) && defined(SO_REUSEPORT)
#define H2O_USE_REUSEPORT 1
#define H2O_SO_REUSEPORT SO_REUSEPORT
#elif defined(SO_REUSEPORT_LB) /* FreeBSD */
#define H2O_USE_REUSEPORT 1
#define H2O_SO_REUSEPORT SO_REUSEPORT_LB
#else
#define H2O_USE_REUSEPORT 0
#endif

#define H2O_DEFAULT_NUM_NAME_RESOLUTION_THREADS 32

#define H2O_DEFAULT_OCSP_UPDATER_MAX_THREADS 10

struct listener_ssl_config_t {
    H2O_VECTOR(h2o_iovec_t) hostnames;
    char *certificate_file;
    SSL_CTX *ctx;
    h2o_iovec_t *http2_origin_frame;
    h2o_iovec_t tcp_congestion_controller; /* per-SNI CC */
    struct {
        uint64_t interval;
        unsigned max_failures;
        char *cmd;
        pthread_t updater_tid; /* should be valid when and only when interval != 0 */
    } ocsp_stapling;
    /**
     * retains up-to-date data to be sent in regard to server authentication (e.g., ocsp status, pre-compressed certs)
     */
    struct {
        pthread_mutex_t mutex;
        h2o_buffer_t *ocsp_status;
        ptls_emit_compressed_certificate_t *emit_compressed_ptls;
    } dynamic;
};

struct listener_config_t {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    h2o_hostconf_t **hosts;
    H2O_VECTOR(struct listener_ssl_config_t *) ssl;
    struct {
        quicly_context_t *ctx;
        /**
         * an array of file descriptors (size: `num_threads`) used for packet forwarding between threads
         */
        int *thread_fds;
        /**
         * whether to send retry
         */
        unsigned send_retry : 1;
        /**
         * QPACK settings
         */
        h2o_http3_qpack_context_t qpack;
    } quic;
    int proxy_protocol;
    h2o_iovec_t tcp_congestion_controller; /* default CC for this address */
};

struct listener_ctx_t {
    size_t listener_index;
    h2o_accept_ctx_t accept_ctx;
    h2o_socket_t *sock;
    struct {
        h2o_http3_server_ctx_t ctx;
        h2o_socket_t *forwarded_sock;
    } http3;
};

typedef struct st_resolve_tag_node_cache_entry_t {
    h2o_iovec_t filename;
    yoml_t *node;
} resolve_tag_node_cache_entry_t;

typedef struct st_resolve_tag_arg_t {
    H2O_VECTOR(resolve_tag_node_cache_entry_t) node_cache;
} resolve_tag_arg_t;

typedef enum en_run_mode_t {
    RUN_MODE_WORKER = 0,
    RUN_MODE_MASTER,
    RUN_MODE_DAEMON,
    RUN_MODE_TEST,
} run_mode_t;

static struct {
    h2o_globalconf_t globalconf;
    run_mode_t run_mode;
    struct {
        int *fds;
        /**
         * List of booleans corresponding to each element of `server_starter.fds` indicating if a H2O listener has been mapped to
         * the file descriptor. The list is used to check if all the file descriptors opened by Server::Starter have been assigned
         * H2O listeners.
         */
        char *bound_fd_map;
        size_t num_fds;
    } server_starter;
    struct listener_config_t **listeners;
    size_t num_listeners;
    char *pid_file;
    char *error_log;
    int max_connections;
    /**
     * In addition to max_connections, maximum number of H3 connections can be further capped by this configuration variable.
     * Can be set to INT_MAX so that only max_connections would be used.
     */
    int max_quic_connections;
    /**
     * array size == number of worker threads to instantiate, the values indicate which CPU to pin, -1 if not
     */
    H2O_VECTOR(int) thread_map;
    struct {
        size_t num_threads;
        h2o_http3_conn_callbacks_t conn_callbacks;
        uint64_t node_id;
        h2o_quic_forward_node_vector_t forward_nodes;
    } quic;
    int tfo_queues;
    time_t launch_time;
    struct {
        h2o_context_t ctx;
        h2o_multithread_receiver_t server_notifications;
        h2o_multithread_receiver_t memcached;
    } * threads;
    volatile sig_atomic_t shutdown_requested;
    h2o_barrier_t startup_sync_barrier;
    struct {
        /* unused buffers exist to avoid false sharing of the cache line */
        char _unused1_avoir_false_sharing[32];
        /**
         * Number of currently handled incoming connections. Should use atomic functions to update the value.
         */
        int _num_connections;
        /* unused buffers exist to avoid false sharing of the cache line */
        char _unused2_avoir_false_sharing[32];
        /**
         * Number of currently handled incoming QUIC connections.
         */
        int _num_quic_connections;
        char _unused3_avoir_false_sharing[32];
        /**
         * Total number of opened incoming connections. Should use atomic functions to update the value.
         */
        unsigned long _num_sessions;
        char _unused4_avoir_false_sharing[32];
    } state;
    char *crash_handler;
    int crash_handler_wait_pipe_close;
    int tcp_reuseport;
} conf = {
    .globalconf = {0},
    .run_mode = RUN_MODE_WORKER,
    .server_starter = {0},
    .listeners = NULL,
    .num_listeners = 0,
    .pid_file = NULL,
    .error_log = NULL,
    .max_connections = 1024,
    .max_quic_connections = INT_MAX, /* (INT_MAX = i.e., allow up to max_connections) */
    .thread_map = {0},               /* initialized in main() */
    .quic = {0},                     /* 0 defaults to all, conn_callbacks (initialized in main() */
    .tfo_queues = 0,                 /* initialized in main() */
    .launch_time = 0,                /* initialized in main() */
    .threads = NULL,
    .shutdown_requested = 0,
    .startup_sync_barrier = H2O_BARRIER_INITIALIZER(SIZE_MAX),
    .state = {{0}},
    .crash_handler = "share/h2o/annotate-backtrace-symbols",
    .crash_handler_wait_pipe_close = 0,
    .tcp_reuseport = 0,
};

static neverbleed_t *neverbleed = NULL;

static int cmd_argc;
static char **cmd_argv;

static void set_cloexec(int fd)
{
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        perror("failed to set FD_CLOEXEC");
        abort();
    }
}

static void on_neverbleed_fork(void)
{
/* Rewrite of argv should only be done on platforms that are known to benefit from doing that. On linux, doing so helps admins look
 *  for h2o (or neverbleed) by running pidof. */
#ifdef __linux__
    for (int i = cmd_argc - 1; i >= 0; --i)
        memset(cmd_argv[i], 0, strlen(cmd_argv[i]));
    strcpy(cmd_argv[0], "neverbleed");
#endif
}

static int on_openssl_print_errors(const char *str, size_t len, void *fp)
{
    fwrite(str, 1, len, fp);
    return (int)len;
}

static void setup_ecc_key(SSL_CTX *ssl_ctx)
{
#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#else
    int nid = NID_X9_62_prime256v1;
    EC_KEY *key = EC_KEY_new_by_curve_name(nid);
    if (key == NULL) {
        fprintf(stderr, "Failed to create curve \"%s\"\n", OBJ_nid2sn(nid));
        return;
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
    EC_KEY_free(key);
#endif
}

static struct listener_ssl_config_t *resolve_sni(struct listener_config_t *listener, const char *name, size_t name_len)
{
    size_t i, j;

    for (i = 0; i != listener->ssl.size; ++i) {
        struct listener_ssl_config_t *ssl_config = listener->ssl.entries[i];
        for (j = 0; j != ssl_config->hostnames.size; ++j) {
            if (ssl_config->hostnames.entries[j].base[0] == '*') {
                /* matching against "*.foo.bar" */
                size_t cmplen = ssl_config->hostnames.entries[j].len - 1;
                if (!(cmplen < name_len && h2o_lcstris(name + name_len - cmplen, cmplen, ssl_config->hostnames.entries[j].base + 1,
                                                       ssl_config->hostnames.entries[j].len - 1)))
                    continue;
            } else {
                if (!h2o_lcstris(name, name_len, ssl_config->hostnames.entries[j].base, ssl_config->hostnames.entries[j].len))
                    continue;
            }
            /* found */
            return listener->ssl.entries[i];
        }
    }
    return listener->ssl.entries[0];
}

static inline void set_tcp_congestion_controller(h2o_socket_t *sock, h2o_iovec_t cc_name)
{
#if defined(TCP_CONGESTION)
    if (cc_name.base != NULL) {
        int fd = h2o_socket_get_fd(sock);
        assert(fd >= 0);
        if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc_name.base, (socklen_t)cc_name.len) != 0)
            perror("setsokopt(IPPROTO_TCP, TCP_CONGESTION)");
    }
#endif
}

static int on_sni_callback(SSL *ssl, int *ad, void *arg)
{
    struct listener_config_t *listener = arg;
    const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (server_name != NULL) {
        struct listener_ssl_config_t *resolved = resolve_sni(listener, server_name, strlen(server_name));
        if (resolved->ctx != SSL_get_SSL_CTX(ssl)) {
            SSL_set_SSL_CTX(ssl, resolved->ctx);
            set_tcp_congestion_controller(SSL_get_app_data(ssl), resolved->tcp_congestion_controller);
        }
    }

    return SSL_TLSEXT_ERR_OK;
}

struct st_on_client_hello_ptls_t {
    ptls_on_client_hello_t super;
    struct listener_config_t *listener;
};

static int on_client_hello_ptls(ptls_on_client_hello_t *_self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    struct st_on_client_hello_ptls_t *self = (struct st_on_client_hello_ptls_t *)_self;
    int ret = 0;

    /* handle SNI */
    if (params->server_name.base != NULL) {
        struct listener_ssl_config_t *resolved =
            resolve_sni(self->listener, (const char *)params->server_name.base, params->server_name.len);
        ptls_context_t *newctx = h2o_socket_ssl_get_picotls_context(resolved->ctx);
        ptls_set_context(tls, newctx);
        ptls_set_server_name(tls, (const char *)params->server_name.base, params->server_name.len);
        if (self->listener->quic.ctx == NULL)
            set_tcp_congestion_controller(*ptls_get_data_ptr(tls), resolved->tcp_congestion_controller);
    }

    /* handle ALPN */
    if (params->negotiated_protocols.count != 0) {
        if (self->listener->quic.ctx != NULL) {
            size_t i, j;
            for (i = 0; i != sizeof(h2o_http3_alpn) / sizeof(h2o_http3_alpn[0]); ++i) {
                for (j = 0; j != params->negotiated_protocols.count; ++j)
                    if (h2o_memis(h2o_http3_alpn[i].base, h2o_http3_alpn[i].len, params->negotiated_protocols.list[j].base,
                                  params->negotiated_protocols.list[j].len))
                        goto HQ_ALPN_Found;
            }
            return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
        HQ_ALPN_Found:
            if ((ret = ptls_set_negotiated_protocol(tls, (char *)h2o_http3_alpn[i].base, h2o_http3_alpn[i].len)) != 0)
                return ret;
        } else {
            const h2o_iovec_t *server_pref;
            for (server_pref = h2o_alpn_protocols; server_pref->len != 0; ++server_pref) {
                size_t i;
                for (i = 0; i != params->negotiated_protocols.count; ++i)
                    if (h2o_memis(server_pref->base, server_pref->len, params->negotiated_protocols.list[i].base,
                                  params->negotiated_protocols.list[i].len))
                        goto TCP_ALPN_Found;
            }
            return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
        TCP_ALPN_Found:
            if ((ret = ptls_set_negotiated_protocol(tls, server_pref->base, server_pref->len)) != 0)
                return ret;
        }
    }

    return ret;
}

static ptls_emit_compressed_certificate_t *build_compressed_certificate_ptls(ptls_context_t *ctx, ptls_iovec_t ocsp_status)
{
    ptls_emit_compressed_certificate_t *ecc = h2o_mem_alloc(sizeof(*ecc));
    int ret;

    if ((ret = ptls_init_compressed_certificate(ecc, ctx->certificates.list, ctx->certificates.count, ocsp_status)) != 0)
        h2o_fatal("failed to rebuild brotli-compressed certificate chain (error %d)\n", ret);

    return ecc;
}

static void build_ssl_dynamic_data(struct listener_ssl_config_t *ssl_conf, h2o_buffer_t *ocsp_status)
{
    ptls_emit_compressed_certificate_t *emit_cert_compressed_ptls = NULL;
    ptls_context_t *ctx_ptls;

    if ((ctx_ptls = h2o_socket_ssl_get_picotls_context(ssl_conf->ctx)) != NULL) {
        emit_cert_compressed_ptls = build_compressed_certificate_ptls(
            h2o_socket_ssl_get_picotls_context(ssl_conf->ctx),
            ocsp_status != NULL ? ptls_iovec_init(ocsp_status->bytes, ocsp_status->size) : ptls_iovec_init(NULL, 0));
    }

    pthread_mutex_lock(&ssl_conf->dynamic.mutex);

    if (ssl_conf->dynamic.ocsp_status != NULL)
        h2o_buffer_dispose(&ssl_conf->dynamic.ocsp_status);
    if (ssl_conf->dynamic.emit_compressed_ptls != NULL) {
        ptls_dispose_compressed_certificate(ssl_conf->dynamic.emit_compressed_ptls);
        free(ssl_conf->dynamic.emit_compressed_ptls);
    }
    ssl_conf->dynamic.ocsp_status = ocsp_status;
    ssl_conf->dynamic.emit_compressed_ptls = emit_cert_compressed_ptls;

    pthread_mutex_unlock(&ssl_conf->dynamic.mutex);
}

static int get_ocsp_response(const char *cert_fn, const char *cmd, h2o_buffer_t **resp)
{
    char *cmd_fullpath = h2o_configurator_get_cmd_path(cmd), *argv[] = {cmd_fullpath, (char *)cert_fn, NULL};
    int child_status, ret;

    if (h2o_read_command(cmd_fullpath, argv, resp, &child_status) != 0) {
        fprintf(stderr, "[OCSP Stapling] failed to execute %s:%s\n", cmd, strerror(errno));
        switch (errno) {
        case EACCES:
        case ENOENT:
        case ENOEXEC:
            /* permanent errors */
            ret = EX_CONFIG;
            goto Exit;
        default:
            ret = EX_TEMPFAIL;
            goto Exit;
        }
    }

    if (!(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0))
        h2o_buffer_dispose(resp);
    if (!WIFEXITED(child_status)) {
        fprintf(stderr, "[OCSP Stapling] command %s was killed by signal %d\n", cmd_fullpath, WTERMSIG(child_status));
        ret = EX_TEMPFAIL;
        goto Exit;
    }
    ret = WEXITSTATUS(child_status);

Exit:
    free(cmd_fullpath);
    return ret;
}

static h2o_sem_t ocsp_updater_semaphore;

static void *ocsp_updater_thread(void *_ssl_conf)
{
    struct listener_ssl_config_t *ssl_conf = _ssl_conf;
    time_t next_at = 0, now;
    unsigned fail_cnt = 0;
    int status;
    h2o_buffer_t *resp;

    assert(ssl_conf->ocsp_stapling.interval != 0);

    while (1) {
        /* sleep until next_at */
        if ((now = time(NULL)) < next_at) {
            time_t sleep_secs = next_at - now;
            sleep(sleep_secs < UINT_MAX ? (unsigned)sleep_secs : UINT_MAX);
            continue;
        }
        /* fetch the response */
        h2o_sem_wait(&ocsp_updater_semaphore);
        status = get_ocsp_response(ssl_conf->certificate_file, ssl_conf->ocsp_stapling.cmd, &resp);
        h2o_sem_post(&ocsp_updater_semaphore);
        switch (status) {
        case 0: /* success */
            fail_cnt = 0;
            build_ssl_dynamic_data(ssl_conf, resp);
            fprintf(stderr, "[OCSP Stapling] successfully updated the response for certificate file:%s\n",
                    ssl_conf->certificate_file);
            break;
        case EX_TEMPFAIL: /* temporary failure */
            if (fail_cnt == ssl_conf->ocsp_stapling.max_failures) {
                fprintf(stderr,
                        "[OCSP Stapling] OCSP stapling is temporary disabled due to repeated errors for certificate file:%s\n",
                        ssl_conf->certificate_file);
                build_ssl_dynamic_data(ssl_conf, NULL);
            } else {
                fprintf(stderr,
                        "[OCSP Stapling] reusing old response due to a temporary error occurred while fetching OCSP "
                        "response for certificate file:%s\n",
                        ssl_conf->certificate_file);
                ++fail_cnt;
            }
            break;
        default: /* permanent failure */
            build_ssl_dynamic_data(ssl_conf, NULL);
            fprintf(stderr, "[OCSP Stapling] disabled for certificate file:%s\n", ssl_conf->certificate_file);
            goto Exit;
        }
        /* update next_at */
        next_at = time(NULL) + ssl_conf->ocsp_stapling.interval;
    }

Exit:
    return NULL;
}

#ifndef OPENSSL_NO_OCSP

static int on_staple_ocsp_ossl(SSL *ssl, void *_ssl_conf)
{
    struct listener_ssl_config_t *ssl_conf = _ssl_conf;
    void *resp = NULL;
    size_t len = 0;

    /* fetch ocsp response */
    pthread_mutex_lock(&ssl_conf->dynamic.mutex);
    if (ssl_conf->dynamic.ocsp_status != NULL) {
        resp = CRYPTO_malloc((int)ssl_conf->dynamic.ocsp_status->size, __FILE__, __LINE__);
        if (resp != NULL) {
            len = ssl_conf->dynamic.ocsp_status->size;
            memcpy(resp, ssl_conf->dynamic.ocsp_status->bytes, len);
        }
    }
    pthread_mutex_unlock(&ssl_conf->dynamic.mutex);

    if (resp != NULL) {
        SSL_set_tlsext_status_ocsp_resp(ssl, resp, len);
        return SSL_TLSEXT_ERR_OK;
    } else {
        return SSL_TLSEXT_ERR_NOACK;
    }
}

#endif

struct st_emit_certificate_ptls_t {
    ptls_emit_certificate_t super;
    struct listener_ssl_config_t *conf;
};

static int on_emit_certificate_ptls(ptls_emit_certificate_t *_self, ptls_t *tls, ptls_message_emitter_t *emitter,
                                    ptls_key_schedule_t *key_sched, ptls_iovec_t context, int push_status_request,
                                    const uint16_t *compress_algos, size_t num_compress_algos)
{
    struct st_emit_certificate_ptls_t *self = (void *)_self;
    int ret;

    pthread_mutex_lock(&self->conf->dynamic.mutex);

    if (self->conf->dynamic.emit_compressed_ptls != NULL) {
        ptls_emit_certificate_t *ec = &self->conf->dynamic.emit_compressed_ptls->super;
        if ((ret = ec->cb(ec, tls, emitter, key_sched, context, push_status_request, compress_algos, num_compress_algos)) !=
            PTLS_ERROR_DELEGATE)
            goto Exit;
    }

    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
        ptls_context_t *tlsctx = ptls_get_context(tls);
        h2o_buffer_t *ocsp_response = push_status_request ? self->conf->dynamic.ocsp_status : NULL;
        ret = ptls_build_certificate_message(
            emitter->buf, ptls_iovec_init(NULL, 0), tlsctx->certificates.list, tlsctx->certificates.count,
            ocsp_response != NULL ? ptls_iovec_init(ocsp_response->bytes, ocsp_response->size) : ptls_iovec_init(NULL, 0));
        if (ret != 0)
            goto Exit;
    });
    ret = 0;

Exit:
    pthread_mutex_unlock(&self->conf->dynamic.mutex);
    return ret;
}

static const char *listener_setup_ssl_picotls(struct listener_config_t *listener, struct listener_ssl_config_t *ssl_config,
                                              SSL_CTX *ssl_ctx)
{
    static const ptls_key_exchange_algorithm_t *key_exchanges[] = {
#ifdef PTLS_OPENSSL_HAVE_X25519
        &ptls_openssl_x25519,
#else
        &ptls_minicrypto_x25519,
#endif
        &ptls_openssl_secp256r1, NULL};
    struct st_fat_context_t {
        ptls_context_t ctx;
        struct st_on_client_hello_ptls_t ch;
        struct st_emit_certificate_ptls_t ec;
        ptls_openssl_sign_certificate_t sc;
    } *pctx = h2o_mem_alloc(sizeof(*pctx));
    EVP_PKEY *key;
    X509 *cert;
    STACK_OF(X509) * cert_chain;
    int ret;

    *pctx = (struct st_fat_context_t){
        .ctx =
            {
                .random_bytes = ptls_openssl_random_bytes,
                .get_time = &ptls_get_time,
                .key_exchanges = key_exchanges,
                .cipher_suites = ptls_openssl_cipher_suites,
                .certificates = {0}, /* fill later */
                .esni = NULL,        /* fill later */
                .on_client_hello = &pctx->ch.super,
                .emit_certificate = &pctx->ec.super,
                .sign_certificate = &pctx->sc.super,
                .verify_certificate = NULL,
                .ticket_lifetime = 0, /* initialized alongside encrypt_ticket */
                .max_early_data_size = 8192,
                .hkdf_label_prefix__obsolete = NULL,
                .require_dhe_on_psk = 1,
                .use_exporter = 0,
                .send_change_cipher_spec = 0, /* is a client-only flag. As a server, this flag can be of any value. */
                .require_client_authentication = 0,
                .omit_end_of_early_data = 0,
                .encrypt_ticket = NULL, /* initialized later */
                .save_ticket = NULL,    /* initialized later */
                .log_event = NULL,
                .update_open_count = NULL,
                .update_traffic_key = NULL,
                .decompress_certificate = NULL,
                .update_esni_key = NULL,
                .on_extension = NULL,
            },
        .ch =
            {
                .listener = listener,
                .super =
                    {
                        .cb = on_client_hello_ptls,
                    },
            },
        .ec =
            {
                .conf = ssl_config,
                .super =
                    {
                        .cb = on_emit_certificate_ptls,
                    },
            },
    };
    { /* obtain key and cert (via fake connection for libressl compatibility) */
        SSL *fakeconn = SSL_new(ssl_ctx);
        assert(fakeconn != NULL);
        key = SSL_get_privatekey(fakeconn);
        assert(key != NULL);
        cert = SSL_get_certificate(fakeconn);
        assert(cert != NULL);
        SSL_free(fakeconn);
    }

    if (ptls_openssl_init_sign_certificate(&pctx->sc, key) != 0) {
        free(pctx);
        return "failed to setup private key";
    }

    SSL_CTX_get_extra_chain_certs(ssl_ctx, &cert_chain);
    ret = ptls_openssl_load_certificates(&pctx->ctx, cert, cert_chain);
    assert(ret == 0);

    h2o_socket_ssl_set_picotls_context(ssl_ctx, &pctx->ctx);

    return NULL;
}

static void listener_setup_ssl_add_host(struct listener_ssl_config_t *ssl_config, h2o_iovec_t host)
{
    const char *host_end = memchr(host.base, ':', host.len);
    if (host_end == NULL)
        host_end = host.base + host.len;

    h2o_vector_reserve(NULL, &ssl_config->hostnames, ssl_config->hostnames.size + 1);
    ssl_config->hostnames.entries[ssl_config->hostnames.size++] = h2o_iovec_init(host.base, host_end - host.base);
}

static h2o_iovec_t *build_http2_origin_frame(h2o_configurator_command_t *cmd, yoml_t **origins, size_t nr_origins)
{
    size_t i;
    h2o_iovec_t *http2_origin_frame = h2o_mem_alloc(sizeof(*http2_origin_frame));
    uint16_t lengths[nr_origins];
    h2o_iovec_t elems[nr_origins * 2];
    for (i = 0; i < nr_origins; i++) {
        yoml_t *origin = origins[i];
        if (origin->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, origin, "element of a sequence passed to http2-origin-frame must be a scalar");
            free(http2_origin_frame);
            return NULL;
        }
        size_t origin_len = strlen(origins[i]->data.scalar);
        lengths[i] = htons(origin_len);
        elems[i * 2].base = (char *)&lengths[i];
        elems[i * 2].len = 2;
        elems[i * 2 + 1].base = origins[i]->data.scalar;
        elems[i * 2 + 1].len = origin_len;
        h2o_strtolower(elems[i * 2 + 1].base, origin_len);
    }
    *http2_origin_frame = h2o_concat_list(NULL, elems, nr_origins * 2);
    return http2_origin_frame;
}

static int listener_setup_ssl(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *listen_node,
                              yoml_t **ssl_node, yoml_t **cc_node, struct listener_config_t *listener, int listener_is_new)
{
    SSL_CTX *ssl_ctx = NULL;
    yoml_t **certificate_file, **key_file, **dh_file, **min_version, **max_version, **cipher_suite, **ocsp_update_cmd,
        **ocsp_update_interval_node, **ocsp_max_failures_node, **cipher_preference_node, **neverbleed_node,
        **http2_origin_frame_node;
    h2o_iovec_t *http2_origin_frame = NULL;
    long ssl_options = SSL_OP_ALL;
    uint64_t ocsp_update_interval = 4 * 60 * 60; /* defaults to 4 hours */
    unsigned ocsp_max_failures = 3;              /* defaults to 3; permit 3 failures before temporary disabling OCSP stapling */
    int use_neverbleed = 1, use_picotls = 1;     /* enabled by default */

    if (!listener_is_new) {
        if (listener->ssl.size != 0 && ssl_node == NULL) {
            h2o_configurator_errprintf(cmd, listen_node, "cannot accept HTTP; already defined to accept HTTPS");
            return -1;
        }
        if (listener->ssl.size == 0 && ssl_node != NULL) {
            h2o_configurator_errprintf(cmd, *ssl_node, "cannot accept HTTPS; already defined to accept HTTP");
            return -1;
        }
    }

    if (ssl_node == NULL)
        return 0;

    /* parse */
    if (h2o_configurator_parse_mapping(cmd, *ssl_node, "certificate-file:s,key-file:s",
                                       "min-version:s,minimum-version:s,max-version:s,maximum-version:s,"
                                       "cipher-suite:s,ocsp-update-cmd:s,ocsp-update-interval:*,"
                                       "ocsp-max-failures:*,dh-file:s,cipher-preference:*,neverbleed:*,"
                                       "http2-origin-frame:*",
                                       &certificate_file, &key_file, &min_version, &min_version, &max_version, &max_version,
                                       &cipher_suite, &ocsp_update_cmd, &ocsp_update_interval_node, &ocsp_max_failures_node,
                                       &dh_file, &cipher_preference_node, &neverbleed_node, &http2_origin_frame_node) != 0)
        return -1;
    if (cipher_preference_node != NULL) {
        switch (h2o_configurator_get_one_of(cmd, *cipher_preference_node, "client,server")) {
        case 0:
            ssl_options &= ~SSL_OP_CIPHER_SERVER_PREFERENCE;
            break;
        case 1:
            ssl_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
            break;
        default:
            return -1;
        }
    }
    if (neverbleed_node != NULL && (use_neverbleed = (int)h2o_configurator_get_one_of(cmd, *neverbleed_node, "off,on")) == -1)
        return -1;
    if (http2_origin_frame_node != NULL) {
        switch ((*http2_origin_frame_node)->type) {
        case YOML_TYPE_SCALAR:
            if ((http2_origin_frame = build_http2_origin_frame(cmd, http2_origin_frame_node, 1)) == NULL)
                return -1;
            break;
        case YOML_TYPE_SEQUENCE:
            if ((http2_origin_frame = build_http2_origin_frame(cmd, (*http2_origin_frame_node)->data.sequence.elements,
                                                               (*http2_origin_frame_node)->data.sequence.size)) == NULL)
                return -1;
            break;
        default:
            h2o_configurator_errprintf(cmd, *http2_origin_frame_node,
                                       "argument to `http2-origin-frame` must be either a scalar or a sequence");
            return -1;
        }
    }
    if (min_version != NULL) {
#define MAP(tok, op)                                                                                                               \
    if (strcasecmp((*min_version)->data.scalar, tok) == 0) {                                                                       \
        ssl_options |= (op);                                                                                                       \
        goto VersionFound;                                                                                                         \
    }
        MAP("sslv2", 0);
        MAP("sslv3", SSL_OP_NO_SSLv2);
        MAP("tlsv1", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        MAP("tlsv1.1", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);
#ifdef SSL_OP_NO_TLSv1_1
        MAP("tlsv1.2", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif
#ifdef SSL_OP_NO_TLSv1_2
        MAP("tlsv1.3", SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
#endif
#undef MAP
        h2o_configurator_errprintf(cmd, *min_version, "unknown protocol version: %s", (*min_version)->data.scalar);
    VersionFound:;
    } else {
        /* default is >= TLSv1 */
        ssl_options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    }
    if (max_version != NULL) {
        if (strcasecmp((*max_version)->data.scalar, "tlsv1.3") < 0) {
#ifdef SSL_OP_NO_TLSv1_3
            ssl_options |= SSL_OP_NO_TLSv1_3;
#endif
            use_picotls = 0;
        }
    }
    if (ocsp_update_interval_node != NULL) {
        if (h2o_configurator_scanf(cmd, *ocsp_update_interval_node, "%" SCNu64, &ocsp_update_interval) != 0)
            goto Error;
    }
    if (ocsp_max_failures_node != NULL) {
        if (h2o_configurator_scanf(cmd, *ocsp_max_failures_node, "%u", &ocsp_max_failures) != 0)
            goto Error;
    }

    /* add the host to the existing SSL config, if the certificate file is already registered */
    if (ctx->hostconf != NULL) {
        size_t i;
        for (i = 0; i != listener->ssl.size; ++i) {
            struct listener_ssl_config_t *ssl_config = listener->ssl.entries[i];
            if (strcmp(ssl_config->certificate_file, (*certificate_file)->data.scalar) == 0) {
                listener_setup_ssl_add_host(ssl_config, ctx->hostconf->authority.hostport);
                return 0;
            }
        }
    }

/* disable tls compression to avoid "CRIME" attacks (see http://en.wikipedia.org/wiki/CRIME) */
#ifdef SSL_OP_NO_COMPRESSION
    ssl_options |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NO_RENEGOTIATION
    ssl_options |= SSL_OP_NO_RENEGOTIATION;
#endif

    /* setup */
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ssl_ctx, ssl_options);

    SSL_CTX_set_session_id_context(ssl_ctx, H2O_SESSID_CTX, H2O_SESSID_CTX_LEN);

    setup_ecc_key(ssl_ctx);
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, (*certificate_file)->data.scalar) != 1) {
        h2o_configurator_errprintf(cmd, *certificate_file, "failed to load certificate file:%s\n",
                                   (*certificate_file)->data.scalar);
        ERR_print_errors_cb(on_openssl_print_errors, stderr);
        goto Error;
    }
    if (use_neverbleed) {
        /* disable neverbleed in case the process is not going to serve requests */
        switch (conf.run_mode) {
        case RUN_MODE_DAEMON:
        case RUN_MODE_MASTER:
            use_neverbleed = 0;
            break;
        default:
            break;
        }
    }
    if (use_neverbleed) {
        char errbuf[NEVERBLEED_ERRBUF_SIZE];
        if (neverbleed == NULL) {
            neverbleed_post_fork_cb = on_neverbleed_fork;
            neverbleed = h2o_mem_alloc(sizeof(*neverbleed));
            if (neverbleed_init(neverbleed, errbuf) != 0) {
                fprintf(stderr, "%s\n", errbuf);
                abort();
            }
        }
        if (neverbleed_load_private_key_file(neverbleed, ssl_ctx, (*key_file)->data.scalar, errbuf) != 1) {
            h2o_configurator_errprintf(cmd, *key_file, "failed to load private key file:%s:%s\n", (*key_file)->data.scalar, errbuf);
            goto Error;
        }
    } else {
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, (*key_file)->data.scalar, SSL_FILETYPE_PEM) != 1) {
            h2o_configurator_errprintf(cmd, *key_file, "failed to load private key file:%s\n", (*key_file)->data.scalar);
            ERR_print_errors_cb(on_openssl_print_errors, stderr);
            goto Error;
        }
    }
    if (cipher_suite != NULL && SSL_CTX_set_cipher_list(ssl_ctx, (*cipher_suite)->data.scalar) != 1) {
        h2o_configurator_errprintf(cmd, *cipher_suite, "failed to setup SSL cipher suite\n");
        ERR_print_errors_cb(on_openssl_print_errors, stderr);
        goto Error;
    }
    if (dh_file != NULL) {
        BIO *bio = BIO_new_file((*dh_file)->data.scalar, "r");
        if (bio == NULL) {
            h2o_configurator_errprintf(cmd, *dh_file, "failed to load dhparam file:%s\n", (*dh_file)->data.scalar);
            ERR_print_errors_cb(on_openssl_print_errors, stderr);
            goto Error;
        }
        DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (dh == NULL) {
            h2o_configurator_errprintf(cmd, *dh_file, "failed to load dhparam file:%s\n", (*dh_file)->data.scalar);
            ERR_print_errors_cb(on_openssl_print_errors, stderr);
            goto Error;
        }
        SSL_CTX_set_tmp_dh(ssl_ctx, dh);
        SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
        DH_free(dh);
    }

/* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(ssl_ctx, h2o_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(ssl_ctx, h2o_alpn_protocols);
#endif

    /* set SNI callback to the first SSL context, when and only when it should be used */
    if (listener->ssl.size == 1) {
        SSL_CTX_set_tlsext_servername_callback(listener->ssl.entries[0]->ctx, on_sni_callback);
        SSL_CTX_set_tlsext_servername_arg(listener->ssl.entries[0]->ctx, listener);
    }

    /* create a new entry in the SSL context list */
    struct listener_ssl_config_t *ssl_config = h2o_mem_alloc(sizeof(*ssl_config));
    memset(ssl_config, 0, sizeof(*ssl_config));
    h2o_vector_reserve(NULL, &listener->ssl, listener->ssl.size + 1);
    listener->ssl.entries[listener->ssl.size++] = ssl_config;
    if (ctx->hostconf != NULL) {
        listener_setup_ssl_add_host(ssl_config, ctx->hostconf->authority.hostport);
    }
    ssl_config->ctx = ssl_ctx;
    ssl_config->certificate_file = h2o_strdup(NULL, (*certificate_file)->data.scalar, SIZE_MAX).base;
    ssl_config->http2_origin_frame = http2_origin_frame;

#ifndef OPENSSL_NO_OCSP
    SSL_CTX_set_tlsext_status_cb(ssl_ctx, on_staple_ocsp_ossl);
    SSL_CTX_set_tlsext_status_arg(ssl_ctx, ssl_config);
#endif

    if (use_picotls) {
        const char *errstr = listener_setup_ssl_picotls(listener, ssl_config, ssl_ctx);
        if (errstr != NULL)
            h2o_configurator_errprintf(cmd, *ssl_node, "%s; TLS 1.3 will be disabled\n", errstr);
        if (listener->quic.ctx != NULL) {
            listener->quic.ctx->tls = h2o_socket_ssl_get_picotls_context(ssl_ctx);
            assert(listener->quic.ctx->tls != NULL);
            quicly_amend_ptls_context(listener->quic.ctx->tls);
        }
    } else if (listener->quic.ctx != NULL) {
        h2o_configurator_errprintf(cmd, *ssl_node, "QUIC support requires TLS 1.3 using picotls");
        goto Error;
    }

    /* congestion control is a concept of the transport but we want to control it per-host, hence defined here */
    if (cc_node != NULL) {
        if (listener->quic.ctx == NULL) {
            /* TCP; CC name is kept in the SSL config */
            ssl_config->tcp_congestion_controller = h2o_strdup(NULL, (*cc_node)->data.scalar, SIZE_MAX);
        } else {
            /* QUIC; the context is modified directly */
            if (listener->ssl.size > 1) {
                h2o_configurator_errprintf(cmd, *cc_node,
                                           "[warning] Setting ignored. At the moment, only the first listen entry for a given "
                                           "address:port tuple can specify the QUIC congestion controller");
            }
            if (strcasecmp((*cc_node)->data.scalar, "reno") == 0) {
                listener->quic.ctx->init_cc = &quicly_cc_reno_init;
            } else if (strcasecmp((*cc_node)->data.scalar, "cubic") == 0) {
                listener->quic.ctx->init_cc = &quicly_cc_cubic_init;
            } else {
                h2o_configurator_errprintf(cmd, *cc_node, "specified congestion controller is unknown or unspported for QUIC");
                goto Error;
            }
        }
    }

    pthread_mutex_init(&ssl_config->dynamic.mutex, NULL);
    build_ssl_dynamic_data(ssl_config, NULL);
    ssl_config->ocsp_stapling.cmd = ocsp_update_cmd != NULL ? h2o_strdup(NULL, (*ocsp_update_cmd)->data.scalar, SIZE_MAX).base
                                                            : "share/h2o/fetch-ocsp-response";
    if (ocsp_update_interval != 0) {
        switch (conf.run_mode) {
        case RUN_MODE_WORKER:
            ssl_config->ocsp_stapling.interval =
                ocsp_update_interval; /* is also used as a flag for indicating if the updater thread was spawned */
            ssl_config->ocsp_stapling.max_failures = ocsp_max_failures;
            h2o_multithread_create_thread(&ssl_config->ocsp_stapling.updater_tid, NULL, ocsp_updater_thread, ssl_config);
            break;
        case RUN_MODE_MASTER:
        case RUN_MODE_DAEMON:
            /* nothing to do */
            break;
        case RUN_MODE_TEST: {
            h2o_buffer_t *respbuf;
            fprintf(stderr, "[OCSP Stapling] testing for certificate file:%s\n", (*certificate_file)->data.scalar);
            switch (get_ocsp_response((*certificate_file)->data.scalar, ssl_config->ocsp_stapling.cmd, &respbuf)) {
            case 0:
                h2o_buffer_dispose(&respbuf);
                fprintf(stderr, "[OCSP Stapling] stapling works for file:%s\n", (*certificate_file)->data.scalar);
                break;
            case EX_TEMPFAIL:
                h2o_configurator_errprintf(cmd, *certificate_file, "[OCSP Stapling] temporary failed for file:%s\n",
                                           (*certificate_file)->data.scalar);
                break;
            default:
                h2o_configurator_errprintf(cmd, *certificate_file, "[OCSP Stapling] does not work, will be disabled for file:%s\n",
                                           (*certificate_file)->data.scalar);
                break;
            }
        } break;
        }
    }

    return 0;

Error:
    if (ssl_ctx != NULL)
        SSL_CTX_free(ssl_ctx);
    return -1;
}

static struct listener_config_t *find_listener(struct sockaddr *addr, socklen_t addrlen, int is_quic)
{
    size_t i;

    for (i = 0; i != conf.num_listeners; ++i) {
        struct listener_config_t *listener = conf.listeners[i];
        if (listener->addrlen == addrlen && h2o_socket_compare_address((void *)&listener->addr, addr, 1) == 0 &&
            (listener->quic.ctx != NULL) == is_quic)
            return listener;
    }

    return NULL;
}

static struct listener_config_t *add_listener(int fd, struct sockaddr *addr, socklen_t addrlen, int is_global, int proxy_protocol)
{
    struct listener_config_t *listener = h2o_mem_alloc(sizeof(*listener));

    memcpy(&listener->addr, addr, addrlen);
    listener->fd = fd;
    listener->addrlen = addrlen;
    if (is_global) {
        listener->hosts = NULL;
    } else {
        listener->hosts = h2o_mem_alloc(sizeof(listener->hosts[0]));
        listener->hosts[0] = NULL;
    }
    memset(&listener->ssl, 0, sizeof(listener->ssl));
    memset(&listener->quic, 0, sizeof(listener->quic));
    listener->quic.qpack = (h2o_http3_qpack_context_t){.encoder_table_capacity = 4096 /* our default */};
    listener->proxy_protocol = proxy_protocol;
    listener->tcp_congestion_controller = h2o_iovec_init(NULL, 0);

    conf.listeners = h2o_mem_realloc(conf.listeners, sizeof(*conf.listeners) * (conf.num_listeners + 1));
    conf.listeners[conf.num_listeners++] = listener;

    return listener;
}

static int find_listener_from_server_starter(struct sockaddr *addr, int type)
{
    size_t i;

    assert(conf.server_starter.fds != NULL);
    assert(conf.server_starter.num_fds != 0);

    for (i = 0; i != conf.server_starter.num_fds; ++i) {
        struct {
            union {
                struct sockaddr sa;
                struct sockaddr_storage ss;
            } addr;
            int type;
        } actual;
        socklen_t l = sizeof(actual.addr);
        if (getsockname(conf.server_starter.fds[i], &actual.addr.sa, &l) != 0) {
            fprintf(stderr, "could not get the socket address of fd %d given as $" SERVER_STARTER_PORT "\n",
                    conf.server_starter.fds[i]);
            exit(EX_CONFIG);
        }
        l = sizeof(actual.type);
        if (getsockopt(conf.server_starter.fds[i], SOL_SOCKET, SO_TYPE, &actual.type, &l) != 0) {
            fprintf(stderr, "could not get the socket type of fd %d given as $" SERVER_STARTER_PORT "\n",
                    conf.server_starter.fds[i]);
            exit(EX_CONFIG);
        }
        if (h2o_socket_compare_address(&actual.addr.sa, addr, 1) == 0 && actual.type == type)
            goto Found;
    }
    /* not found */
    return -1;

Found:
    conf.server_starter.bound_fd_map[i] = 1;
    return conf.server_starter.fds[i];
}

static int open_unix_listener(h2o_configurator_command_t *cmd, yoml_t *node, struct sockaddr_un *sa, yoml_t **owner_node,
                              yoml_t **permission_node)
{
    struct stat st;
    int fd = -1;
    struct passwd *owner = NULL, pwbuf;
    char pwbuf_buf[65536];
    unsigned mode = UINT_MAX;

    /* obtain owner and permission */
    if (owner_node != NULL) {
        if (getpwnam_r((*owner_node)->data.scalar, &pwbuf, pwbuf_buf, sizeof(pwbuf_buf), &owner) != 0 || owner == NULL) {
            h2o_configurator_errprintf(cmd, *owner_node, "failed to obtain uid of user:%s: %s", (*owner_node)->data.scalar,
                                       strerror(errno));
            goto ErrorExit;
        }
    }
    if (permission_node != NULL && h2o_configurator_scanf(cmd, *permission_node, "%o", &mode) != 0) {
        h2o_configurator_errprintf(cmd, *permission_node, "`permission` must be an octal number");
        goto ErrorExit;
    }

    /* remove existing socket file as suggested in #45 */
    if (lstat(sa->sun_path, &st) == 0) {
        if (S_ISSOCK(st.st_mode)) {
            unlink(sa->sun_path);
        } else {
            h2o_configurator_errprintf(cmd, node, "path:%s already exists and is not an unix socket.", sa->sun_path);
            goto ErrorExit;
        }
    }

    /* add new listener */
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 || bind(fd, (void *)sa, sizeof(*sa)) != 0 || listen(fd, H2O_SOMAXCONN) != 0) {
        h2o_configurator_errprintf(NULL, node, "failed to listen to socket:%s: %s", sa->sun_path, strerror(errno));
        goto ErrorExit;
    }
    set_cloexec(fd);

    /* set file owner and permission */
    if (owner != NULL && chown(sa->sun_path, owner->pw_uid, owner->pw_gid) != 0) {
        h2o_configurator_errprintf(NULL, node, "failed to chown socket:%s to %s: %s", sa->sun_path, owner->pw_name,
                                   strerror(errno));
        goto ErrorExit;
    }
    if (mode != UINT_MAX && chmod(sa->sun_path, mode) != 0) {
        h2o_configurator_errprintf(NULL, node, "failed to chmod socket:%s to %o: %s", sa->sun_path, mode, strerror(errno));
        goto ErrorExit;
    }

    return fd;

ErrorExit:
    if (fd != -1)
        close(fd);
    return -1;
}

static void socket_reuseport(int fd)
{
#if H2O_USE_REUSEPORT
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, H2O_SO_REUSEPORT, &opt, sizeof(opt)) != 0)
        fprintf(stderr, "[warning] setsockopt(SO_REUSEPORT) failed:%s\n", strerror(errno));
#endif
}

/**
 * Opens an INET or INET6 socket for accepting connections. When the protocol is UDP, SO_REUSEPORT is set if available.
 */
static int open_listener(int domain, int type, int protocol, struct sockaddr *addr, socklen_t addrlen)
{
    int fd;

    if ((fd = socket(domain, type, protocol)) == -1)
        goto Error;
    set_cloexec(fd);

    /* set SO_*, IP_* options */
#ifdef IPV6_V6ONLY
    if (domain == AF_INET6) {
        int flag = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0) {
            perror("setsockopt(IPV6_V6ONLY) failed");
            goto Error;
        }
    }
#endif
    switch (type) {
    case SOCK_STREAM: {
        if (conf.tcp_reuseport)
            socket_reuseport(fd);
        /* TCP: set SO_REUSEADDR flag to avoid TIME_WAIT after shutdown */
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
            goto Error;
    } break;
    case SOCK_DGRAM:
        /* UDP: set SO_REUSEPORT and DF bit */
        socket_reuseport(fd);
        h2o_socket_set_df_bit(fd, domain);
        break;
    default:
        h2o_fatal("unexpected socket type %d", type);
        break;
    }

    /* bind */
    if (bind(fd, addr, addrlen) != 0)
        goto Error;

    /* TCP-specific actions */
    if (protocol == IPPROTO_TCP) {
#ifdef TCP_DEFER_ACCEPT
        { /* set TCP_DEFER_ACCEPT */
            int flag = 1;
            if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &flag, sizeof(flag)) != 0)
                goto Error;
        }
#endif
        /* listen */
        if (listen(fd, H2O_SOMAXCONN) != 0)
            goto Error;
        /* set TCP_FASTOPEN; when tfo_queues is zero TFO is always disabled */
        if (conf.tfo_queues > 0) {
#ifdef TCP_FASTOPEN
            int tfo_queues;
#ifdef __APPLE__
            /* In OS X, the option value for TCP_FASTOPEN must be 1 if is's enabled */
            tfo_queues = 1;
#else
            tfo_queues = conf.tfo_queues;
#endif
            if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, (const void *)&tfo_queues, sizeof(tfo_queues)) != 0)
                fprintf(stderr, "[warning] failed to set TCP_FASTOPEN:%s\n", strerror(errno));
#else
            assert(!"conf.tfo_queues not zero on platform without TCP_FASTOPEN");
#endif
        }
    }

    return fd;

Error:
    if (fd != -1)
        close(fd);
    return -1;
}

static int open_inet_listener(h2o_configurator_command_t *cmd, yoml_t *node, const char *hostname, const char *servname, int domain,
                              int type, int protocol, struct sockaddr *addr, socklen_t addrlen)
{
    int fd;

    if ((fd = open_listener(domain, type, protocol, addr, addrlen)) == -1)
        h2o_configurator_errprintf(cmd, node, "failed to listen to %s port %s:%s: %s", protocol == IPPROTO_TCP ? "TCP" : "UDP",
                                   hostname != NULL ? hostname : "ANY", servname, strerror(errno));

    return fd;
}

static void setsockopt_recvpktinfo(int fd, int family)
{
    switch (family) {
    case AF_INET: {
#if defined(IP_PKTINFO) /* this is the de-facto API (that works on both linux, macOS) */
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) != 0)
            h2o_fatal("failed to set IP_PKTINFO option:%s", strerror(errno));
#elif defined(IP_RECVDSTADDR) /* *BSD */
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on)) != 0)
            h2o_fatal("failed to set IP_RECVDSTADDR option:%s", strerror(errno));
#endif
    } break;
    case AF_INET6: {
#ifdef IPV6_RECVPKTINFO /* API defined by RFC 3542 */
        int on = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0)
            h2o_fatal("failed to set IPV6_RECVPKTINFO option:%s", strerror(errno));
#endif
    } break;
    default:
        break;
    }
}

static struct addrinfo *resolve_address(h2o_configurator_command_t *cmd, yoml_t *node, int socktype, int protocol,
                                        const char *hostname, const char *servname)
{
    struct addrinfo hints, *res;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;

    if ((error = getaddrinfo(hostname, servname, &hints, &res)) != 0) {
        h2o_configurator_errprintf(cmd, node, "failed to resolve address: %s", gai_strerror(error));
        return NULL;
    } else if (res == NULL) {
        h2o_configurator_errprintf(cmd, node, "failed to resolve address: getaddrinfo returned an empty list");
        return NULL;
    }

    return res;
}

static void notify_all_threads(void)
{
    unsigned i;
    for (i = 0; i != conf.thread_map.size; ++i)
        h2o_multithread_send_message(&conf.threads[i].server_notifications, NULL);
}

static int num_connections(int delta)
{
    return __sync_fetch_and_add(&conf.state._num_connections, delta);
}

static int num_quic_connections(int delta)
{
    return __sync_fetch_and_add(&conf.state._num_quic_connections, delta);
}

static unsigned long num_sessions(int delta)
{
    return __sync_fetch_and_add(&conf.state._num_sessions, delta);
}

static void on_connection_close(void)
{
    int prev_num_connections = num_connections(-1);

    if (prev_num_connections == conf.max_connections) {
        /* ready to accept new connections. wake up all the threads! */
        notify_all_threads();
    }
}

static void on_http3_conn_destroy(h2o_quic_conn_t *conn)
{
    on_connection_close();
    num_quic_connections(-1);

    H2O_HTTP3_CONN_CALLBACKS.super.destroy_connection(conn);
}

static int on_config_listen(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    const char *hostname = NULL, *servname, *type = "tcp";
    yoml_t **ssl_node = NULL, **owner_node = NULL, **permission_node = NULL, **quic_node = NULL, **cc_node = NULL;
    int proxy_protocol = 0;

    /* fetch servname (and hostname) */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        servname = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t **port_node, **host_node, **type_node, **proxy_protocol_node;
        if (h2o_configurator_parse_mapping(
                cmd, node, "port:s", "host:s,type:s,owner:s,permission:*,ssl:m,proxy-protocol:*,quic:m,cc:s", &port_node,
                &host_node, &type_node, &owner_node, &permission_node, &ssl_node, &proxy_protocol_node, &quic_node, &cc_node) != 0)
            return -1;
        servname = (*port_node)->data.scalar;
        if (host_node != NULL)
            hostname = (*host_node)->data.scalar;
        if (type_node != NULL) {
            type = (*type_node)->data.scalar;
        } else if (quic_node != NULL) {
            type = "quic";
        }
        if (proxy_protocol_node != NULL &&
            (proxy_protocol = (int)h2o_configurator_get_one_of(cmd, *proxy_protocol_node, "OFF,ON")) == -1)
            return -1;
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "value must be a string or a mapping (with keys: `port` and optionally `host`)");
        return -1;
    }

    if (strcmp(type, "unix") == 0) {

        if (cc_node != NULL)
            h2o_configurator_errprintf(cmd, *cc_node, "[warning] cannot set congestion controller for unix socket");

        /* unix socket */
        struct sockaddr_un sa;
        int listener_is_new;
        struct listener_config_t *listener;

        /* build sockaddr */
        memset(&sa, 0, sizeof(sa));
        if (strlen(servname) >= sizeof(sa.sun_path)) {
            h2o_configurator_errprintf(cmd, node, "path:%s is too long as a unix socket name", servname);
            return -1;
        }
        sa.sun_family = AF_UNIX;
        strcpy(sa.sun_path, servname);
        /* find existing listener or create a new one */
        listener_is_new = 0;
        if ((listener = find_listener((void *)&sa, sizeof(sa), 0)) == NULL) {
            int fd = -1;
            switch (conf.run_mode) {
            case RUN_MODE_WORKER:
                if (conf.server_starter.fds != NULL) {
                    if ((fd = find_listener_from_server_starter((void *)&sa, SOCK_STREAM)) == -1) {
                        h2o_configurator_errprintf(cmd, node, "unix socket:%s is not being bound to the server\n", sa.sun_path);
                        return -1;
                    }
                } else {
                    if ((fd = open_unix_listener(cmd, node, &sa, owner_node, permission_node)) == -1)
                        return -1;
                }
                break;
            default:
                break;
            }
            listener = add_listener(fd, (struct sockaddr *)&sa, sizeof(sa), ctx->hostconf == NULL, proxy_protocol);
            listener_is_new = 1;
        } else if (listener->proxy_protocol != proxy_protocol) {
            goto ProxyConflict;
        }
        if (listener_setup_ssl(cmd, ctx, node, ssl_node, NULL, listener, listener_is_new) != 0)
            return -1;
        if (listener->hosts != NULL && ctx->hostconf != NULL)
            h2o_append_to_null_terminated_list((void *)&listener->hosts, ctx->hostconf);

    } else if (strcmp(type, "tcp") == 0) {

        /* TCP socket */
#if !defined(TCP_CONGESTION)
        if (cc_node != NULL)
            h2o_configurator_errprintf(
                cmd, *cc_node, "[warning] Setting ignored. TCP congestion controller cannot be set at runtime on this environment");
#endif
        struct addrinfo *res, *ai;
        if ((res = resolve_address(cmd, node, SOCK_STREAM, IPPROTO_TCP, hostname, servname)) == NULL)
            return -1;
        for (ai = res; ai != NULL; ai = ai->ai_next) {
            struct listener_config_t *listener = find_listener(ai->ai_addr, ai->ai_addrlen, 0);
            int listener_is_new = 0;
            if (listener == NULL) {
                int fd = -1;
                switch (conf.run_mode) {
                case RUN_MODE_WORKER:
                    if (conf.server_starter.fds != NULL) {
                        if ((fd = find_listener_from_server_starter(ai->ai_addr, SOCK_STREAM)) == -1) {
                            h2o_configurator_errprintf(cmd, node, "tcp socket:%s:%s is not being bound to the server\n", hostname,
                                                       servname);
                            freeaddrinfo(res);
                            return -1;
                        }
                    } else {
                        if ((fd = open_inet_listener(cmd, node, hostname, servname, ai->ai_family, ai->ai_socktype, ai->ai_protocol,
                                                     ai->ai_addr, ai->ai_addrlen)) == -1) {
                            freeaddrinfo(res);
                            return -1;
                        }
                    }
                    break;
                default:
                    break;
                }
                listener = add_listener(fd, ai->ai_addr, ai->ai_addrlen, ctx->hostconf == NULL, proxy_protocol);
                if (cc_node != NULL)
                    listener->tcp_congestion_controller = h2o_strdup(NULL, (*cc_node)->data.scalar, SIZE_MAX);
                listener_is_new = 1;
            } else if (listener->proxy_protocol != proxy_protocol) {
                freeaddrinfo(res);
                goto ProxyConflict;
            }
            if (listener_setup_ssl(cmd, ctx, node, ssl_node, cc_node, listener, listener_is_new) != 0) {
                freeaddrinfo(res);
                return -1;
            }
            if (listener->hosts != NULL && ctx->hostconf != NULL)
                h2o_append_to_null_terminated_list((void *)&listener->hosts, ctx->hostconf);
        }
        freeaddrinfo(res);

    } else if (strcmp(type, "quic") == 0) {

        /* QUIC socket */
        struct addrinfo *res, *ai;
        if (ssl_node == NULL) {
            h2o_configurator_errprintf(cmd, node, "QUIC endpoint must have an accompanying SSL configuration");
            return -1;
        }
        if ((res = resolve_address(cmd, node, SOCK_DGRAM, IPPROTO_UDP, hostname, servname)) == NULL)
            return -1;
        for (ai = res; ai != NULL; ai = ai->ai_next) {
            struct listener_config_t *listener = find_listener(ai->ai_addr, ai->ai_addrlen, 1);
            int listener_is_new = 0;
            if (listener == NULL) {
                int fd = -1;
                switch (conf.run_mode) {
                case RUN_MODE_WORKER:
                    if (conf.server_starter.fds != NULL) {
                        if ((fd = find_listener_from_server_starter(ai->ai_addr, ai->ai_socktype)) == -1) {
                            h2o_configurator_errprintf(cmd, node, "udp socket:%s:%s is not being bound to the server\n", hostname,
                                                       servname);
                            freeaddrinfo(res);
                            return -1;
                        }
                    } else if ((fd = open_inet_listener(cmd, node, hostname, servname, ai->ai_family, ai->ai_socktype,
                                                        ai->ai_protocol, ai->ai_addr, ai->ai_addrlen)) == -1) {
                        freeaddrinfo(res);
                        return -1;
                    }
                    setsockopt_recvpktinfo(fd, ai->ai_family);
                    break;
                default:
                    break;
                }
                quicly_context_t *quic = h2o_mem_alloc(sizeof(*quic));
                *quic = quicly_spec_context;
                quic->cid_encryptor = &quic_cid_encryptor;
                quic->generate_resumption_token = &quic_resumption_token_generator;
                listener = add_listener(fd, ai->ai_addr, ai->ai_addrlen, ctx->hostconf == NULL, 0);
                listener->quic.ctx = quic;
                if (quic_node != NULL) {
                    yoml_t **retry_node, **sndbuf, **rcvbuf, **amp_limit, **qpack_encoder_table_capacity;
                    if (h2o_configurator_parse_mapping(
                            cmd, *quic_node, NULL, "retry:s,sndbuf:s,rcvbuf:s,amp-limit:s,qpack-encoder-table-capacity:s",
                            &retry_node, &sndbuf, &rcvbuf, &amp_limit, &qpack_encoder_table_capacity) != 0)
                        return -1;
                    if (retry_node != NULL) {
                        ssize_t on = h2o_configurator_get_one_of(cmd, *retry_node, "OFF,ON");
                        if (on == -1)
                            return -1;
                        listener->quic.send_retry = (unsigned)on;
                    }
                    if (sndbuf != NULL) {
                        unsigned sz;
                        if (h2o_configurator_scanf(cmd, *sndbuf, "%u", &sz) != 0)
                            return -1;
                        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)) != 0)
                            h2o_configurator_errprintf(cmd, *quic_node, "setsockopt(SO_SNDBUF) failed:%s", strerror(errno));
                    }
                    if (rcvbuf != NULL) {
                        unsigned sz;
                        if (h2o_configurator_scanf(cmd, *rcvbuf, "%u", &sz) != 0)
                            return -1;
                        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)) != 0)
                            h2o_configurator_errprintf(cmd, *quic_node, "setsockopt(SO_RCVBUF) failed:%s", strerror(errno));
                    }
                    if (amp_limit != NULL) {
                        if (h2o_configurator_scanf(cmd, *amp_limit, "%" SCNu16,
                                                   &listener->quic.ctx->pre_validation_amplification_limit) != 0)
                            return -1;
                    }
                    if (qpack_encoder_table_capacity != NULL) {
                        if (h2o_configurator_scanf(cmd, *qpack_encoder_table_capacity, "%" SCNu32,
                                                   &listener->quic.qpack.encoder_table_capacity) != 0)
                            return -1;
                    }
                }
                listener_is_new = 1;
            }
            if (listener_setup_ssl(cmd, ctx, node, ssl_node, cc_node, listener, listener_is_new) != 0) {
                freeaddrinfo(res);
                return -1;
            }
            if (listener->hosts != NULL && ctx->hostconf != NULL)
                h2o_append_to_null_terminated_list((void *)&listener->hosts, ctx->hostconf);
        }
        freeaddrinfo(res);

    } else {

        h2o_configurator_errprintf(cmd, node, "unknown listen type: %s", type);
        return -1;
    }

    return 0;

ProxyConflict:
    h2o_configurator_errprintf(cmd, node, "`proxy-protocol` cannot be turned %s, already defined as opposite",
                               proxy_protocol ? "on" : "off");
    return -1;
}

static int on_config_listen_enter(h2o_configurator_t *_configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return 0;
}

static int on_config_listen_exit(h2o_configurator_t *_configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (ctx->pathconf != NULL) {
        /* skip */
    } else if (ctx->hostconf == NULL) {
        /* at global level: bind all hostconfs to the global-level listeners */
        size_t i;
        for (i = 0; i != conf.num_listeners; ++i) {
            struct listener_config_t *listener = conf.listeners[i];
            if (listener->hosts == NULL)
                listener->hosts = conf.globalconf.hosts;
        }
    } else if (ctx->pathconf == NULL) {
        /* at host-level */
        if (conf.num_listeners == 0) {
            h2o_configurator_errprintf(
                NULL, node,
                "mandatory configuration directive `listen` does not exist, neither at global level or at this host level");
            return -1;
        }
    }

    return 0;
}

static int on_config_user(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    errno = 0;
    if (getpwnam(node->data.scalar) == NULL) {
        if (errno == 0) {
            h2o_configurator_errprintf(cmd, node, "user:%s does not exist", node->data.scalar);
        } else {
            perror("getpwnam");
        }
        return -1;
    }
    ctx->globalconf->user = h2o_strdup(NULL, node->data.scalar, SIZE_MAX).base;
    return 0;
}

static int on_config_pid_file(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    conf.pid_file = h2o_strdup(NULL, node->data.scalar, SIZE_MAX).base;
    return 0;
}

static int on_config_error_log(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    conf.error_log = h2o_strdup(NULL, node->data.scalar, SIZE_MAX).base;
    return 0;
}

static int on_config_max_connections(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%d", &conf.max_connections);
}

static int on_config_max_quic_connections(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return h2o_configurator_scanf(cmd, node, "%d", &conf.max_quic_connections);
}

static inline int on_config_num_threads_add_cpu(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (node->type != YOML_TYPE_SCALAR) {
        h2o_configurator_errprintf(cmd, node, "CPUs in cpu sequence must be a scalar");
        return -1;
    }

    const char *cpu_spec = node->data.scalar;
    unsigned cpu_low, cpu_high, cpu_num;
    int pos;
    if (index(cpu_spec, '-') == NULL) {
        if (sscanf(cpu_spec, "%u%n", &cpu_low, &pos) != 1 || pos != strlen(cpu_spec))
            goto Error;
        cpu_high = cpu_low;
    } else {
        if (sscanf(cpu_spec, "%u-%u%n", &cpu_low, &cpu_high, &pos) != 2 || pos != strlen(cpu_spec))
            goto Error;
        if (cpu_low > cpu_high)
            goto Error;
    }
    for (cpu_num = cpu_low; cpu_num <= cpu_high; cpu_num++) {
        h2o_vector_reserve(NULL, &conf.thread_map, conf.thread_map.size + 1);
        conf.thread_map.entries[conf.thread_map.size++] = cpu_num;
    }
    return 0;
Error:
    h2o_configurator_errprintf(
        cmd, node, "Invalid CPU number: CPUs must be specified as a non-negative number or as a range of non-negative numbers");
    return -1;
}

static int on_config_num_threads(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    conf.thread_map.size = 0;
    if (node->type == YOML_TYPE_SCALAR) {
        size_t i, num_threads = 0;
        if (h2o_configurator_scanf(cmd, node, "%zu", &num_threads) != 0)
            return -1;
        h2o_vector_reserve(NULL, &conf.thread_map, num_threads);
        for (i = 0; i < num_threads; i++)
            conf.thread_map.entries[conf.thread_map.size++] = -1;
    } else if (node->type == YOML_TYPE_SEQUENCE) {
        /* a sequence is treated as a list of CPUs to bind to, one per thread to instantiate */
#ifdef H2O_HAS_PTHREAD_SETAFFINITY_NP
        size_t i;
        for (i = 0; i < node->data.sequence.size; i++) {
            if (on_config_num_threads_add_cpu(cmd, ctx, node->data.sequence.elements[i]) != 0)
                return -1;
        }
#else
        h2o_configurator_errprintf(
            cmd, node, "Can't handle a CPU list, this platform doesn't support thread pinning via `pthread_setaffinity_np`");
        return -1;
#endif
    }
    if (conf.thread_map.size == 0) {
        h2o_configurator_errprintf(cmd, node, "num-threads must be >=1");
        return -1;
    }
    return 0;
}

static int on_config_num_quic_threads(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (h2o_configurator_scanf(cmd, node, "%zu", &conf.quic.num_threads) != 0)
        return -1;
    return 0;
}

static int on_config_num_name_resolution_threads(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (h2o_configurator_scanf(cmd, node, "%zu", &h2o_hostinfo_max_threads) != 0)
        return -1;
    if (h2o_hostinfo_max_threads == 0) {
        h2o_configurator_errprintf(cmd, node, "num-name-resolution-threads must be >=1");
        return -1;
    }
    return 0;
}

static int on_config_tcp_fastopen(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (h2o_configurator_scanf(cmd, node, "%d", &conf.tfo_queues) != 0)
        return -1;
#ifndef TCP_FASTOPEN
    if (conf.tfo_queues != 0) {
        h2o_configurator_errprintf(cmd, node, "[warning] ignoring the value; the platform does not support TCP_FASTOPEN");
        conf.tfo_queues = 0;
    }
#endif
    return 0;
}

static int configure_quic_forward_node(h2o_configurator_command_t *cmd, struct st_h2o_quic_forward_node_t *target,
                                       yoml_mapping_element_t *input)
{
    char hostname[257], servname[sizeof(H2O_UINT16_LONGEST_STR)];
    struct addrinfo *ai = NULL;
    int success = 0;

    target->fd = -1;

    /* parse key */
    if (h2o_configurator_scanf(cmd, input->key, "%" SCNu64, &target->id) != 0)
        goto Exit;

    { /* convert value to hostname and servname */
        h2o_iovec_t hostvec;
        uint16_t portnum;
        if (input->value->type != YOML_TYPE_SCALAR ||
            h2o_url_parse_hostport(input->value->data.scalar, strlen(input->value->data.scalar), &hostvec, &portnum) == NULL ||
            hostvec.len >= sizeof(hostname)) {
            h2o_configurator_errprintf(cmd, input->value, "values of mapping must be in the form of `host[:port]`");
            goto Exit;
        }
        memcpy(hostname, hostvec.base, hostvec.len);
        hostname[hostvec.len] = '\0';
        sprintf(servname, "%" PRIu16, portnum);
    }

    /* lookup the address */
    if ((ai = resolve_address(cmd, input->value, SOCK_DGRAM, IPPROTO_UDP, hostname, servname)) == NULL)
        goto Exit;

    /* open connected socket */
    if ((target->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1 ||
        connect(target->fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        h2o_configurator_errprintf(cmd, input->value, "failed to connect to %s:%s", input->value->data.scalar, strerror(errno));
        goto Exit;
    }

    success = 1;
Exit:
    if (ai != NULL)
        freeaddrinfo(ai);
    if (!success && target->fd != -1)
        close(target->fd);
    return success ? 0 : -1;
}

static int on_config_quic_nodes(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    yoml_t **self_node, **mapping_node;

    if (h2o_configurator_parse_mapping(cmd, node, "self:s,mapping:m", NULL, &self_node, &mapping_node) != 0)
        return -1;

    /* obtain node-id of this server */
    if (h2o_configurator_scanf(cmd, *self_node, "%" SCNu64, &conf.quic.node_id) != 0)
        return -1;

    /* build list of servers */
    h2o_vector_reserve(NULL, &conf.quic.forward_nodes, (*mapping_node)->data.mapping.size);
    size_t i;
    for (i = 0; i != (*mapping_node)->data.mapping.size; ++i) {
        if (configure_quic_forward_node(cmd, conf.quic.forward_nodes.entries + i, (*mapping_node)->data.mapping.elements + i) != 0)
            return -1;
    }
    conf.quic.forward_nodes.size = (*mapping_node)->data.mapping.size;

    return 0;
}

static int on_config_num_ocsp_updaters(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    ssize_t n;
    if (h2o_configurator_scanf(cmd, node, "%zd", &n) != 0)
        return -1;
    if (n <= 0) {
        h2o_configurator_errprintf(cmd, node, "num-ocsp-updaters must be >=1");
        return -1;
    }
    h2o_sem_set_capacity(&ocsp_updater_semaphore, n);
    return 0;
}

static int on_config_temp_buffer_path(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    char buf[sizeof(h2o_socket_buffer_mmap_settings.fn_template)];

    int len = snprintf(buf, sizeof(buf), "%s%s", node->data.scalar, strrchr(h2o_socket_buffer_mmap_settings.fn_template, '/'));
    if (len >= sizeof(buf)) {
        h2o_configurator_errprintf(cmd, node, "path is too long");
        return -1;
    }
    strcpy(h2o_socket_buffer_mmap_settings.fn_template, buf);

    return 0;
}

static int on_config_temp_buffer_threshold(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    /* if "OFF", disable temp buffers by setting the threshold to SIZE_MAX */
    if (strcasecmp(node->data.scalar, "OFF") == 0) {
        h2o_socket_buffer_mmap_settings.threshold = SIZE_MAX;
        return 0;
    }

    /* if not "OFF", it could be a number */
    if (h2o_configurator_scanf(cmd, node, "%zu", &h2o_socket_buffer_mmap_settings.threshold) != 0)
        return -1;

    if (h2o_socket_buffer_mmap_settings.threshold < 1048576) {
        h2o_configurator_errprintf(cmd, node, "threshold is too low (must be >= 1048576; OFF to disable)");
        return -1;
    }

    return 0;
}

static int on_config_crash_handler(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    conf.crash_handler = h2o_strdup(NULL, node->data.scalar, SIZE_MAX).base;
    return 0;
}

static int on_config_onoff(h2o_configurator_command_t *cmd, yoml_t *node, int *slot)
{
    ssize_t v;

    if ((v = h2o_configurator_get_one_of(cmd, node, "OFF,ON")) == -1)
        return -1;

    *slot = (int)v;
    return 0;
}

static int on_config_crash_handler_wait_pipe_close(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return on_config_onoff(cmd, node, &conf.crash_handler_wait_pipe_close);
}

static int on_tcp_reuseport(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return on_config_onoff(cmd, node, &conf.tcp_reuseport);
}

static yoml_t *load_config(yoml_parse_args_t *parse_args, yoml_t *source)
{
    FILE *fp;
    yaml_parser_t parser;
    yoml_t *yoml;

    if ((fp = fopen(parse_args->filename, "rb")) == NULL) {
        fprintf(stderr, "could not open configuration file %s: %s\n", parse_args->filename, strerror(errno));
        return NULL;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fp);

    yoml = yoml_parse_document(&parser, NULL, parse_args);

    if (yoml == NULL) {
        fprintf(stderr, "failed to parse configuration file %s line %d", parse_args->filename, (int)parser.problem_mark.line + 1);
        if (source != NULL) {
            fprintf(stderr, " (included from file %s line %d)", source->filename, (int)source->line + 1);
        }
        fprintf(stderr, ": %s\n", parser.problem);
    }

    yaml_parser_delete(&parser);

    fclose(fp);

    return yoml;
}

static yoml_t *resolve_tag(const char *tag, yoml_t *node, void *cb_arg);
static yoml_t *resolve_file_tag(yoml_t *node, resolve_tag_arg_t *arg)
{
    size_t i;
    yoml_t *loaded;

    if (node->type != YOML_TYPE_SCALAR) {
        fprintf(stderr, "value of the !file node must be a scalar");
        return NULL;
    }

    char *filename = node->data.scalar;

    /* check cache */
    for (i = 0; i != arg->node_cache.size; ++i) {
        resolve_tag_node_cache_entry_t *cached = arg->node_cache.entries + i;
        if (strcmp(filename, cached->filename.base) == 0) {
            ++cached->node->_refcnt;
            return cached->node;
        }
    }

    yoml_parse_args_t parse_args = {
        filename,          /* filename */
        NULL,              /* mem_set */
        {resolve_tag, arg} /* resolve_tag */
    };
    loaded = load_config(&parse_args, node);

    if (loaded != NULL) {
        /* cache newly loaded node */
        h2o_vector_reserve(NULL, &arg->node_cache, arg->node_cache.size + 1);
        resolve_tag_node_cache_entry_t entry = {h2o_strdup(NULL, filename, SIZE_MAX), loaded};
        arg->node_cache.entries[arg->node_cache.size++] = entry;
        ++loaded->_refcnt;
    }

    return loaded;
}

static yoml_t *resolve_env_tag(yoml_t *node, resolve_tag_arg_t *arg)
{
    if (node->type != YOML_TYPE_SCALAR) {
        fprintf(stderr, "value of !env must be a scalar");
        return NULL;
    }

    const char *value;
    if ((value = getenv(node->data.scalar)) == NULL)
        value = "";

    /* free old data (we need to reset tag; otherwise we might try to resolve the value once again if the same object is referred
     * more than once due to the use of aliases) */
    free(node->data.scalar);
    free(node->tag);
    node->tag = NULL;

    node->data.scalar = h2o_strdup(NULL, value, SIZE_MAX).base;
    ++node->_refcnt;

    return node;
}

static yoml_t *resolve_tag(const char *tag, yoml_t *node, void *cb_arg)
{
    resolve_tag_arg_t *arg = (resolve_tag_arg_t *)cb_arg;

    if (strcmp(tag, "!file") == 0) {
        return resolve_file_tag(node, arg);
    }

    if (strcmp(tag, "!env") == 0) {
        return resolve_env_tag(node, arg);
    }

    /* otherwise, return the node itself */
    ++node->_refcnt;
    return node;
}

static void dispose_resolve_tag_arg(resolve_tag_arg_t *arg)
{
    size_t i;
    for (i = 0; i != arg->node_cache.size; ++i) {
        resolve_tag_node_cache_entry_t *cached = arg->node_cache.entries + i;
        free(cached->filename.base);
        yoml_free(cached->node, NULL);
    }
    free(arg->node_cache.entries);
}

static void on_sigterm(int signo)
{
    conf.shutdown_requested = 1;
    if (!h2o_barrier_done(&conf.startup_sync_barrier)) {
        /* initialization hasn't completed yet, exit right away */
        exit(0);
    }
    notify_all_threads();
}

#ifdef LIBC_HAS_BACKTRACE

static int popen_crash_handler(void)
{
    char *cmd_fullpath = h2o_configurator_get_cmd_path(conf.crash_handler), *argv[] = {cmd_fullpath, NULL};
    int pipefds[2];

    /* create pipe */
    if (pipe(pipefds) != 0) {
        perror("pipe failed");
        return -1;
    }
    if (fcntl(pipefds[1], F_SETFD, FD_CLOEXEC) == -1) {
        perror("failed to set FD_CLOEXEC on pipefds[1]");
        return -1;
    }
    /* spawn the logger */
    int mapped_fds[] = {pipefds[0], 0, /* output of the pipe is connected to STDIN of the spawned process */
                        2, 1,          /* STDOUT of the spawned process in connected to STDERR of h2o */
                        -1};
    if (h2o_spawnp(cmd_fullpath, argv, mapped_fds, 0) == -1) {
        /* silently ignore error */
        close(pipefds[0]);
        close(pipefds[1]);
        return -1;
    }
    /* do the rest, and return the fd */
    close(pipefds[0]);
    return pipefds[1];
}

static int crash_handler_fd = -1;

static void on_sigfatal(int signo)
{
    fprintf(stderr, "received fatal signal %d\n", signo);

    h2o_set_signal_handler(signo, SIG_DFL);

    void *frames[128];
    int framecnt = backtrace(frames, sizeof(frames) / sizeof(frames[0]));
    backtrace_symbols_fd(frames, framecnt, crash_handler_fd);

    if (conf.crash_handler_wait_pipe_close) {
        struct pollfd pfd[1];
        pfd[0].fd = crash_handler_fd;
        pfd[0].events = POLLERR | POLLHUP;
        while (poll(pfd, 1, -1) == -1 && errno == EINTR)
            ;
    }

    raise(signo);
}

#endif /* LIBC_HAS_BACKTRACE */

static void setup_signal_handlers(void)
{
    h2o_set_signal_handler(SIGTERM, on_sigterm);
    h2o_set_signal_handler(SIGPIPE, SIG_IGN);
#ifdef LIBC_HAS_BACKTRACE
    if ((crash_handler_fd = popen_crash_handler()) == -1)
        crash_handler_fd = 2;
    h2o_set_signal_handler(SIGABRT, on_sigfatal);
    h2o_set_signal_handler(SIGBUS, on_sigfatal);
    h2o_set_signal_handler(SIGFPE, on_sigfatal);
    h2o_set_signal_handler(SIGILL, on_sigfatal);
    h2o_set_signal_handler(SIGSEGV, on_sigfatal);
#endif
}

struct st_h2o_quic_forwarded_t {
    union {
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
    } srcaddr, destaddr;
    int is_v6 : 1;
};

/* FIXME forward destaddr */
/* The format:
 * type:     0b10000000 (1 byte)
 * version:  0x91917000 (4 bytes)
 * destaddr: 1 or 7 or 19 bytes (UNSPEC, v4, v6)
 * srcaddr:  same as above
 * ttl:      1 byte
 */
#define H2O_QUIC_FORWARDED_HEADER_MAX_SIZE (1 + 4 + (1 + 16 + 2) * 2 + 1)
#define H2O_QUIC_FORWARDED_VERSION 0x91c17000

static uint8_t *encode_quic_address(uint8_t *dst, quicly_address_t *addr)
{
    switch (addr->sa.sa_family) {
    case AF_INET:
        *dst++ = 4;
        memcpy(dst, &addr->sin.sin_addr.s_addr, 4);
        dst += 4;
        memcpy(dst, &addr->sin.sin_port, 2);
        dst += 2;
        break;
    case AF_INET6:
        *dst++ = 6;
        memcpy(dst, addr->sin6.sin6_addr.s6_addr, 16);
        dst += 16;
        memcpy(dst, &addr->sin.sin_port, 2);
        dst += 2;
        break;
    case AF_UNSPEC:
        *dst++ = 0;
    default:
        h2o_fatal("unknown protocol family");
        break;
    }
    return dst;
}

static int decode_quic_address(quicly_address_t *addr, const uint8_t **src, const uint8_t *end)
{
    memset(addr, 0, sizeof(*addr));

    if (*src >= end)
        return 0;
    switch (*(*src)++) {
    case 4: /* ipv4 */
        if (end - *src < 6)
            return 0;
        addr->sin.sin_family = AF_INET;
        memcpy(&addr->sin.sin_addr.s_addr, *src, 4);
        *src += 4;
        memcpy(&addr->sin.sin_port, *src, 2);
        *src += 2;
        break;
    case 6: /* ipv6 */
        if (end - *src < 18)
            return 0;
        addr->sin6.sin6_family = AF_INET6;
        memcpy(addr->sin6.sin6_addr.s6_addr, *src, 16);
        *src += 16;
        memcpy(&addr->sin6.sin6_port, *src, 2);
        *src += 2;
        break;
    case 0: /* unspec */
        addr->sa.sa_family = AF_UNSPEC;
        break;
    default:
        return 0;
    }
    return 1;
}

/**
 * encodes a forwarded header
 * TODO add authentication for inter-node forwarding
 */
static size_t encode_quic_forwarded_header(void *buf, quicly_address_t *destaddr, quicly_address_t *srcaddr, uint8_t ttl)
{
    uint8_t *dst = buf;

    *dst++ = 0x80;
    dst = quicly_encode32(dst, H2O_QUIC_FORWARDED_VERSION);
    dst = encode_quic_address(dst, destaddr);
    dst = encode_quic_address(dst, srcaddr);
    *dst++ = ttl;

    return dst - (uint8_t *)buf;
}

static size_t decode_quic_forwarded_header(quicly_address_t *destaddr, quicly_address_t *srcaddr, uint8_t *ttl, h2o_iovec_t octets)
{
    const uint8_t *src = (uint8_t *)octets.base, *end = src + octets.len;

    if (end - src < 6)
        goto NotForwarded;
    if (*src++ != 0x80)
        goto NotForwarded;
    if (quicly_decode32(&src) != H2O_QUIC_FORWARDED_VERSION)
        goto NotForwarded;
    if (!decode_quic_address(destaddr, &src, end))
        goto NotForwarded;
    if (!decode_quic_address(srcaddr, &src, end))
        goto NotForwarded;
    if (end - src < 1)
        goto NotForwarded;
    *ttl = *src++;

    return src - (const uint8_t *)octets.base;
NotForwarded:
    return SIZE_MAX;
}

static int forward_quic_packets(h2o_quic_ctx_t *h3ctx, const uint64_t *node_id, uint32_t thread_id, quicly_address_t *destaddr,
                                quicly_address_t *srcaddr, uint8_t ttl, quicly_decoded_packet_t *packets, size_t num_packets)
{
    struct listener_ctx_t *ctx = H2O_STRUCT_FROM_MEMBER(struct listener_ctx_t, http3.ctx.super, h3ctx);
    int fd;

    /* determine the file descriptor to which the packets should be forwarded, or return */
    if (node_id != NULL && *node_id != ctx->http3.ctx.super.next_cid.node_id) {
        /* inter-node forwarding */
        assert(ctx->http3.ctx.super.next_cid.node_id == conf.quic.node_id);
        for (size_t i = 0; i != conf.quic.forward_nodes.size; ++i) {
            if (*node_id == conf.quic.forward_nodes.entries[i].id) {
                fd = conf.quic.forward_nodes.entries[i].fd;
                goto NodeFound;
            }
        }
        return 0;
    NodeFound:;
    } else {
        /* intra-node */
        if (node_id == NULL) {
            /* initial or 0-RTT packet, forward to thread_id being specified */
            if (thread_id == h3ctx->next_cid.thread_id) {
                assert(h3ctx->acceptor == NULL);
                /* FIXME forward packets to the newer generation process */
                return 0;
            }
        } else {
            /* intra-node, validate thread id */
            assert(thread_id != ctx->http3.ctx.super.next_cid.thread_id);
            if (thread_id >= conf.quic.num_threads)
                return 0;
        }
        fd = conf.listeners[ctx->listener_index]->quic.thread_fds[thread_id];
    }

    /* forward (TODO coalesce packets that were coalesced upon receipt) */
    char header_buf[H2O_QUIC_FORWARDED_HEADER_MAX_SIZE];
    size_t header_len = encode_quic_forwarded_header(header_buf, destaddr, srcaddr, ttl);
    for (size_t i = 0; i != num_packets; ++i) {
        struct iovec vec[2] = {{header_buf, header_len}, {packets[i].octets.base, packets[i].octets.len}};
        writev(fd, vec, 2);
    }

#if H2O_USE_DTRACE
    if (H2O_H3_PACKET_FORWARD_ENABLED()) {
        size_t i, num_bytes = 0;
        for (i = 0; i != num_packets; ++i)
            num_bytes += packets[i].octets.len;
        H2O_PROBE(H3_PACKET_FORWARD, &destaddr->sa, &srcaddr->sa, num_packets, num_bytes, fd);
    }
#endif

    return 1;
}

static int rewrite_forwarded_quic_datagram(h2o_quic_ctx_t *h3ctx, struct msghdr *msg, quicly_address_t *destaddr,
                                           quicly_address_t *srcaddr, uint8_t *ttl)
{
    struct {
        quicly_address_t destaddr, srcaddr;
        uint8_t ttl;
        size_t offset;
    } encapsulated;

    assert(msg->msg_iovlen == 1);

    if ((encapsulated.offset = decode_quic_forwarded_header(&encapsulated.destaddr, &encapsulated.srcaddr, &encapsulated.ttl,
                                                            h2o_iovec_init(msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len))) ==
        SIZE_MAX) {
        return 1; /* process the packet as-is */
    }

    /* process as-is, if the destination port is going to be different; the contexts are always bound to a specific port */
    switch (encapsulated.destaddr.sa.sa_family) {
    case AF_UNSPEC:
        break;
    case AF_INET:
        if (encapsulated.destaddr.sin.sin_port != *h3ctx->sock.port)
            return 1;
        break;
    case AF_INET6:
        if (encapsulated.destaddr.sin6.sin6_port != *h3ctx->sock.port)
            return 1;
        break;
    }

    /* update */
    msg->msg_iov[0].iov_base += encapsulated.offset;
    msg->msg_iov[0].iov_len -= encapsulated.offset;
    *destaddr = encapsulated.destaddr;
    *srcaddr = encapsulated.srcaddr;
    *ttl = encapsulated.ttl;
    return 1;
}

static void forwarded_quic_socket_on_read(h2o_socket_t *sock, const char *err)
{
    struct listener_ctx_t *ctx = sock->data;
    h2o_quic_read_socket(&ctx->http3.ctx.super, sock);
}

static void on_socketclose(void *data)
{
    on_connection_close();
}

static void on_accept(h2o_socket_t *listener, const char *err)
{
    struct listener_ctx_t *ctx = listener->data;
    size_t num_accepts = conf.max_connections / 16 / conf.thread_map.size;
    if (num_accepts < 8)
        num_accepts = 8;

    if (err != NULL) {
        return;
    }

    do {
        h2o_socket_t *sock;
        if (num_connections(0) >= conf.max_connections) {
            /* The accepting socket is disactivated before entering the next in `run_loop`.
             * Note: it is possible that the server would accept at most `max_connections + num_threads` connections, since the
             * server does not check if the number of connections has exceeded _after_ epoll notifies of a new connection _but_
             * _before_ calling `accept`.  In other words t/40max-connections.t may fail.
             */
            break;
        }
        if ((sock = h2o_evloop_socket_accept(listener)) == NULL) {
            break;
        }
        num_connections(1);
        num_sessions(1);

        sock->on_close.cb = on_socketclose;
        sock->on_close.data = ctx->accept_ctx.ctx;

        set_tcp_congestion_controller(sock, conf.listeners[ctx->listener_index]->tcp_congestion_controller);

        h2o_accept(&ctx->accept_ctx, sock);

    } while (--num_accepts != 0);
}

struct init_ebpf_key_info_t {
    struct sockaddr *local, *remote;
};

static int init_ebpf_key_info(struct st_h2o_ebpf_map_key_t *key, void *_info)
{
    struct init_ebpf_key_info_t *info = _info;
    return h2o_socket_ebpf_init_key_raw(key, SOCK_DGRAM, info->local, info->remote);
}

static int validate_token(h2o_http3_server_ctx_t *ctx, struct sockaddr *remote, ptls_iovec_t client_cid, ptls_iovec_t server_cid,
                          quicly_address_token_plaintext_t *token)
{
    int64_t age;

    if ((age = ctx->super.quic->now->cb(ctx->super.quic->now) - token->issued_at) < 0)
        age = 0;
    if (h2o_socket_compare_address(remote, &token->remote.sa, token->type == QUICLY_ADDRESS_TOKEN_TYPE_RETRY) != 0)
        return 0;
    switch (token->type) {
    case QUICLY_ADDRESS_TOKEN_TYPE_RETRY:
        if (age > 30 * 1000)
            return 0;
        if (!quicly_cid_is_equal(&token->retry.client_cid, client_cid))
            return 0;
        if (!quicly_cid_is_equal(&token->retry.server_cid, server_cid))
            return 0;
        break;
    case QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION:
        if (age > 10 * 60 * 1000)
            return 0;
        break;
    default:
        h2o_fatal("unexpected token type: %d", (int)token->type);
        break;
    }

    return 1;
}

static h2o_quic_conn_t *on_http3_accept(h2o_quic_ctx_t *_ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                        quicly_decoded_packet_t *packet)
{
    h2o_http3_server_ctx_t *ctx = (void *)_ctx;
    struct init_ebpf_key_info_t ebpf_keyinfo = {&destaddr->sa, &srcaddr->sa};
    h2o_ebpf_map_value_t ebpf_value = h2o_socket_ebpf_lookup(ctx->super.loop, init_ebpf_key_info, &ebpf_keyinfo);
    quicly_address_token_plaintext_t *token = NULL, token_buf;
    h2o_http3_conn_t *conn;

    /* just drop when handling too many connections */
    if (num_connections(0) >= conf.max_connections || num_quic_connections(0) >= conf.max_quic_connections)
        return NULL;

    /* handle retry, setting `token` to a non-NULL pointer if contains a valid token */
    if (packet->token.len != 0) {
        int ret;
        const char *err_desc = NULL;
        if ((ret = quic_decrypt_address_token(&token_buf, packet->token, &err_desc)) == 0) {
            if (validate_token(ctx, &srcaddr->sa, packet->cid.src, packet->cid.dest.encrypted, &token_buf))
                token = &token_buf;
        } else if (ret == QUICLY_TRANSPORT_ERROR_INVALID_TOKEN) {
            uint8_t payload[QUICLY_MIN_CLIENT_INITIAL_SIZE];
            size_t payload_size = quicly_send_close_invalid_token(ctx->super.quic, packet->version, packet->cid.src,
                                                                  packet->cid.dest.encrypted, err_desc, payload);
            assert(payload_size != SIZE_MAX);
            struct iovec vec = {.iov_base = payload, .iov_len = payload_size};
            h2o_quic_send_datagrams(&ctx->super, srcaddr, destaddr, &vec, 1);
            return NULL;
        }
    }

    /* send retry if necessary */
    if (token == NULL || token->type != QUICLY_ADDRESS_TOKEN_TYPE_RETRY) {
        int send_retry = ctx->send_retry;
        switch (ebpf_value.quic_send_retry) {
        case H2O_EBPF_QUIC_SEND_RETRY_ON:
            send_retry = 1;
            break;
        case H2O_EBPF_QUIC_SEND_RETRY_OFF:
            send_retry = 0;
            break;
        default:
            break;
        }
        if (send_retry) {
            static __thread struct {
                ptls_aead_context_t *current;
                ptls_aead_context_t *draft27;
            } retry_integrity_aead_cache;
            uint8_t scid[16], payload[QUICLY_MIN_CLIENT_INITIAL_SIZE], token_prefix;
            ptls_openssl_random_bytes(scid, sizeof(scid));
            ptls_aead_context_t *token_aead = quic_get_address_token_encryptor(&token_prefix), **retry_integrity_aead;
            switch (packet->version) {
            case QUICLY_PROTOCOL_VERSION_CURRENT:
                retry_integrity_aead = &retry_integrity_aead_cache.current;
                break;
            case QUICLY_PROTOCOL_VERSION_DRAFT27:
                retry_integrity_aead = &retry_integrity_aead_cache.draft27;
                break;
            default:
                retry_integrity_aead = NULL;
                break;
            }
            size_t payload_size =
                quicly_send_retry(ctx->super.quic, token_aead, packet->version, &srcaddr->sa, packet->cid.src, &destaddr->sa,
                                  ptls_iovec_init(scid, sizeof(scid)), packet->cid.dest.encrypted,
                                  ptls_iovec_init(&token_prefix, 1), ptls_iovec_init(NULL, 0), retry_integrity_aead, payload);
            assert(payload_size != SIZE_MAX);
            struct iovec vec = {.iov_base = payload, .iov_len = payload_size};
            h2o_quic_send_datagrams(&ctx->super, srcaddr, destaddr, &vec, 1);
            return NULL;
        }
    }

    /* accept the connection */
    conn = h2o_http3_server_accept(ctx, destaddr, srcaddr, packet, token, ebpf_value.skip_tracing, &conf.quic.conn_callbacks);
    if (conn == NULL || &conn->super == H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED)
        return &conn->super;
    num_connections(1);
    num_quic_connections(1);
    num_sessions(1);
    return &conn->super;
}

static void update_listener_state(struct listener_ctx_t *listeners)
{
    size_t i;

    if (num_connections(0) < conf.max_connections) {
        for (i = 0; i != conf.num_listeners; ++i) {
            if (conf.listeners[i]->quic.ctx == NULL && !h2o_socket_is_reading(listeners[i].sock))
                h2o_socket_read_start(listeners[i].sock, on_accept);
        }
    } else {
        for (i = 0; i != conf.num_listeners; ++i) {
            if (conf.listeners[i]->quic.ctx == NULL && h2o_socket_is_reading(listeners[i].sock))
                h2o_socket_read_stop(listeners[i].sock);
        }
    }
}

static void on_server_notification(h2o_multithread_receiver_t *receiver, h2o_linklist_t *messages)
{
    /* the notification is used only for exitting h2o_evloop_run; actual changes are done in the main loop of run_loop */

    while (!h2o_linklist_is_empty(messages)) {
        h2o_multithread_message_t *message = H2O_STRUCT_FROM_MEMBER(h2o_multithread_message_t, link, messages->next);
        h2o_linklist_unlink(&message->link);
        free(message);
    }
}

static void *run_loop(void *_thread_index)
{
    size_t thread_index = (size_t)_thread_index;
    struct listener_ctx_t *listeners = alloca(sizeof(*listeners) * conf.num_listeners);
    size_t i;

    h2o_context_init(&conf.threads[thread_index].ctx, h2o_evloop_create(), &conf.globalconf);
    h2o_multithread_register_receiver(conf.threads[thread_index].ctx.queue, &conf.threads[thread_index].server_notifications,
                                      on_server_notification);
    h2o_multithread_register_receiver(conf.threads[thread_index].ctx.queue, &conf.threads[thread_index].memcached,
                                      h2o_memcached_receiver);

    if (conf.thread_map.entries[thread_index] >= 0) {
#ifdef H2O_HAS_PTHREAD_SETAFFINITY_NP
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(conf.thread_map.entries[thread_index], &cpu_set);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set) != 0) {
            static int once;
            if (__sync_fetch_and_add(&once, 1) == 0) {
                fprintf(stderr, "[warning] failed to set bind to CPU:%d\n", conf.thread_map.entries[thread_index]);
            }
        }
#else
        h2o_fatal("internal error; thread pinning not available even though specified");
#endif
    }

    /* setup listeners */
    for (i = 0; i != conf.num_listeners; ++i) {
        struct listener_config_t *listener_config = conf.listeners[i];
        int fd = -1;
        /* dup the listener fd for other threads than the main thread */
        if (thread_index == 0) {
            fd = listener_config->fd;
        } else {
            int reuseport = 0;
#if H2O_USE_REUSEPORT
            socklen_t reuseportlen = sizeof(reuseport);
            if (getsockopt(listener_config->fd, SOL_SOCKET, H2O_SO_REUSEPORT, &reuseport, &reuseportlen) != 0) {
                perror("gestockopt(SO_REUSEPORT) failed");
                abort();
            }
            assert(reuseportlen == sizeof(reuseport));
            if (reuseport) {
                int type;
                socklen_t typelen = sizeof(type);
                struct sockaddr_storage ss;
                socklen_t sslen = sizeof(ss);
                if (getsockopt(listener_config->fd, SOL_SOCKET, SO_TYPE, &type, &typelen) != 0) {
                    perror("failed to obtain the type of a listening socket");
                    abort();
                }
                assert(type == SOCK_DGRAM || type == SOCK_STREAM);
                if (getsockname(listener_config->fd, (struct sockaddr *)&ss, &sslen) != 0) {
                    perror("failed to obtain local address of a listening socket");
                    abort();
                }
                if ((fd = open_listener(ss.ss_family, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP, (struct sockaddr *)&ss,
                                        sslen)) != -1) {
                    if (type == SOCK_DGRAM)
                        setsockopt_recvpktinfo(fd, ss.ss_family);
                } else {
                    reuseport = 0;
                }
            }
#endif
            if (!reuseport && (fd = dup(listener_config->fd)) == -1) {
                perror("failed to dup listening socket");
                abort();
            }
            set_cloexec(fd);
        }
        assert(fd != -1);
        listeners[i] = (struct listener_ctx_t){i,
                                               {&conf.threads[thread_index].ctx, listener_config->hosts, NULL, NULL,
                                                listener_config->proxy_protocol, &conf.threads[thread_index].memcached}};
        if (listener_config->ssl.size != 0) {
            listeners[i].accept_ctx.ssl_ctx = listener_config->ssl.entries[0]->ctx;
            listeners[i].accept_ctx.http2_origin_frame = listener_config->ssl.entries[0]->http2_origin_frame;
        }
        listeners[i].sock = h2o_evloop_socket_create(conf.threads[thread_index].ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
        listeners[i].sock->data = listeners + i;
        /* setup quic context and the unix socket to receive forwarded packets */
        if (thread_index < conf.quic.num_threads && listener_config->quic.ctx != NULL) {
            h2o_quic_init_context(&listeners[i].http3.ctx.super, conf.threads[thread_index].ctx.loop, listeners[i].sock,
                                  listener_config->quic.ctx, on_http3_accept, NULL);
            h2o_quic_set_context_identifier(&listeners[i].http3.ctx.super, 0, (uint32_t)thread_index, conf.quic.node_id, 4,
                                            forward_quic_packets, rewrite_forwarded_quic_datagram);
            listeners[i].http3.ctx.accept_ctx = &listeners[i].accept_ctx;
            listeners[i].http3.ctx.send_retry = listener_config->quic.send_retry;
            listeners[i].http3.ctx.qpack = listener_config->quic.qpack;
            int fds[2];
            /* TODO switch to using named socket in temporary directory to forward packets between server generations */
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
                perror("socketpair(AF_UNIX, SOCK_DGRAM) failed");
                abort();
            }
            set_cloexec(fds[0]);
            set_cloexec(fds[1]);
            listeners[i].http3.forwarded_sock =
                h2o_evloop_socket_create(conf.threads[thread_index].ctx.loop, fds[0], H2O_SOCKET_FLAG_DONT_READ);
            listeners[i].http3.forwarded_sock->data = listeners + i;
            h2o_socket_read_start(listeners[i].http3.forwarded_sock, forwarded_quic_socket_on_read);
            fcntl(fds[1], F_SETFL, O_NONBLOCK);
            conf.listeners[i]->quic.thread_fds[thread_index] = fds[1];
        }
    }
    /* and start listening */
    update_listener_state(listeners);

    /* make sure all threads are initialized before starting to serve requests */
    h2o_barrier_wait(&conf.startup_sync_barrier);

    if (thread_index == 0)
        fprintf(stderr, "h2o server (pid:%d) is ready to serve requests with %zu threads\n", (int)getpid(), conf.thread_map.size);

    /* the main loop */
    while (1) {
        if (conf.shutdown_requested)
            break;
        update_listener_state(listeners);
        /* run the loop once */
        h2o_evloop_run(conf.threads[thread_index].ctx.loop, INT32_MAX);
        h2o_filecache_clear(conf.threads[thread_index].ctx.filecache);
    }

    if (thread_index == 0)
        fprintf(stderr, "received SIGTERM, gracefully shutting down\n");

    /* shutdown requested, unregister, close the listeners and notify the protocol handlers */
    for (i = 0; i != conf.num_listeners; ++i) {
        if (conf.listeners[i]->quic.ctx == NULL)
            h2o_socket_read_stop(listeners[i].sock);
    }
    h2o_evloop_run(conf.threads[thread_index].ctx.loop, 0);
    for (i = 0; i != conf.num_listeners; ++i) {
        if (conf.listeners[i]->quic.ctx == NULL) {
            h2o_socket_close(listeners[i].sock);
            listeners[i].sock = NULL;
        } else {
            listeners[i].http3.ctx.super.acceptor = NULL;
        }
    }
    h2o_context_request_shutdown(&conf.threads[thread_index].ctx);

    /* wait until all the connection gets closed */
    while (num_connections(0) != 0)
        h2o_evloop_run(conf.threads[thread_index].ctx.loop, INT32_MAX);

    return NULL;
}

static char **build_server_starter_argv(const char *h2o_cmd, const char *config_file)
{
    H2O_VECTOR(char *) args = {NULL};
    size_t i;

    h2o_vector_reserve(NULL, &args, 1);
    args.entries[args.size++] = h2o_configurator_get_cmd_path("share/h2o/start_server");

    /* error-log and pid-file are the directives that are handled by server-starter */
    if (conf.pid_file != NULL) {
        h2o_vector_reserve(NULL, &args, args.size + 1);
        args.entries[args.size++] =
            h2o_concat(NULL, h2o_iovec_init(H2O_STRLIT("--pid-file=")), h2o_iovec_init(conf.pid_file, strlen(conf.pid_file))).base;
    }
    if (conf.error_log != NULL) {
        h2o_vector_reserve(NULL, &args, args.size + 1);
        args.entries[args.size++] =
            h2o_concat(NULL, h2o_iovec_init(H2O_STRLIT("--log-file=")), h2o_iovec_init(conf.error_log, strlen(conf.error_log)))
                .base;
    }

    switch (conf.run_mode) {
    case RUN_MODE_DAEMON:
        h2o_vector_reserve(NULL, &args, args.size + 1);
        args.entries[args.size++] = "--daemonize";
        break;
    default:
        break;
    }

    for (i = 0; i != conf.num_listeners; ++i) {
        char *newarg;
        switch (conf.listeners[i]->addr.ss_family) {
        default: {
            char host[NI_MAXHOST], serv[NI_MAXSERV + 1];
            int err;
            /* add "u" prefix if binding to a UDP port */
            if (conf.listeners[i]->quic.ctx != NULL) {
                strcpy(serv, "u");
            } else {
                serv[0] = '\0';
            }
            if ((err = getnameinfo((void *)&conf.listeners[i]->addr, conf.listeners[i]->addrlen, host, sizeof(host),
                                   serv + strlen(serv), NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
                fprintf(stderr, "failed to stringify the address of %zu-th listen directive:%s\n", i, gai_strerror(err));
                exit(EX_OSERR);
            }
            newarg = h2o_mem_alloc(sizeof("--port=[]:") + strlen(host) + strlen(serv));
            if (strchr(host, ':') != NULL) {
                sprintf(newarg, "--port=[%s]:%s", host, serv);
            } else {
                sprintf(newarg, "--port=%s:%s", host, serv);
            }
        } break;
        case AF_UNIX: {
            struct sockaddr_un *sa = (void *)&conf.listeners[i]->addr;
            newarg = h2o_mem_alloc(sizeof("--path=") + strlen(sa->sun_path));
            sprintf(newarg, "--path=%s", sa->sun_path);
        } break;
        }
        h2o_vector_reserve(NULL, &args, args.size + 1);
        args.entries[args.size++] = newarg;
    }

    h2o_vector_reserve(NULL, &args, args.size + 5);
    args.entries[args.size++] = "--";
    args.entries[args.size++] = (char *)h2o_cmd;
    args.entries[args.size++] = "-c";
    args.entries[args.size++] = (char *)config_file;
    args.entries[args.size] = NULL;

    return args.entries;
}

static int run_using_server_starter(const char *h2o_cmd, const char *config_file)
{
    char **args = build_server_starter_argv(h2o_cmd, config_file);
    setenv("H2O_VIA_MASTER", "", 1);
    execvp(args[0], args);
    fprintf(stderr, "failed to spawn %s:%s\n", args[0], strerror(errno));
    return EX_CONFIG;
}

/* make jemalloc linkage optional by marking the functions as 'weak',
 * since upstream doesn't rely on it. */
struct extra_status_jemalloc_cb_arg {
    h2o_iovec_t outbuf;
    int err;
    size_t written;
};

#if JEMALLOC_STATS == 1
static void extra_status_jemalloc_cb(void *ctx, const char *stats)
{
    size_t cur_len;
    struct extra_status_jemalloc_cb_arg *out = ctx;
    h2o_iovec_t outbuf = out->outbuf;
    int i;

    if (out->written >= out->outbuf.len || out->err) {
        return;
    }
    cur_len = out->written;

    i = 0;
    while (cur_len < outbuf.len && stats[i]) {
        switch (stats[i]) {
#define JSON_ESCAPE(x, y)                                                                                                          \
    case x:                                                                                                                        \
        outbuf.base[cur_len++] = '\\';                                                                                             \
        if (cur_len >= outbuf.len) {                                                                                               \
            goto err;                                                                                                              \
        }                                                                                                                          \
        outbuf.base[cur_len] = y;                                                                                                  \
        break;
            JSON_ESCAPE('\b', 'b');
            JSON_ESCAPE('\f', 'f');
            JSON_ESCAPE('\n', 'n');
            JSON_ESCAPE('\r', 'r')
            JSON_ESCAPE('\t', 't');
            JSON_ESCAPE('/', '/');
            JSON_ESCAPE('"', '"');
            JSON_ESCAPE('\\', '\\');
#undef JSON_ESCAPE
        default:
            outbuf.base[cur_len] = stats[i];
        }
        i++;
        cur_len++;
    }
    if (cur_len < outbuf.len) {
        out->written = cur_len;
        return;
    }

err:
    out->err = 1;
    return;
}
#endif

static h2o_iovec_t on_extra_status(void *unused, h2o_globalconf_t *_conf, h2o_req_t *req)
{
#define BUFSIZE (16 * 1024)
    h2o_iovec_t ret;
    char current_time[H2O_TIMESTR_LOG_LEN + 1], restart_time[H2O_TIMESTR_LOG_LEN + 1];
    const char *generation;
    time_t now = time(NULL);

    h2o_time2str_log(current_time, now);
    h2o_time2str_log(restart_time, conf.launch_time);
    if ((generation = getenv("SERVER_STARTER_GENERATION")) == NULL)
        generation = "null";

    ret.base = h2o_mem_alloc_pool(&req->pool, char, BUFSIZE);
    ret.len = snprintf(ret.base, BUFSIZE,
                       ",\n"
                       " \"server-version\": \"" H2O_VERSION "\",\n"
                       " \"openssl-version\": \"%s\",\n"
                       " \"current-time\": \"%s\",\n"
                       " \"restart-time\": \"%s\",\n"
                       " \"uptime\": %" PRIu64 ",\n"
                       " \"generation\": %s,\n"
                       " \"connections\": %d,\n"
                       " \"max-connections\": %d,\n"
                       " \"listeners\": %zu,\n"
                       " \"worker-threads\": %zu,\n"
                       " \"num-sessions\": %lu",
                       OpenSSL_version(OPENSSL_VERSION), current_time, restart_time, (uint64_t)(now - conf.launch_time), generation,
                       num_connections(0), conf.max_connections, conf.num_listeners, conf.thread_map.size, num_sessions(0));
    assert(ret.len < BUFSIZE);

#if JEMALLOC_STATS == 1
    struct extra_status_jemalloc_cb_arg arg;
    size_t sz, allocated, active, metadata, resident, mapped;
    uint64_t epoch = 1;
    /* internal jemalloc interface */
    void malloc_stats_print(void (*write_cb)(void *, const char *), void *cbopaque, const char *opts);
    int mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

    arg.outbuf = h2o_iovec_init(alloca(BUFSIZE - ret.len), BUFSIZE - ret.len);
    arg.err = 0;
    arg.written = snprintf(arg.outbuf.base, arg.outbuf.len,
                           ",\n"
                           " \"jemalloc\": {\n"
                           "   \"jemalloc-raw\": \"");
    malloc_stats_print(extra_status_jemalloc_cb, &arg, "ga" /* omit general info, only aggregated stats */);

    if (arg.err || arg.written + 1 >= arg.outbuf.len) {
        goto jemalloc_err;
    }

    /* terminate the jemalloc-raw json string */
    arg.written += snprintf(&arg.outbuf.base[arg.written], arg.outbuf.len - arg.written, "\"");
    if (arg.written + 1 >= arg.outbuf.len) {
        goto jemalloc_err;
    }

    sz = sizeof(epoch);
    mallctl("epoch", &epoch, &sz, &epoch, sz);

    sz = sizeof(size_t);
    if (!mallctl("stats.allocated", &allocated, &sz, NULL, 0) && !mallctl("stats.active", &active, &sz, NULL, 0) &&
        !mallctl("stats.metadata", &metadata, &sz, NULL, 0) && !mallctl("stats.resident", &resident, &sz, NULL, 0) &&
        !mallctl("stats.mapped", &mapped, &sz, NULL, 0)) {
        arg.written += snprintf(&arg.outbuf.base[arg.written], arg.outbuf.len - arg.written,
                                ",\n"
                                "   \"allocated\": %zu,\n"
                                "   \"active\": %zu,\n"
                                "   \"metadata\": %zu,\n"
                                "   \"resident\": %zu,\n"
                                "   \"mapped\": %zu }",
                                allocated, active, metadata, resident, mapped);
    }
    if (arg.written + 1 >= arg.outbuf.len) {
        goto jemalloc_err;
    }

    strncpy(&ret.base[ret.len], arg.outbuf.base, arg.written);
    ret.base[ret.len + arg.written] = '\0';
    ret.len += arg.written;
    return ret;

jemalloc_err:
    /* couldn't fit the jemalloc output, exiting */
    ret.base[ret.len] = '\0';

#endif /* JEMALLOC_STATS == 1 */

    return ret;
#undef BUFSIZE
}

static void setup_configurators(void)
{
    h2o_config_init(&conf.globalconf);

    /* let the default setuid user be "nobody", if run as root */
    if (getuid() == 0 && getpwnam("nobody") != NULL)
        conf.globalconf.user = "nobody";

    {
        h2o_configurator_t *c = h2o_configurator_create(&conf.globalconf, sizeof(*c));
        c->enter = on_config_listen_enter;
        c->exit = on_config_listen_exit;
        h2o_configurator_define_command(c, "listen", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST, on_config_listen);
    }

    {
        h2o_configurator_t *c = h2o_configurator_create(&conf.globalconf, sizeof(*c));
        h2o_configurator_define_command(c, "user", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_user);
        h2o_configurator_define_command(c, "pid-file", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_pid_file);
        h2o_configurator_define_command(c, "error-log", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_error_log);
        h2o_configurator_define_command(c, "max-connections", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_max_connections);
        h2o_configurator_define_command(c, "max-quic-connections", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_max_quic_connections);
        h2o_configurator_define_command(c, "num-threads", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_num_threads);
        h2o_configurator_define_command(c, "num-quic-threads", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_num_quic_threads);
        h2o_configurator_define_command(c, "num-name-resolution-threads", H2O_CONFIGURATOR_FLAG_GLOBAL,
                                        on_config_num_name_resolution_threads);
        h2o_configurator_define_command(c, "tcp-fastopen", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_tcp_fastopen);
        h2o_configurator_define_command(c, "quic-nodes", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                        on_config_quic_nodes);
        h2o_configurator_define_command(c, "ssl-session-resumption",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
                                        ssl_session_resumption_on_config);
        h2o_configurator_define_command(c, "num-ocsp-updaters", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_num_ocsp_updaters);
        h2o_configurator_define_command(c, "temp-buffer-path", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_temp_buffer_path);
        h2o_configurator_define_command(c, "temp-buffer-threshold",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_temp_buffer_threshold);
        h2o_configurator_define_command(c, "crash-handler", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_crash_handler);
        h2o_configurator_define_command(c, "crash-handler.wait-pipe-close",
                                        H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_crash_handler_wait_pipe_close);
        h2o_configurator_define_command(c, "tcp-reuseport", H2O_CONFIGURATOR_FLAG_GLOBAL, on_tcp_reuseport);
    }

    h2o_access_log_register_configurator(&conf.globalconf);
    h2o_compress_register_configurator(&conf.globalconf);
    h2o_expires_register_configurator(&conf.globalconf);
    h2o_errordoc_register_configurator(&conf.globalconf);
    h2o_fastcgi_register_configurator(&conf.globalconf);
    h2o_file_register_configurator(&conf.globalconf);
    h2o_throttle_resp_register_configurator(&conf.globalconf);
    h2o_headers_register_configurator(&conf.globalconf);
    h2o_proxy_register_configurator(&conf.globalconf);
    h2o_reproxy_register_configurator(&conf.globalconf);
    h2o_redirect_register_configurator(&conf.globalconf);
    h2o_status_register_configurator(&conf.globalconf);
    h2o_http2_debug_state_register_configurator(&conf.globalconf);
    h2o_server_timing_register_configurator(&conf.globalconf);
#if H2O_USE_MRUBY
    h2o_mruby_register_configurator(&conf.globalconf);
#endif

    static h2o_status_handler_t extra_status_handler = {{H2O_STRLIT("main")}, on_extra_status};
    h2o_config_register_status_handler(&conf.globalconf, &extra_status_handler);
}

int main(int argc, char **argv)
{
    cmd_argc = argc;
    cmd_argv = argv;

    const char *cmd = argv[0], *opt_config_file = H2O_TO_STR(H2O_CONFIG_PATH);
    int n, error_log_fd = -1;
    size_t num_procs = h2o_numproc();

    h2o_vector_reserve(NULL, &conf.thread_map, num_procs);
    for (n = 0; n < num_procs; n++)
        conf.thread_map.entries[conf.thread_map.size++] = -1;
    conf.quic.conn_callbacks = H2O_HTTP3_CONN_CALLBACKS;
    conf.quic.conn_callbacks.super.destroy_connection = on_http3_conn_destroy;
    conf.tfo_queues = H2O_DEFAULT_LENGTH_TCP_FASTOPEN_QUEUE;
    conf.launch_time = time(NULL);

    h2o_hostinfo_max_threads = H2O_DEFAULT_NUM_NAME_RESOLUTION_THREADS;

    h2o_sem_init(&ocsp_updater_semaphore, H2O_DEFAULT_OCSP_UPDATER_MAX_THREADS);

    init_openssl();
    setup_configurators();

    { /* parse options */
        int ch;
        static struct option longopts[] = {{"conf", required_argument, NULL, 'c'}, {"mode", required_argument, NULL, 'm'},
                                           {"test", no_argument, NULL, 't'},       {"version", no_argument, NULL, 'v'},
                                           {"help", no_argument, NULL, 'h'},       {NULL}};
        while ((ch = getopt_long(argc, argv, "c:m:tvh", longopts, NULL)) != -1) {
            switch (ch) {
            case 'c':
                opt_config_file = optarg;
                break;
            case 'm':
                if (strcmp(optarg, "worker") == 0) {
                    conf.run_mode = RUN_MODE_WORKER;
                } else if (strcmp(optarg, "master") == 0) {
                    conf.run_mode = RUN_MODE_MASTER;
                } else if (strcmp(optarg, "daemon") == 0) {
                    conf.run_mode = RUN_MODE_DAEMON;
                } else if (strcmp(optarg, "test") == 0) {
                    conf.run_mode = RUN_MODE_TEST;
                } else {
                    fprintf(stderr, "unknown mode:%s\n", optarg);
                }
                switch (conf.run_mode) {
                case RUN_MODE_MASTER:
                case RUN_MODE_DAEMON:
                    if (getenv(SERVER_STARTER_PORT) != NULL) {
                        fprintf(stderr,
                                "refusing to start in `%s` mode, environment variable " SERVER_STARTER_PORT " is already set\n",
                                optarg);
                        exit(EX_SOFTWARE);
                    }
                    break;
                default:
                    break;
                }
                break;
            case 't':
                conf.run_mode = RUN_MODE_TEST;
                break;
            case 'v':
                printf("h2o version " H2O_VERSION "\n");
                printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
#if H2O_USE_MRUBY
                printf(
                    "mruby: YES\n"); /* TODO determine the way to obtain the version of mruby (that is being linked dynamically) */
#endif
#if H2O_USE_DTRACE
                printf("dtrace: YES\n");
#endif
                exit(0);
            case 'h':
                printf("h2o version " H2O_VERSION "\n"
                       "\n"
                       "Usage:\n"
                       "  h2o [OPTION]...\n"
                       "\n"
                       "Options:\n"
                       "  -c, --conf FILE    configuration file (default: %s)\n"
                       "  -m, --mode MODE    specifies one of the following modes:\n"
                       "                     - worker: invoked process handles incoming connections\n"
                       "                               (default)\n"
                       "                     - daemon: spawns a master process and exits. `error-log`\n"
                       "                               must be configured when using this mode, as all\n"
                       "                               the errors are logged to the file instead of\n"
                       "                               being emitted to STDERR\n"
                       "                     - master: invoked process becomes a master process (using\n"
                       "                               the `share/h2o/start_server` command) and spawns\n"
                       "                               a worker process for handling incoming\n"
                       "                               connections. Users may send SIGHUP to the master\n"
                       "                               process to reconfigure or upgrade the server.\n"
                       "                     - test:   tests the configuration and exits\n"
                       "  -t, --test         synonym of `--mode=test`\n"
                       "  -v, --version      prints the version number\n"
                       "  -h, --help         print this help\n"
                       "\n"
                       "Please refer to the documentation under `share/doc/h2o` (or available online at\n"
                       "https://h2o.examp1e.net/) for how to configure the server.\n"
                       "\n",
                       H2O_TO_STR(H2O_CONFIG_PATH));
                exit(0);
                break;
            case ':':
            case '?':
                exit(EX_CONFIG);
            default:
                assert(0);
                break;
            }
        }
        argc -= optind;
        argv += optind;
    }

    /* setup conf.server_starter */
    if ((conf.server_starter.num_fds = h2o_server_starter_get_fds(&conf.server_starter.fds)) == SIZE_MAX)
        exit(EX_CONFIG);
    if (conf.server_starter.fds != 0) {
        size_t i;
        for (i = 0; i != conf.server_starter.num_fds; ++i)
            set_cloexec(conf.server_starter.fds[i]);
        conf.server_starter.bound_fd_map = alloca(conf.server_starter.num_fds);
        memset(conf.server_starter.bound_fd_map, 0, conf.server_starter.num_fds);
    }

    { /* configure */
        yoml_t *yoml;
        resolve_tag_arg_t resolve_tag_arg = {{NULL}};
        yoml_parse_args_t parse_args = {
            opt_config_file,                /* filename */
            NULL,                           /* mem_set */
            {resolve_tag, &resolve_tag_arg} /* resolve_tag */
        };
        if ((yoml = load_config(&parse_args, NULL)) == NULL)
            exit(EX_CONFIG);
        if (h2o_configurator_apply(&conf.globalconf, yoml, conf.run_mode != RUN_MODE_WORKER) != 0)
            exit(EX_CONFIG);

        dispose_resolve_tag_arg(&resolve_tag_arg);
        yoml_free(yoml, NULL);
    }

    {
        int fd = h2o_file_mktemp(h2o_socket_buffer_mmap_settings.fn_template);
        if (fd == -1) {
            fprintf(stderr, "temp-buffer-path: failed to create temporary file from the mkstemp(3) template '%s': %s\n",
                    h2o_socket_buffer_mmap_settings.fn_template, strerror(errno));
            return EX_CONFIG;
        }
        close(fd);
    }

    /* calculate defaults (note: open file cached is purged once every loop) */
    conf.globalconf.filecache.capacity = conf.globalconf.http2.max_concurrent_requests_per_connection * 2;
    if (conf.quic.num_threads == 0) {
        conf.quic.num_threads = conf.thread_map.size;
    } else if (conf.quic.num_threads > conf.thread_map.size) {
        fprintf(stderr, "capping quic.num_threads (%zu) to the total number of threads (%zu)\n", conf.quic.num_threads,
                conf.thread_map.size);
        conf.quic.num_threads = conf.thread_map.size;
    }

    /* check if all the fds passed in by server::starter were bound */
    if (conf.server_starter.fds != NULL) {
        size_t i;
        int all_were_bound = 1;
        for (i = 0; i != conf.server_starter.num_fds; ++i) {
            if (!conf.server_starter.bound_fd_map[i]) {
                fprintf(stderr, "no configuration found for fd:%d passed in by $" SERVER_STARTER_PORT "\n",
                        conf.server_starter.fds[i]);
                all_were_bound = 0;
                break;
            }
        }
        if (!all_were_bound) {
            fprintf(stderr, "note: $" SERVER_STARTER_PORT " was \"%s\"\n", getenv(SERVER_STARTER_PORT));
            return EX_CONFIG;
        }
    }
    unsetenv(SERVER_STARTER_PORT);

    h2o_srand();
    /* handle run_mode == MASTER|TEST */
    switch (conf.run_mode) {
    case RUN_MODE_WORKER:
        break;
    case RUN_MODE_DAEMON:
        if (conf.error_log == NULL) {
            fprintf(stderr, "to run in `daemon` mode, `error-log` must be specified in the configuration file\n");
            return EX_CONFIG;
        }
        return run_using_server_starter(cmd, opt_config_file);
    case RUN_MODE_MASTER:
        return run_using_server_starter(cmd, opt_config_file);
    case RUN_MODE_TEST:
        printf("configuration OK\n");
        return 0;
    }

    if (getenv("H2O_VIA_MASTER") != NULL) {
        /* pid_file and error_log are the directives that are handled by the master process (invoking start_server) */
        conf.pid_file = NULL;
        conf.error_log = NULL;
    }

    { /* raise RLIMIT_NOFILE */
        struct rlimit limit;
        if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
            limit.rlim_cur = limit.rlim_max;
            if (setrlimit(RLIMIT_NOFILE, &limit) == 0
#ifdef __APPLE__
                || (limit.rlim_cur = OPEN_MAX, setrlimit(RLIMIT_NOFILE, &limit)) == 0
#endif
            ) {
                fprintf(stderr, "[INFO] raised RLIMIT_NOFILE to %d\n", (int)limit.rlim_cur);
            }
        }
    }

    setup_signal_handlers();

    /* open the log file to redirect STDIN/STDERR to, before calling setuid */
    if (conf.error_log != NULL) {
        if ((error_log_fd = h2o_access_log_open_log(conf.error_log)) == -1)
            return EX_CONFIG;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    /* setuid */
    if (conf.globalconf.user != NULL) {
        if (h2o_setuidgid(conf.globalconf.user) != 0) {
            fprintf(stderr, "failed to change the running user (are you sure you are running as root?)\n");
            return EX_OSERR;
        }
        if (neverbleed != NULL && neverbleed_setuidgid(neverbleed, conf.globalconf.user, 1) != 0) {
            fprintf(stderr, "failed to change the running user of neverbleed daemon\n");
            return EX_OSERR;
        }
    } else {
        if (getuid() == 0) {
            fprintf(stderr, "refusing to run as root (and failed to switch to `nobody`); you can use the `user` directive to set "
                            "the running user\n");
            return EX_CONFIG;
        }
    }

    /* pid file must be written after setuid, since we need to remove it  */
    if (conf.pid_file != NULL) {
        FILE *fp = fopen(conf.pid_file, "wt");
        if (fp == NULL) {
            fprintf(stderr, "failed to open pid file:%s:%s\n", conf.pid_file, strerror(errno));
            return EX_OSERR;
        }
        fprintf(fp, "%d\n", (int)getpid());
        fclose(fp);
    }

    /* build barrier to synchronize the start of all threads */
    assert(conf.thread_map.size != 0);
    h2o_barrier_init(&conf.startup_sync_barrier, conf.thread_map.size);

    { /* initialize SSL_CTXs for session resumption and ticket-based resumption (also starts memcached client threads for the
         purpose) */
        size_t i, j;
        int has_quic = 0;
        H2O_VECTOR(SSL_CTX *) ssl_contexts = {NULL};
        for (i = 0; i != conf.num_listeners; ++i) {
            for (j = 0; j != conf.listeners[i]->ssl.size; ++j) {
                h2o_vector_reserve(NULL, &ssl_contexts, ssl_contexts.size + 1);
                ssl_contexts.entries[ssl_contexts.size++] = conf.listeners[i]->ssl.entries[j]->ctx;
            }
            if (conf.listeners[i]->quic.ctx != NULL)
                has_quic = 1;
            conf.listeners[i]->quic.thread_fds = h2o_mem_alloc(conf.quic.num_threads * sizeof(*conf.listeners[i]->quic.thread_fds));
            for (j = 0; j != conf.quic.num_threads; ++j)
                conf.listeners[i]->quic.thread_fds[j] = -1;
        }
        struct st_h2o_quic_resumption_args_t quic_args_buf = {}, *quic_args = NULL;
        h2o_barrier_t *sync_barrier = NULL;
        if (has_quic) {
            quic_args = &quic_args_buf;
            quic_args->is_clustered = conf.quic.node_id != 0;
            sync_barrier = &conf.startup_sync_barrier;
        }
        ssl_setup_session_resumption(ssl_contexts.entries, ssl_contexts.size, quic_args, sync_barrier);
        free(ssl_contexts.entries);
        for (i = 0; i != conf.num_listeners; ++i) {
            for (j = 0; j != conf.listeners[i]->ssl.size; ++j) {
                ptls_context_t *ptls = h2o_socket_ssl_get_picotls_context(conf.listeners[i]->ssl.entries[j]->ctx);
                if (ptls != NULL)
                    ssl_setup_session_resumption_ptls(ptls, conf.listeners[i]->quic.ctx);
            }
        }
    }

    /* apply HTTP/3 global configuraton to the listeners */
    for (size_t i = 0; i != conf.num_listeners; ++i) {
        quicly_context_t *qctx;
        if ((qctx = conf.listeners[i]->quic.ctx) != NULL)
            h2o_http3_server_amend_quicly_context(&conf.globalconf, qctx);
    }

    /* all setup should be complete by now */

    /* replace STDIN to an closed pipe */
    {
        int fds[2];
        if (pipe(fds) != 0) {
            perror("pipe failed");
            return EX_OSERR;
        }
        close(fds[1]);
        dup2(fds[0], 0);
        close(fds[0]);
    }

    /* redirect STDOUT and STDERR to error_log (if specified) */
    if (error_log_fd != -1) {
        if (dup2(error_log_fd, 1) == -1 || dup2(error_log_fd, 2) == -1) {
            perror("dup(2) failed");
            return EX_OSERR;
        }
        close(error_log_fd);
        error_log_fd = -1;
    }

    /* start the threads */
    conf.threads = alloca(sizeof(conf.threads[0]) * conf.thread_map.size);
    pthread_t *tids = alloca(sizeof(*tids) * conf.thread_map.size);
    for (size_t i = 1; i != conf.thread_map.size; ++i)
        h2o_multithread_create_thread(&tids[i], NULL, run_loop, (void *)i);

    /* this thread becomes the first thread */
    run_loop((void *)0);

    /* wait for all threads to exit */
    for (size_t i = 1; i != conf.thread_map.size; ++i) {
        if (pthread_join(tids[i], NULL) != 0) {
            char errbuf[256];
            h2o_fatal("pthread_join: %s", h2o_strerror_r(errno, errbuf, sizeof(errbuf)));
        }
    }

    /* remove the pid file */
    if (conf.pid_file != NULL)
        unlink(conf.pid_file);

    return 0;
}
