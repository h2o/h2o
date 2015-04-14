/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Tatsuhiko Kubo,
 *                         Domingo Alvarez Duarte, Nick Desaulniers,
 *                         Jeff Marison
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
#include <sys/un.h>
#include <sys/wait.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "yoml-parser.h"
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/serverutil.h"

/* simply use a large value, and let the kernel clip it to the internal max */
#define H2O_SOMAXCONN (65535)

#define H2O_DEFAULT_NUM_NAME_RESOLUTION_THREADS 32

struct listener_ssl_config_t {
    H2O_VECTOR(h2o_iovec_t) hostnames;
    char *certificate_file;
    SSL_CTX *ctx;
#ifndef OPENSSL_NO_OCSP
    struct {
        uint64_t interval;
        unsigned max_failures;
        char *cmd;
        pthread_t updater_tid; /* should be valid when and only when interval != 0 */
        struct {
            pthread_mutex_t mutex;
            h2o_buffer_t *data;
        } response;
    } ocsp_stapling;
#endif
};

struct listener_config_t {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    h2o_hostconf_t **hosts;
    H2O_VECTOR(struct listener_ssl_config_t) ssl;
};

struct listener_ctx_t {
    h2o_context_t *ctx;
    h2o_hostconf_t **hosts;
    SSL_CTX *ssl_ctx;
    h2o_socket_t *sock;
};

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
        char *bound_fd_map; /* has `num_fds` elements, set to 1 if fd[index] was bound to one of the listeners */
        size_t num_fds;
    } server_starter;
    struct listener_config_t **listeners;
    size_t num_listeners;
    struct passwd *running_user; /* NULL if not set */
    char *pid_file;
    char *error_log;
    int max_connections;
    size_t num_threads;
    struct {
        pthread_t tid;
        h2o_context_t ctx;
        h2o_multithread_receiver_t server_notifications;
    } *threads;
    volatile sig_atomic_t shutdown_requested;
    struct {
        /* unused buffers exist to avoid false sharing of the cache line */
        char _unused1[32];
        int _num_connections; /* should use atomic functions to update the value */
        char _unused2[32];
    } state;
} conf = {
    {},   /* globalconf */
    0,    /* dry-run */
    {},   /* server_starter */
    NULL, /* listeners */
    0,    /* num_listeners */
    NULL, /* running_user */
    NULL, /* pid_file */
    NULL, /* error_log */
    1024, /* max_connections */
    0,    /* initialized in main() */
    NULL, /* thread_ids */
    0,    /* shutdown_requested */
    {},   /* state */
};

static void set_cloexec(int fd)
{
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        perror("failed to set FD_CLOEXEC");
        abort();
    }
}

static char *get_cmd_path(const char *cmd)
{
    char *root, *cmd_fullpath;

    /* just return the cmd (being strdup'ed) in case we do not need to prefix the value */
    if (cmd[0] == '/' || strchr(cmd, '/') == NULL)
        goto ReturnOrig;

    /* obtain root */
    if ((root = getenv("H2O_ROOT")) == NULL) {
#ifdef H2O_ROOT
        root = H2O_ROOT;
#endif
        if (root == NULL)
            goto ReturnOrig;
    }

    /* build full-path and return */
    cmd_fullpath = h2o_mem_alloc(strlen(root) + strlen(cmd) + 2);
    sprintf(cmd_fullpath, "%s/%s", root, cmd);
    return cmd_fullpath;

ReturnOrig:
    return h2o_strdup(NULL, cmd, SIZE_MAX).base;
}

static int on_openssl_print_errors(const char *str, size_t len, void *fp)
{
    fwrite(str, 1, len, fp);
    return (int)len;
}

static unsigned long openssl_thread_id_callback(void)
{
    return (unsigned long)pthread_self();
}

static pthread_mutex_t *openssl_thread_locks;

static void openssl_thread_lock_callback(int mode, int n, const char *file, int line)
{
    if ((mode & CRYPTO_LOCK) != 0) {
        pthread_mutex_lock(openssl_thread_locks + n);
    } else if ((mode & CRYPTO_UNLOCK) != 0) {
        pthread_mutex_unlock(openssl_thread_locks + n);
    } else {
        assert(!"unexpected mode");
    }
}

static void init_openssl(void)
{
    static int ready = 0;
    if (!ready) {
        int nlocks = CRYPTO_num_locks(), i;
        openssl_thread_locks = h2o_mem_alloc(sizeof(*openssl_thread_locks) * nlocks);
        for (i = 0; i != nlocks; ++i)
            pthread_mutex_init(openssl_thread_locks + i, NULL);
        CRYPTO_set_locking_callback(openssl_thread_lock_callback);
        CRYPTO_set_id_callback(openssl_thread_id_callback);
        /* TODO [OpenSSL] set dynlock callbacks for better performance */
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ready = 1;
    }
}

static void setup_ecc_key(SSL_CTX *ssl_ctx)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ssl_ctx, key);
    EC_KEY_free(key);
}

static int on_sni_callback(SSL *ssl, int *ad, void *arg)
{
    struct listener_config_t *listener = arg;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    size_t ctx_index = 0;

    if (name != NULL) {
        size_t i, j, name_len = strlen(name);
        for (i = 0; i != listener->ssl.size; ++i) {
            struct listener_ssl_config_t *ssl_config = listener->ssl.entries + i;
            for (j = 0; j != ssl_config->hostnames.size; ++j) {
                if (h2o_lcstris(name, name_len, ssl_config->hostnames.entries[j].base, ssl_config->hostnames.entries[j].len)) {
                    ctx_index = i;
                    goto Found;
                }
            }
        }
        ctx_index = 0;
    Found:
        ;
    }

    if (SSL_get_SSL_CTX(ssl) != listener->ssl.entries[ctx_index].ctx)
        SSL_set_SSL_CTX(ssl, listener->ssl.entries[ctx_index].ctx);

    return SSL_TLSEXT_ERR_OK;
}

#ifndef OPENSSL_NO_OCSP

static void update_ocsp_stapling(struct listener_ssl_config_t *ssl_conf, h2o_buffer_t *resp)
{
    pthread_mutex_lock(&ssl_conf->ocsp_stapling.response.mutex);
    if (ssl_conf->ocsp_stapling.response.data != NULL)
        h2o_buffer_dispose(&ssl_conf->ocsp_stapling.response.data);
    ssl_conf->ocsp_stapling.response.data = resp;
    pthread_mutex_unlock(&ssl_conf->ocsp_stapling.response.mutex);
}

static int get_ocsp_response(const char *cert_fn, const char *cmd, h2o_buffer_t **resp)
{
    char *cmd_fullpath = get_cmd_path(cmd), *argv[] = {cmd_fullpath, (char *)cert_fn, NULL};
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
        status = get_ocsp_response(ssl_conf->certificate_file, ssl_conf->ocsp_stapling.cmd, &resp);
        switch (status) {
        case 0: /* success */
            fail_cnt = 0;
            update_ocsp_stapling(ssl_conf, resp);
            fprintf(stderr, "[OCSP Stapling] successfully updated the response for certificate file:%s\n",
                    ssl_conf->certificate_file);
            break;
        case EX_TEMPFAIL: /* temporary failure */
            if (fail_cnt == ssl_conf->ocsp_stapling.max_failures) {
                fprintf(stderr,
                        "[OCSP Stapling] OCSP stapling is temporary disabled due to repeated errors for certificate file:%s\n",
                        ssl_conf->certificate_file);
                update_ocsp_stapling(ssl_conf, NULL);
            } else {
                fprintf(stderr, "[OCSP Stapling] reusing old response due to a temporary error occurred while fetching OCSP "
                                "response for certificate file:%s\n",
                        ssl_conf->certificate_file);
                ++fail_cnt;
            }
            break;
        default: /* permanent failure */
            fprintf(stderr, "[OCSP Stapling] disabled for certificate file:%s\n", ssl_conf->certificate_file);
            goto Exit;
        }
        /* update next_at */
        next_at = time(NULL) + ssl_conf->ocsp_stapling.interval;
    }

Exit:
    return NULL;
}

static int on_ocsp_stapling_callback(SSL *ssl, void *_ssl_conf)
{
    struct listener_ssl_config_t *ssl_conf = _ssl_conf;
    void *resp = NULL;
    size_t len = 0;

    /* fetch ocsp response */
    pthread_mutex_lock(&ssl_conf->ocsp_stapling.response.mutex);
    if (ssl_conf->ocsp_stapling.response.data != NULL) {
        resp = CRYPTO_malloc((int)ssl_conf->ocsp_stapling.response.data->size, __FILE__, __LINE__);
        if (resp != NULL) {
            len = ssl_conf->ocsp_stapling.response.data->size;
            memcpy(resp, ssl_conf->ocsp_stapling.response.data->bytes, len);
        }
    }
    pthread_mutex_unlock(&ssl_conf->ocsp_stapling.response.mutex);

    if (resp != NULL) {
        SSL_set_tlsext_status_ocsp_resp(ssl, resp, len);
        return SSL_TLSEXT_ERR_OK;
    } else {
        return SSL_TLSEXT_ERR_NOACK;
    }
}

#endif

static void listener_setup_ssl_add_host(struct listener_ssl_config_t *ssl_config, h2o_iovec_t host)
{
    const char *host_end = memchr(host.base, ':', host.len);
    if (host_end == NULL)
        host_end = host.base + host.len;

    h2o_vector_reserve(NULL, (void *)&ssl_config->hostnames, sizeof(ssl_config->hostnames.entries[0]),
                       ssl_config->hostnames.size + 1);
    ssl_config->hostnames.entries[ssl_config->hostnames.size++] = h2o_iovec_init(host.base, host_end - host.base);
}

static int listener_setup_ssl(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *listen_node,
                              yoml_t *ssl_node, struct listener_config_t *listener, int listener_is_new)
{
    SSL_CTX *ssl_ctx = NULL;
    yoml_t *certificate_file = NULL, *key_file = NULL, *dh_file = NULL, *minimum_version = NULL, *cipher_suite = NULL,
           *ocsp_update_cmd = NULL, *ocsp_update_interval_node = NULL, *ocsp_max_failures_node = NULL;
    long ssl_options = SSL_OP_ALL;
    uint64_t ocsp_update_interval = 4 * 60 * 60; /* defaults to 4 hours */
    unsigned ocsp_max_failures = 3;              /* defaults to 3; permit 3 failures before temporary disabling OCSP stapling */

    if (!listener_is_new) {
        if (listener->ssl.size != 0 && ssl_node == NULL) {
            h2o_configurator_errprintf(cmd, listen_node, "cannot accept HTTP; already defined to accept HTTPS");
            return -1;
        }
        if (listener->ssl.size == 0 && ssl_node != NULL) {
            h2o_configurator_errprintf(cmd, ssl_node, "cannot accept HTTPS; already defined to accept HTTP");
            return -1;
        }
    }

    if (ssl_node == NULL)
        return 0;
    if (ssl_node->type != YOML_TYPE_MAPPING) {
        h2o_configurator_errprintf(cmd, ssl_node, "`ssl` is not a mapping");
        return -1;
    }

    { /* parse */
        size_t i;
        for (i = 0; i != ssl_node->data.sequence.size; ++i) {
            yoml_t *key = ssl_node->data.mapping.elements[i].key, *value = ssl_node->data.mapping.elements[i].value;
            /* obtain the target command */
            if (key->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(NULL, key, "command must be a string");
                return -1;
            }
#define FETCH_PROPERTY(n, p)                                                                                                       \
    if (strcmp(key->data.scalar, n) == 0) {                                                                                        \
        if (value->type != YOML_TYPE_SCALAR) {                                                                                     \
            h2o_configurator_errprintf(cmd, value, "property of `" n "` must be a string");                                        \
            return -1;                                                                                                             \
        }                                                                                                                          \
        p = value;                                                                                                                 \
        continue;                                                                                                                  \
    }
            FETCH_PROPERTY("certificate-file", certificate_file);
            FETCH_PROPERTY("key-file", key_file);
            FETCH_PROPERTY("minimum-version", minimum_version);
            FETCH_PROPERTY("cipher-suite", cipher_suite);
            FETCH_PROPERTY("ocsp-update-cmd", ocsp_update_cmd);
            FETCH_PROPERTY("ocsp-update-interval", ocsp_update_interval_node);
            FETCH_PROPERTY("ocsp-max-failures", ocsp_max_failures_node);
            FETCH_PROPERTY("dh-file", dh_file);
            if (strcmp(key->data.scalar, "cipher-preference") == 0) {
                if (value->type == YOML_TYPE_SCALAR && strcasecmp(value->data.scalar, "client") == 0) {
                    ssl_options &= ~SSL_OP_CIPHER_SERVER_PREFERENCE;
                } else if (value->type == YOML_TYPE_SCALAR && strcasecmp(value->data.scalar, "server") == 0) {
                    ssl_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
                } else {
                    h2o_configurator_errprintf(cmd, value, "property of `cipher-preference` must be either of: `client`, `server`");
                    return -1;
                }
                continue;
            }
            h2o_configurator_errprintf(cmd, key, "unknown property: %s", key->data.scalar);
            return -1;
#undef FETCH_PROPERTY
        }
        if (certificate_file == NULL) {
            h2o_configurator_errprintf(cmd, ssl_node, "could not find mandatory property `certificate-file`");
            return -1;
        }
        if (key_file == NULL) {
            h2o_configurator_errprintf(cmd, ssl_node, "could not find mandatory property `key-file`");
            return -1;
        }
        if (minimum_version != NULL) {
#define MAP(tok, op)                                                                                                               \
    if (strcasecmp(minimum_version->data.scalar, tok) == 0) {                                                                      \
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
            h2o_configurator_errprintf(cmd, minimum_version, "unknown protocol version: %s", minimum_version->data.scalar);
        VersionFound:
            ;
        } else {
            /* default is >= TLSv1 */
            ssl_options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
        }
        if (ocsp_update_interval_node != NULL) {
            if (h2o_configurator_scanf(cmd, ocsp_update_interval_node, "%" PRIu64, &ocsp_update_interval) != 0)
                goto Error;
        }
        if (ocsp_max_failures_node != NULL) {
            if (h2o_configurator_scanf(cmd, ocsp_max_failures_node, "%u", &ocsp_max_failures) != 0)
                goto Error;
        }
    }

    /* add the host to the existing SSL config, if the certificate file is already registered */
    if (ctx->hostconf != NULL) {
        size_t i;
        for (i = 0; i != listener->ssl.size; ++i) {
            struct listener_ssl_config_t *ssl_config = listener->ssl.entries + i;
            if (strcmp(ssl_config->certificate_file, certificate_file->data.scalar) == 0) {
                listener_setup_ssl_add_host(ssl_config, ctx->hostconf->hostname);
                return 0;
            }
        }
    }

/* disable tls compression to avoid "CRIME" attacks (see http://en.wikipedia.org/wiki/CRIME) */
#ifdef SSL_OP_NO_COMPRESSION
    ssl_options |= SSL_OP_NO_COMPRESSION;
#endif

    /* setup */
    init_openssl();
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ssl_ctx, ssl_options);
    setup_ecc_key(ssl_ctx);
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_file->data.scalar) != 1) {
        h2o_configurator_errprintf(cmd, certificate_file, "failed to load certificate file:%s\n", certificate_file->data.scalar);
        ERR_print_errors_cb(on_openssl_print_errors, stderr);
        goto Error;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file->data.scalar, SSL_FILETYPE_PEM) != 1) {
        h2o_configurator_errprintf(cmd, key_file, "failed to load private key file:%s\n", key_file->data.scalar);
        ERR_print_errors_cb(on_openssl_print_errors, stderr);
        goto Error;
    }
    if (cipher_suite != NULL && SSL_CTX_set_cipher_list(ssl_ctx, cipher_suite->data.scalar) != 1) {
        h2o_configurator_errprintf(cmd, cipher_suite, "failed to setup SSL cipher suite\n");
        ERR_print_errors_cb(on_openssl_print_errors, stderr);
        goto Error;
    }
    if (dh_file != NULL) {
        BIO *bio = BIO_new_file(dh_file->data.scalar, "r");
        if (bio == NULL) {
            h2o_configurator_errprintf(cmd, dh_file, "failed to load dhparam file:%s\n", dh_file->data.scalar);
            ERR_print_errors_cb(on_openssl_print_errors, stderr);
            goto Error;
        }
        DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (dh == NULL) {
            h2o_configurator_errprintf(cmd, dh_file, "failed to load dhparam file:%s\n", dh_file->data.scalar);
            ERR_print_errors_cb(on_openssl_print_errors, stderr);
            goto Error;
        }
        SSL_CTX_set_tmp_dh(ssl_ctx, dh);
        SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
        DH_free(dh);
    }

/* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(ssl_ctx, h2o_http2_alpn_protocols);
#endif

    /* set SNI callback to the first SSL context, when and only when it should be used */
    if (listener->ssl.size == 1) {
        SSL_CTX_set_tlsext_servername_callback(listener->ssl.entries[0].ctx, on_sni_callback);
        SSL_CTX_set_tlsext_servername_arg(listener->ssl.entries[0].ctx, listener);
    }

    { /* create a new entry in the SSL context list */
        struct listener_ssl_config_t *ssl_config;
        h2o_vector_reserve(NULL, (void *)&listener->ssl, sizeof(listener->ssl.entries[0]), listener->ssl.size + 1);
        ssl_config = listener->ssl.entries + listener->ssl.size++;
        memset(ssl_config, 0, sizeof(*ssl_config));
        if (ctx->hostconf != NULL) {
            listener_setup_ssl_add_host(ssl_config, ctx->hostconf->hostname);
        }
        ssl_config->ctx = ssl_ctx;
        ssl_config->certificate_file = h2o_strdup(NULL, certificate_file->data.scalar, SIZE_MAX).base;
#ifdef OPENSSL_NO_OCSP
        if (ocsp_update_interval != 0)
            fprintf(stderr, "[OCSP Stapling] disabled (not support by the SSL library)\n");
#else
        SSL_CTX_set_tlsext_status_cb(ssl_ctx, on_ocsp_stapling_callback);
        SSL_CTX_set_tlsext_status_arg(ssl_ctx, ssl_config);
        pthread_mutex_init(&ssl_config->ocsp_stapling.response.mutex, NULL);
        ssl_config->ocsp_stapling.cmd =
            ocsp_update_cmd != NULL ? strdup(ocsp_update_cmd->data.scalar) : "share/h2o/fetch-ocsp-response";
        if (ocsp_update_interval != 0) {
            switch (conf.run_mode) {
            case RUN_MODE_WORKER:
                ssl_config->ocsp_stapling.interval =
                    ocsp_update_interval; /* is also used as a flag for indicating if the updater thread was spawned */
                ssl_config->ocsp_stapling.max_failures = ocsp_max_failures;
                pthread_create(&ssl_config->ocsp_stapling.updater_tid, NULL, ocsp_updater_thread, ssl_config);
                break;
            case RUN_MODE_MASTER:
            case RUN_MODE_DAEMON:
                /* nothing to do */
                break;
            case RUN_MODE_TEST: {
                h2o_buffer_t *respbuf;
                fprintf(stderr, "[OCSP Stapling] testing for certificate file:%s\n", certificate_file->data.scalar);
                switch (get_ocsp_response(certificate_file->data.scalar, ssl_config->ocsp_stapling.cmd, &respbuf)) {
                case 0:
                    h2o_buffer_dispose(&respbuf);
                    fprintf(stderr, "[OCSP Stapling] stapling works for file:%s\n", certificate_file->data.scalar);
                    break;
                case EX_TEMPFAIL:
                    h2o_configurator_errprintf(cmd, certificate_file, "[OCSP Stapling] temporary failed for file:%s\n",
                                               certificate_file->data.scalar);
                    break;
                default:
                    h2o_configurator_errprintf(cmd, certificate_file,
                                               "[OCSP Stapling] does not work, will be disabled for file:%s\n",
                                               certificate_file->data.scalar);
                    break;
                }
            } break;
            }
        }
#endif
    }

    return 0;

Error:
    if (ssl_ctx != NULL)
        SSL_CTX_free(ssl_ctx);
    return -1;
}

static struct listener_config_t *find_listener(struct sockaddr *addr, socklen_t addrlen)
{
    size_t i;

    for (i = 0; i != conf.num_listeners; ++i) {
        struct listener_config_t *listener = conf.listeners[i];
        if (listener->addrlen == addrlen && h2o_socket_compare_address((void *)&listener->addr, addr) == 0)
            return listener;
    }

    return NULL;
}

static struct listener_config_t *add_listener(int fd, struct sockaddr *addr, socklen_t addrlen, int is_global)
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
    conf.listeners = h2o_mem_realloc(conf.listeners, sizeof(*conf.listeners) * (conf.num_listeners + 1));
    conf.listeners[conf.num_listeners++] = listener;

    return listener;
}

static int find_listener_from_server_starter(struct sockaddr *addr)
{
    size_t i;

    assert(conf.server_starter.fds != NULL);
    assert(conf.server_starter.num_fds != 0);

    for (i = 0; i != conf.server_starter.num_fds; ++i) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof(sa);
        if (getsockname(conf.server_starter.fds[i], (void *)&sa, &salen) != 0) {
            fprintf(stderr, "could not get the socket address of fd %d given as $SERVER_STARTER_PORT\n",
                    conf.server_starter.fds[i]);
            exit(EX_CONFIG);
        }
        if (h2o_socket_compare_address((void *)&sa, addr) == 0)
            goto Found;
    }
    /* not found */
    return -1;

Found:
    conf.server_starter.bound_fd_map[i] = 1;
    return conf.server_starter.fds[i];
}

static int open_unix_listener(h2o_configurator_command_t *cmd, yoml_t *node, struct sockaddr_un *sun)
{
    struct stat st;
    int fd;

    /* remove existing socket file as suggested in #45 */
    if (lstat(sun->sun_path, &st) == 0) {
        if (S_ISSOCK(st.st_mode)) {
            unlink(sun->sun_path);
        } else {
            h2o_configurator_errprintf(cmd, node, "path:%s already exists and is not an unix socket.", sun->sun_path);
            return -1;
        }
    }
    /* add new listener */
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 || bind(fd, (void *)sun, sizeof(*sun)) != 0 ||
        listen(fd, H2O_SOMAXCONN) != 0) {
        if (fd != -1)
            close(fd);
        h2o_configurator_errprintf(NULL, node, "failed to listen to socket:%s: %s", sun->sun_path, strerror(errno));
        return -1;
    }
    set_cloexec(fd);

    return fd;
}

static int open_tcp_listener(h2o_configurator_command_t *cmd, yoml_t *node, const char *hostname, const char *servname, int domain,
                             int type, int protocol, struct sockaddr *addr, socklen_t addrlen)
{
    int fd;

    if ((fd = socket(domain, type, protocol)) == -1)
        goto Error;
    set_cloexec(fd);
    { /* set reuseaddr */
        int flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) != 0)
            goto Error;
    }
#ifdef TCP_DEFER_ACCEPT
    { /* set TCP_DEFER_ACCEPT */
        int flag = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &flag, sizeof(flag)) != 0)
            goto Error;
    }
#endif
#ifdef IPV6_V6ONLY
    /* set IPv6only */
    if (domain == AF_INET6) {
        int flag = 1;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0)
            goto Error;
    }
#endif
    if (bind(fd, addr, addrlen) != 0)
        goto Error;
    if (listen(fd, H2O_SOMAXCONN) != 0)
        goto Error;

    return fd;

Error:
    if (fd != -1)
        close(fd);
    h2o_configurator_errprintf(NULL, node, "failed to listen to port %s:%s: %s", hostname != NULL ? hostname : "ANY", servname,
                               strerror(errno));
    return -1;
}

static int on_config_listen(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    const char *hostname = NULL, *servname = NULL, *type = "tcp";
    yoml_t *ssl_node = NULL;

    /* fetch servname (and hostname) */
    switch (node->type) {
    case YOML_TYPE_SCALAR:
        servname = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t *t;
        if ((t = yoml_get(node, "host")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, t, "`host` is not a string");
                return -1;
            }
            hostname = t->data.scalar;
        }
        if ((t = yoml_get(node, "port")) == NULL) {
            h2o_configurator_errprintf(cmd, node, "cannot find mandatory property `port`");
            return -1;
        }
        if (t->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, node, "`port` is not a string");
            return -1;
        }
        servname = t->data.scalar;
        if ((t = yoml_get(node, "type")) != NULL) {
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, t, "`type` is not a string");
                return -1;
            }
            type = t->data.scalar;
        }
        if ((t = yoml_get(node, "ssl")) != NULL)
            ssl_node = t;
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "value must be a string or a mapping (with keys: `port` and optionally `host`)");
        return -1;
    }

    if (strcmp(type, "unix") == 0) {

        /* unix socket */
        struct sockaddr_un sun;
        int listener_is_new;
        struct listener_config_t *listener;
        /* build sockaddr */
        if (strlen(servname) >= sizeof(sun.sun_path)) {
            h2o_configurator_errprintf(cmd, node, "path:%s is too long as a unix socket name", servname);
            return -1;
        }
        sun.sun_family = AF_UNIX;
        strcpy(sun.sun_path, servname);
        /* find existing listener or create a new one */
        listener_is_new = 0;
        if ((listener = find_listener((void *)&sun, sizeof(sun))) == NULL) {
            int fd = -1;
            switch (conf.run_mode) {
            case RUN_MODE_WORKER:
                if (conf.server_starter.fds != NULL) {
                    if ((fd = find_listener_from_server_starter((void *)&sun)) == -1) {
                        h2o_configurator_errprintf(cmd, node, "unix socket:%s is not being bound to the server\n", sun.sun_path);
                        return -1;
                    }
                } else {
                    if ((fd = open_unix_listener(cmd, node, &sun)) == -1)
                        return -1;
                }
                break;
            default:
                break;
            }
            listener = add_listener(fd, (struct sockaddr *)&sun, sizeof(sun), ctx->hostconf == NULL);
            listener_is_new = 1;
        }
        if (listener_setup_ssl(cmd, ctx, node, ssl_node, listener, listener_is_new) != 0)
            return -1;
        if (listener->hosts != NULL && ctx->hostconf != NULL)
            h2o_append_to_null_terminated_list((void *)&listener->hosts, ctx->hostconf);

    } else if (strcmp(type, "tcp") == 0) {

        /* TCP socket */
        struct addrinfo hints, *res, *ai;
        int error;
        /* call getaddrinfo */
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
        if ((error = getaddrinfo(hostname, servname, &hints, &res)) != 0) {
            h2o_configurator_errprintf(cmd, node, "failed to resolve the listening address: %s", gai_strerror(error));
            return -1;
        } else if (res == NULL) {
            h2o_configurator_errprintf(cmd, node, "failed to resolve the listening address: getaddrinfo returned an empty list");
            return -1;
        }
        /* listen to the returned addresses */
        for (ai = res; ai != NULL; ai = ai->ai_next) {
            struct listener_config_t *listener = find_listener(ai->ai_addr, ai->ai_addrlen);
            int listener_is_new = 0;
            if (listener == NULL) {
                int fd = -1;
                switch (conf.run_mode) {
                case RUN_MODE_WORKER:
                    if (conf.server_starter.fds != NULL) {
                        if ((fd = find_listener_from_server_starter(ai->ai_addr)) == -1) {
                            h2o_configurator_errprintf(cmd, node, "tcp socket:%s:%s is not being bound to the server\n", hostname,
                                                       servname);
                            return -1;
                        }
                    } else {
                        if ((fd = open_tcp_listener(cmd, node, hostname, servname, ai->ai_family, ai->ai_socktype, ai->ai_protocol,
                                                    ai->ai_addr, ai->ai_addrlen)) == -1)
                            return -1;
                    }
                    break;
                default:
                    break;
                }
                listener = add_listener(fd, ai->ai_addr, ai->ai_addrlen, ctx->hostconf == NULL);
                listener_is_new = 1;
            }
            if (listener_setup_ssl(cmd, ctx, node, ssl_node, listener, listener_is_new) != 0)
                return -1;
            if (listener->hosts != NULL && ctx->hostconf != NULL)
                h2o_append_to_null_terminated_list((void *)&listener->hosts, ctx->hostconf);
        }
        /* release res */
        freeaddrinfo(res);

    } else {

        h2o_configurator_errprintf(cmd, node, "unknown listen type: %s", type);
        return -1;
    }

    return 0;
}

static int on_config_listen_enter(h2o_configurator_t *_configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    return 0;
}

static int on_config_listen_exit(h2o_configurator_t *_configurator, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (ctx->hostconf == NULL) {
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

static int setup_running_user(const char *login)
{
    struct passwd *passwdbuf = h2o_mem_alloc(sizeof(*passwdbuf));
    char *buf;
    size_t bufsz = 4096;

Redo:
    buf = h2o_mem_alloc(bufsz);
    if (getpwnam_r(login, passwdbuf, buf, bufsz, &conf.running_user) != 0) {
        if (errno == ERANGE
#ifdef __APPLE__
            || errno == EINVAL /* OS X 10.9.5 returns EINVAL if bufsz == 16 */
#endif
            ) {
            free(buf);
            bufsz *= 2;
            goto Redo;
        }
        perror("getpwnam_r");
    }
    if (conf.running_user == NULL)
        return -1;

    return 0;
}

static int on_config_user(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (setup_running_user(node->data.scalar) != 0) {
        h2o_configurator_errprintf(cmd, node, "user:%s does not exist", node->data.scalar);
        return -1;
    }

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

static int on_config_num_threads(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (h2o_configurator_scanf(cmd, node, "%zu", &conf.num_threads) != 0)
        return -1;
    if (conf.num_threads == 0) {
        h2o_configurator_errprintf(cmd, node, "num-threads should be >=1");
        return -1;
    }
    return 0;
}

static int on_config_num_name_resolution_threads(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (h2o_configurator_scanf(cmd, node, "%zu", &h2o_hostinfo_max_threads) != 0)
        return -1;
    if (h2o_hostinfo_max_threads == 0) {
        h2o_configurator_errprintf(cmd, node, "num-name-resolution-threads should be >=1");
        return -1;
    }
    return 0;
}

static void usage_print_directives(h2o_globalconf_t *conf)
{
    h2o_linklist_t *node;
    size_t i;

    for (node = conf->configurators.next; node != &conf->configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        for (i = 0; i != configurator->commands.size; ++i) {
            h2o_configurator_command_t *cmd = configurator->commands.entries + i;
            const char *desc_line;
            printf("  %s: [%s%s%s]\n", cmd->name, ("g") + ((cmd->flags & H2O_CONFIGURATOR_FLAG_GLOBAL) == 0),
                   ("h") + ((cmd->flags & H2O_CONFIGURATOR_FLAG_HOST) == 0),
                   ("p") + ((cmd->flags & H2O_CONFIGURATOR_FLAG_PATH) == 0));
            desc_line = cmd->description;
            while (*desc_line != '\0') {
                const char *eol = strchr(desc_line, '\n');
                if (eol != NULL) {
                    printf("    %.*s", (int)(eol - desc_line + 1), desc_line);
                    desc_line += eol - desc_line + 1;
                } else {
                    printf("    %s\n", desc_line);
                    break;
                }
            }
        }
        printf("\n");
    }
}

yoml_t *load_config(const char *fn)
{
    FILE *fp;
    yaml_parser_t parser;
    yoml_t *yoml;

    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "could not open configuration file:%s:%s\n", fn, strerror(errno));
        return NULL;
    }
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fp);

    yoml = yoml_parse_document(&parser, NULL, fn);

    if (yoml == NULL)
        fprintf(stderr, "failed to parse configuration file:%s:line %d:%s\n", fn, (int)parser.problem_mark.line, parser.problem);

    yaml_parser_delete(&parser);

    return yoml;
}

static void notify_all_threads(void)
{
    unsigned i;
    for (i = 0; i != conf.num_threads; ++i) {
        h2o_multithread_message_t *message = h2o_mem_alloc(sizeof(*message));
        *message = (h2o_multithread_message_t){};
        h2o_multithread_send_message(&conf.threads[i].server_notifications, message);
    }
}

static void on_sigterm(int signo)
{
    conf.shutdown_requested = 1;
    notify_all_threads();
}

static void setup_signal_handlers(void)
{
    h2o_set_signal_handler(SIGTERM, on_sigterm);
    h2o_set_signal_handler(SIGPIPE, SIG_IGN);
}

static int num_connections(int delta)
{
    return __sync_fetch_and_add(&conf.state._num_connections, delta);
}

static void on_socketclose(void *data)
{
    int prev_num_connections = num_connections(-1);

    if (prev_num_connections == conf.max_connections) {
        /* ready to accept new connections. wake up all the threads! */
        notify_all_threads();
    }
}

static void on_accept(h2o_socket_t *listener, int status)
{
    struct listener_ctx_t *ctx = listener->data;
    size_t num_accepts = conf.max_connections / 16 / conf.num_threads;
    if (num_accepts < 8)
        num_accepts = 8;

    if (status == -1) {
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

        sock->on_close.cb = on_socketclose;
        sock->on_close.data = ctx->ctx;

        if (ctx->ssl_ctx != NULL)
            h2o_accept_ssl(ctx->ctx, ctx->hosts, sock, ctx->ssl_ctx);
        else
            h2o_http1_accept(ctx->ctx, ctx->hosts, sock);

    } while (--num_accepts != 0);
}

static void update_listener_state(struct listener_ctx_t *listeners)
{
    size_t i;

    if (num_connections(0) < conf.max_connections) {
        for (i = 0; i != conf.num_listeners; ++i) {
            if (!h2o_socket_is_reading(listeners[i].sock))
                h2o_socket_read_start(listeners[i].sock, on_accept);
        }
    } else {
        for (i = 0; i != conf.num_listeners; ++i) {
            if (h2o_socket_is_reading(listeners[i].sock))
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

H2O_NORETURN static void *run_loop(void *_thread_index)
{
    size_t thread_index = (size_t)_thread_index;
    struct listener_ctx_t *listeners = alloca(sizeof(*listeners) * conf.num_listeners);
    size_t i;

    h2o_context_init(&conf.threads[thread_index].ctx, h2o_evloop_create(), &conf.globalconf);
    h2o_multithread_register_receiver(conf.threads[thread_index].ctx.queue, &conf.threads[thread_index].server_notifications,
                                      on_server_notification);
    conf.threads[thread_index].tid = pthread_self();

    if (conf.num_listeners < 1) {
      perror("not enought listeners to start listening");
      abort();
    }

    /* setup listeners */
    for (i = 0; i != conf.num_listeners; ++i) {
        struct listener_config_t *listener_config = conf.listeners[i];
        int fd;
        /* dup the listener fd for other threads than the main thread */
        if (thread_index == 0) {
            fd = listener_config->fd;
        } else {
            if ((fd = dup(listener_config->fd)) == -1) {
                perror("failed to dup listening socket");
                abort();
            }
            set_cloexec(fd);
        }
        listeners[i] = (struct listener_ctx_t){
            &conf.threads[thread_index].ctx,                                             /* ctx */
            listener_config->hosts,                                                      /* hosts */
            listener_config->ssl.size != 0 ? listener_config->ssl.entries[0].ctx : NULL, /* ssl_ctx */
            h2o_evloop_socket_create(conf.threads[thread_index].ctx.loop, fd, (struct sockaddr *)&listener_config->addr,
                                     listener_config->addrlen, H2O_SOCKET_FLAG_DONT_READ) /* sock */
        };
        listeners[i].sock->data = listeners + i;
    }
    /* and start listening */
    update_listener_state(listeners);

    /* the main loop */
    while (1) {
        if (conf.shutdown_requested)
            break;
        update_listener_state(listeners);
        /* run the loop once */
        h2o_evloop_run(conf.threads[thread_index].ctx.loop);
    }

    if (thread_index == 0)
        fprintf(stderr, "received SIGTERM, gracefully shutting down\n");

    /* shutdown requested, close the listeners, notify the protocol handlers */
    for (i = 0; i != conf.num_listeners; ++i) {
        h2o_socket_close(listeners[i].sock);
        listeners[i].sock = NULL;
    }
    h2o_context_request_shutdown(&conf.threads[thread_index].ctx);

    /* wait until all the connection gets closed */
    while (num_connections(0) != 0)
        h2o_evloop_run(conf.threads[thread_index].ctx.loop);

    /* the process that detects num_connections becoming zero performs the last cleanup */
    if (conf.pid_file != NULL)
        unlink(conf.pid_file);
    _exit(0);
}

static char **build_server_starter_argv(const char *h2o_cmd, const char *config_file)
{
    H2O_VECTOR(char *)args = {};
    size_t i;

    h2o_vector_reserve(NULL, (void *)&args, sizeof(args.entries[0]), 1);
    args.entries[args.size++] = get_cmd_path("share/h2o/start_server");

    /* error-log and pid-file are the directives that are handled by server-starter */
    if (conf.pid_file != NULL) {
        h2o_vector_reserve(NULL, (void *)&args, sizeof(args.entries[0]), args.size + 1);
        args.entries[args.size++] =
            h2o_concat(NULL, h2o_iovec_init(H2O_STRLIT("--pid-file=")), h2o_iovec_init(conf.pid_file, strlen(conf.pid_file))).base;
    }
    if (conf.error_log != NULL) {
        h2o_vector_reserve(NULL, (void *)&args, sizeof(args.entries[0]), args.size + 1);
        args.entries[args.size++] = h2o_concat(NULL, h2o_iovec_init(H2O_STRLIT("--log-file=")),
                                               h2o_iovec_init(conf.error_log, strlen(conf.error_log))).base;
    }

    switch (conf.run_mode) {
    case RUN_MODE_DAEMON:
        h2o_vector_reserve(NULL, (void *)&args, sizeof(args.entries[0]), args.size + 1);
        args.entries[args.size++] = "--daemonize";
        break;
    default:
        break;
    }

    for (i = 0; i != conf.num_listeners; ++i) {
        char *newarg;
        switch (conf.listeners[i]->addr.ss_family) {
        default: {
            char host[NI_MAXHOST], serv[NI_MAXSERV];
            int err;
            if ((err = getnameinfo((void *)&conf.listeners[i]->addr, conf.listeners[i]->addrlen, host, sizeof(host), serv,
                                   sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
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
            struct sockaddr_un *sun = (void *)&conf.listeners[i]->addr;
            newarg = h2o_mem_alloc(sizeof("--path=") + strlen(sun->sun_path));
            sprintf(newarg, "--path=%s", sun->sun_path);
        } break;
        }
        h2o_vector_reserve(NULL, (void *)&args, sizeof(args.entries[0]), args.size + 1);
        args.entries[args.size++] = newarg;
    }

    h2o_vector_reserve(NULL, (void *)&args, sizeof(args.entries[0]), args.size + 5);
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

static void setup_configurators(void)
{
    h2o_config_init(&conf.globalconf);

    {
        h2o_configurator_t *c = h2o_configurator_create(&conf.globalconf, sizeof(*c));
        c->enter = on_config_listen_enter;
        c->exit = on_config_listen_exit;
        h2o_configurator_define_command(c, "listen", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST, on_config_listen,
                                        "port at which the server should listen for incoming requests (mandatory)\n"
                                        " - if the value is a scalar, it is treated as the port number (or as the\n"
                                        "   service name)\n"
                                        " - if the value is a mapping, following properties are recognized:\n"
                                        "     port: incoming port number or service name (mandatory)\n"
                                        "     host: incoming address (default: any address)\n"
                                        "     ssl: mapping of SSL configuration using the keys below (default: none)\n"
                                        "       certificate-file:  path of the SSL certificate file (mandatory)\n"
                                        "       key-file:          path of the SSL private key file (mandatory)\n"
                                        "       minimum-version:   minimum protocol version, should be one of:\n"
                                        "                          `SSLv2`, `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`\n"
                                        "                          (default: TLSv1)\n"
                                        "       cipher-suite:      list of cipher suites to be passed to OpenSSL via\n"
                                        "                          SSL_CTX_set_cipher_list (optional)\n"
                                        "       cipher-preference: side of the list that should be used for\n"
                                        "                          selecting the cipher-suite; should be either of:\n"
                                        "                          `client`, `server` (default: client)\n"
                                        "       dh-file:           PEM file of dhparam to use (optional)\n"
                                        "       ocsp-update-interval:\n"
                                        "                          interval for updating the OCSP stapling data (in\n"
                                        "                          seconds), or set to zero to disable OCSP stapling\n"
                                        "                          (default: 14400 = 4 hours)\n"
                                        "       ocsp-max-failures: number of consecutive OCSP queriy failures before\n"
                                        "                          stopping to send OCSP stapling data to the client\n"
                                        "                          (default: 3)\n"
                                        " - if the value is a sequence, each element should be either a scalar or a\n"
                                        "   mapping that conform to the requirements above");
    }

    {
        h2o_configurator_t *c = h2o_configurator_create(&conf.globalconf, sizeof(*c));
        h2o_configurator_define_command(c, "user", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_user,
                                        "user under with the server should handle incoming requests (default: none)");
        h2o_configurator_define_command(c, "pid-file", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_pid_file, "name of the pid file (default: none)");
        h2o_configurator_define_command(c, "error-log", H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR,
                                        on_config_error_log,
                                        "path of a file to which error logs should be appended; if the path starts\n"
                                        "with `|`, the rest of the path is considered as a command to which the logs\n"
                                        "should be piped (default: stdout and stderr)");
        h2o_configurator_define_command(c, "max-connections", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_max_connections,
                                        "max connections (default: 1024)");
        h2o_configurator_define_command(c, "num-threads", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_num_threads,
                                        "number of worker threads (default: getconf NPROCESSORS_ONLN)");
        h2o_configurator_define_command(
            c, "num-name-resolution-threads", H2O_CONFIGURATOR_FLAG_GLOBAL, on_config_num_name_resolution_threads,
            "number of threads to run for name resolution (default: " H2O_TO_STR(H2O_DEFAULT_NUM_NAME_RESOLUTION_THREADS) ")");
    }

    h2o_access_log_register_configurator(&conf.globalconf);
    h2o_expires_register_configurator(&conf.globalconf);
    h2o_file_register_configurator(&conf.globalconf);
    h2o_headers_register_configurator(&conf.globalconf);
    h2o_proxy_register_configurator(&conf.globalconf);
    h2o_reproxy_register_configurator(&conf.globalconf);
    h2o_redirect_register_configurator(&conf.globalconf);
}

int main(int argc, char **argv)
{
    const char *cmd = argv[0], *opt_config_file = "h2o.conf";
    int error_log_fd = -1;

    conf.num_threads = h2o_numproc();
    h2o_hostinfo_max_threads = H2O_DEFAULT_NUM_NAME_RESOLUTION_THREADS;
    setup_configurators();

    { /* parse options */
        int ch;
        static struct option longopts[] = {{"conf", required_argument, NULL, 'c'},
                                           {"mode", required_argument, NULL, 'm'},
                                           {"test", no_argument, NULL, 't'},
                                           {"version", no_argument, NULL, 'v'},
                                           {"help", no_argument, NULL, 'h'},
                                           {NULL, 0, NULL, 0}};
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
                    if (getenv("SERVER_STARTER_PORT") != NULL) {
                        fprintf(stderr, "refusing to start in `%s` mode, environment variable SERVER_STARTER_PORT is already set\n",
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
                exit(0);
            case 'h':
                printf("h2o version " H2O_VERSION "\n"
                       "\n"
                       "Usage:\n"
                       "  h2o [options]\n"
                       "\n"
                       "Options:\n"
                       "  -c, --conf FILE    configuration file (default: h2o.conf)\n"
                       "  -m, --mode <mode>  specifies one of the following mode\n"
                       "                     - worker: invoked process handles incoming connections\n"
                       "                               (default)\n"
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
                       "Configuration File:\n"
                       "  The configuration file should be written in YAML format.  Below is the list\n"
                       "  of configuration directives; the flags indicate at which level the directives\n"
                       "  can be used; g=global, h=host, p=path.\n"
                       "\n");
                usage_print_directives(&conf.globalconf);
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
    if (conf.server_starter.fds != 0)
        conf.server_starter.bound_fd_map = alloca(conf.server_starter.num_fds);

    { /* configure */
        yoml_t *yoml;
        if ((yoml = load_config(opt_config_file)) == NULL)
            exit(EX_CONFIG);
        if (h2o_configurator_apply(&conf.globalconf, yoml) != 0)
            exit(EX_CONFIG);
        yoml_free(yoml);
    }

    /* check if all the fds passed in by server::starter were bound */
    if (conf.server_starter.fds != NULL) {
        size_t i;
        int all_were_bound = 1;
        for (i = 0; i != conf.server_starter.num_fds; ++i) {
            if (!conf.server_starter.bound_fd_map[i]) {
                fprintf(stderr, "no configuration found for fd:%d passed in by $SERVER_STARTER_PORT\n", conf.server_starter.fds[i]);
                all_were_bound = 0;
            }
        }
        if (!all_were_bound) {
            fprintf(stderr, "note: $SERVER_STARTER_PORT was \"%s\"\n", getenv("SERVER_STARTER_PORT"));
            return EX_CONFIG;
        }
    }

    unsetenv("SERVER_STARTER_PORT");

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

    /* setuid */
    if (conf.running_user != NULL) {
        if (h2o_setuidgid(conf.running_user) != 0) {
            fprintf(stderr, "failed to change the running user (are you sure you are running as root?)\n");
            return EX_OSERR;
        }
    } else {
        if (getuid() == 0) {
            if (setup_running_user("nobody") == 0) {
                fprintf(stderr, "cowardly switching to nobody; please use the `user` directive to set the running user\n");
            } else {
                fprintf(stderr, "refusing to run as root (and failed to switch to `nobody`); you can use the `user` directive to "
                                "set the running user\n");
                return EX_CONFIG;
            }
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

    fprintf(stderr, "h2o server (pid:%d) is ready to serve requests\n", (int)getpid());

    assert(conf.num_threads != 0);

    /* start the threads */
    conf.threads = alloca(sizeof(conf.threads[0]) * conf.num_threads);
    size_t i;
    for (i = 1; i != conf.num_threads; ++i) {
        pthread_t tid;
        pthread_create(&tid, NULL, run_loop, (void *)i);
    }

    /* this thread becomes the first thread */
    run_loop((void *)0);

    /* notreached */
    return 0;
}
