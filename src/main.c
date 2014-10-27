/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/err.h>
#include "yoml-parser.h"
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

/* taken from sysexits.h */
#ifndef EX_CONFIG
# define EX_CONFIG 78
#endif

struct listener_config_t {
    int fd;
    int family;
    int socktype;
    int protocol;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    SSL_CTX *ssl_ctx;
};

struct listener_ctx_t {
    h2o_context_t *ctx;
    SSL_CTX *ssl_ctx;
    h2o_socket_t *sock;
};

struct config_t {
    h2o_globalconf_t global_config;
    struct listener_config_t **listeners;
    size_t num_listeners;
    unsigned max_connections;
    unsigned num_threads;
    pthread_t *thread_ids;
    struct {
        /* unused buffers exist to avoid false sharing of the cache line */
        char _unused1[32];
        unsigned num_connections; /* should use atomic functions to update the value */
        char _unused2[32];
    } state;
};

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
    if (! ready) {
        int nlocks = CRYPTO_num_locks(), i;
        openssl_thread_locks = malloc(sizeof(*openssl_thread_locks) * nlocks);
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

static SSL_CTX *on_config_listen_setup_ssl(h2o_configurator_command_t *cmd, const char *config_file, yoml_t *config_node)
{
    SSL_CTX *ssl_ctx = NULL;
    const char *cert_file = NULL, *key_file = NULL;
    yoml_t *t;

    /* parse */
    if (config_node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(cmd, config_file, config_node, "`ssl` is not a mapping");
        goto Error;
    }
    if ((t = yoml_get(config_node, "certificate-file")) == NULL) {
        h2o_config_print_error(cmd, config_file, config_node, "could not find mandatory property `certificate-file`");
        goto Error;
    } else if (t->type != YOML_TYPE_SCALAR) {
        h2o_config_print_error(cmd, config_file, t, "the property must be a string");
        goto Error;
    }
    cert_file = t->data.scalar;
    if ((t = yoml_get(config_node, "key-file")) == NULL) {
        h2o_config_print_error(cmd, config_file, config_node, "could not find mandatory property `key-file`");
        goto Error;
    } else if (t->type != YOML_TYPE_SCALAR) {
        h2o_config_print_error(cmd, config_file, t, "the property must be a string");
        goto Error;
    }
    key_file = t->data.scalar;

    /* setup */
    init_openssl();
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
    setup_ecc_key(ssl_ctx);
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        h2o_config_print_error(cmd, config_file, config_node, "failed to load certificate file:%s\n", cert_file);
        ERR_print_errors_fp(stderr);
        goto Error;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        h2o_config_print_error(cmd, config_file, config_node, "failed to load private key file:%s\n", key_file);
        ERR_print_errors_fp(stderr);
        goto Error;
    }

    /* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(ssl_ctx, h2o_http2_alpn_protocols);
#endif

    return ssl_ctx;
Error:
    if (ssl_ctx != NULL)
        SSL_CTX_free(ssl_ctx);
    return NULL;
}

static int on_config_listen(h2o_configurator_command_t *cmd, h2o_globalconf_t *globalconf, h2o_hostconf_t *hostconf, const char *config_file, yoml_t *config_node)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, globalconf);
    const char *hostname = NULL, *servname = NULL;
    SSL_CTX *ssl_ctx = NULL;
    struct addrinfo hints, *res;
    int error;

    /* fetch servname (and hostname) */
    switch (config_node->type) {
    case YOML_TYPE_SCALAR:
        servname = config_node->data.scalar;
        break;
    case YOML_TYPE_MAPPING:
        {
            yoml_t *t;
            if ((t = yoml_get(config_node, "host")) != NULL) {
                if (t->type != YOML_TYPE_SCALAR) {
                    h2o_config_print_error(cmd, config_file, t, "`host` is not a string");
                    return -1;
                }
                hostname = t->data.scalar;
            }
            if ((t = yoml_get(config_node, "port")) == NULL) {
                h2o_config_print_error(cmd, config_file, config_node, "cannot find mandatory property `port`");
                return -1;
            }
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_config_print_error(cmd, config_file, config_node, "`port` is not a string");
                return -1;
            }
            servname = t->data.scalar;
            if ((t = yoml_get(config_node, "ssl")) != NULL) {
                if ((ssl_ctx = on_config_listen_setup_ssl(cmd, config_file, t)) == NULL)
                    return -1;
            }
        }
        break;
    default:
        h2o_config_print_error(cmd, config_file, config_node, "value must be a string or a mapping (with keys: `port` and optionally `host`)");
        return -1;
    }

    /* call getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    if ((error = getaddrinfo(hostname, servname, &hints, &res)) != 0) {
        h2o_config_print_error(cmd, config_file, config_node, "failed to resolve the listening address: %s", gai_strerror(error));
        return -1;
    } else if (res == NULL) {
        h2o_config_print_error(cmd, config_file, config_node, "failed to resolve the listening address: getaddrinfo returned an empty list");
        return -1;
    }

    { /* save the entries */
        struct addrinfo *ai;
        for (ai = res; ai != NULL; ai = ai->ai_next) {
            struct listener_config_t *listener = h2o_malloc(sizeof(*listener));
            listener->fd = -1;
            listener->family = ai->ai_family;
            listener->socktype = ai->ai_socktype;
            listener->protocol = ai->ai_protocol;
            memcpy(&listener->addr, ai->ai_addr, ai->ai_addrlen);
            listener->addrlen = ai->ai_addrlen;
            listener->ssl_ctx = ssl_ctx;
            conf->listeners = h2o_realloc(conf->listeners, sizeof(*conf->listeners) * (conf->num_listeners + 1));
            conf->listeners[conf->num_listeners++] = listener;
        }
    }

    /* release res */
    freeaddrinfo(res);

    return 0;
}

static int on_config_listen_exit(h2o_configurator_t *configurator, h2o_globalconf_t *globalconf, h2o_hostconf_t *hostconf)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, globalconf);
    int reuseaddr_flag = 1;
#ifdef IPV6_V6ONLY
    int v6only_flag = 1;
#endif
    size_t i;

    if (conf->num_listeners == 0) {
        fprintf(stderr, "mandatory configuration directive `port` is missing\n");
        return -1;
    }

    for (i = 0; i != conf->num_listeners; ++i) {
        struct listener_config_t *listener = conf->listeners[i];
        if ((listener->fd = socket(listener->family, listener->socktype, listener->protocol)) == -1
            || setsockopt(listener->fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0
#ifdef IPV6_V6ONLY
            || (listener->family == AF_INET6 && setsockopt(listener->fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only_flag, sizeof(v6only_flag)) != 0)
#endif
            || bind(listener->fd, (void*)&listener->addr, listener->addrlen) != 0
            || listen(listener->fd, SOMAXCONN) != 0) {
            char host[NI_MAXHOST], serv[NI_MAXSERV];
            getnameinfo((void*)&listener->addr, listener->addrlen, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
            fprintf(stderr, "failed to listen to port %s:%s: %s\n", host, serv, strerror(errno));
            return -1;
        }
    }

    return 0;
}

static int on_config_max_connections(h2o_configurator_command_t *cmd, h2o_globalconf_t *globalconf, h2o_hostconf_t *hostconf, const char *config_file, yoml_t *config_node)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, globalconf);
    return h2o_config_scanf(cmd, config_file, config_node, "%u", &conf->max_connections);
}


static int on_config_num_threads(h2o_configurator_command_t *cmd, h2o_globalconf_t *globalconf, h2o_hostconf_t *hostconf, const char *config_file, yoml_t *config_node)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, globalconf);
    return h2o_config_scanf(cmd, config_file, config_node, "%u", &conf->num_threads);
}

static void usage_print_directives(h2o_globalconf_t *conf, int flags_mask)
{
    h2o_linklist_t *node;
    size_t i;

    for (node = conf->configurators.next; node != &conf->configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if ((configurator->flags & flags_mask) != 0) {
            for (i = 0; i != configurator->commands.size; ++i) {
                h2o_configurator_command_t *cmd = configurator->commands.entries + i;
                const char **desc;
                printf("    %s:\n", cmd->name);
                for (desc = cmd->description; *desc != NULL; ++desc)
                    printf("      %s\n", *desc);
            }
        }
    }
}

static void usage(h2o_globalconf_t *config)
{
    printf(
        "H2O version 0.1\n"
        "\n"
        "Usage:\n"
        "  h2o [options]\n"
        "\n"
        "Options:\n"
        "  --conf=file  configuration file (default: h2o.conf)\n"
        "  --help       print this help\n"
        "\n"
        "Directives of the Configuration File:\n"
        "  global:\n");
    usage_print_directives(config, H2O_CONFIGURATOR_FLAG_GLOBAL);
    printf(
        "  per-host:\n");
    usage_print_directives(config, H2O_CONFIGURATOR_FLAG_HOST);
    printf(
        "\n"
        "  note: per-host directives can be used at the global level to define the\n"
        "  behaviour of the default host\n"
        "\n");
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

    yoml = yoml_parse_document(&parser, NULL);

    if (yoml == NULL)
        fprintf(stderr, "failed to parse configuration file:%s:%s\n", fn, parser.problem);

    yaml_parser_delete(&parser);

    return yoml;
}

static void signal_ignore_cb(int signo)
{
}

static void setup_signal_handlers(void)
{
    struct sigaction action;
    sigset_t mask;

    /* ignore SIGPIPE */
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    /* accept SIGCONT (so that we could use the signal to interrupt blocking syscalls like epoll) */
    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = signal_ignore_cb;
    sigaction(SIGCONT, &action, NULL);
    /* and make sure SIGCONT is delivered */
    pthread_sigmask(SIG_BLOCK, NULL, &mask);
    sigdelset(&mask, SIGCONT);
    pthread_sigmask(SIG_SETMASK, &mask, NULL);
}

static void on_close(h2o_context_t *ctx)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, ctx->global_config);
    unsigned prev_num_connections = __sync_fetch_and_sub(&conf->state.num_connections, 1);

    if (conf->num_threads != 1) {
        if (prev_num_connections == conf->max_connections) {
            /* ready to accept new connections.  wake up the threads! */
            pthread_t self_tid = pthread_self();
            unsigned i;
            for (i = 0; i != conf->num_threads; ++i) {
                if (conf->thread_ids[i] != self_tid)
                    pthread_kill(conf->thread_ids[i], SIGCONT);
            }
        }
    }
}

static void on_accept(h2o_socket_t *listener, int status)
{
    struct listener_ctx_t *ctx = listener->data;
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, ctx->ctx->global_config);
    int num_accepts = 16;

    if (status == -1) {
        return;
    }

    do {
        h2o_socket_t *sock;
        if (conf->state.num_connections >= conf->max_connections)
            break;
        if ((sock = h2o_evloop_socket_accept(listener)) == NULL) {
            break;
        }
        __sync_add_and_fetch(&conf->state.num_connections, 1);

        if (ctx->ssl_ctx != NULL)
            h2o_accept_ssl(ctx->ctx, sock, ctx->ssl_ctx);
        else
            h2o_http1_accept(ctx->ctx, sock);

    } while (--num_accepts != 0);
}


static void *run_loop(void *_conf)
{
    struct config_t *conf = _conf;
    h2o_evloop_t *loop;
    h2o_context_t ctx;
    struct listener_ctx_t *listeners = alloca(sizeof(*listeners) * conf->num_listeners);
    size_t i;

    /* setup loop and context */
    loop = h2o_evloop_create();
    h2o_context_init(&ctx, loop, &conf->global_config);

    /* setup listeners */
    for (i = 0; i != conf->num_listeners; ++i) {
        listeners[i].ctx = &ctx;
        listeners[i].ssl_ctx = conf->listeners[i]->ssl_ctx;
        listeners[i].sock = h2o_evloop_socket_create(
            ctx.loop, conf->listeners[i]->fd,
            (struct sockaddr*)&conf->listeners[i]->addr, conf->listeners[i]->addrlen,
            H2O_SOCKET_FLAG_IS_ACCEPT);
        listeners[i].sock->data = listeners + i;
    }

    /* the main loop */
    while (1) {
        /* start / stop trying to accept new connections */
        if (conf->state.num_connections < conf->max_connections) {
            for (i = 0; i != conf->num_listeners; ++i) {
                if (! h2o_socket_is_reading(listeners[i].sock))
                    h2o_socket_read_start(listeners[i].sock, on_accept);
            }
        } else {
            for (i = 0; i != conf->num_listeners; ++i) {
                if (h2o_socket_is_reading(listeners[i].sock))
                    h2o_socket_read_stop(listeners[i].sock);
            }
        }
        /* run the loop once */
        h2o_evloop_run(loop);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    static struct option longopts[] = {
        { "conf", required_argument, NULL, 'c' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    static struct config_t config = {
        {}, /* global_config */
        NULL, /* listeners */
        0, /* num_listeners */
        1024, /* max_connections */
        1, /* num_threads */
        NULL, /* thread_ids */
        {}, /* state */
    };

    const char *config_file = "h2o.conf";
    int opt_ch;
    yoml_t *config_yoml;

    h2o_config_init(&config.global_config);
    config.global_config.close_cb = on_close;

    {
        h2o_configurator_t *c = h2o_config_create_configurator(&config.global_config, sizeof(*c), H2O_CONFIGURATOR_FLAG_GLOBAL);
        c->exit = on_config_listen_exit;
        h2o_config_define_command(
            c, "listen", on_config_listen,
            "port at which the server should listen for incoming requests (mandatory)",
            " - if the value is a scalar, it is treated as the port number (or as the",
            "   service name)",
            " - if the value is a mapping, following properties are recognized:",
            "     port: incoming port number or service name (mandatory)",
            "     host: incoming address (default: any address)",
            "     ssl:  if using SSL (default: none)",
            "       certificate-file: path of the certificate file",
            "       key-file:         path of the key file");
        h2o_config_define_command(
            c, "max-connections", on_config_max_connections,
            "max connections (default: 1024)");
        h2o_config_define_command(
            c, "num-threads", on_config_num_threads,
            "number of worker threads (default: 1)");
    }

    h2o_access_log_register_configurator(&config.global_config);
    h2o_proxy_register_reverse_proxy_configurator(&config.global_config);

    /* parse options */
    while ((opt_ch = getopt_long(argc, argv, "c:h", longopts, NULL)) != -1) {
        switch (opt_ch) {
        case 'c':
            config_file = optarg;
            break;
        case 'h':
            usage(&config.global_config);
            exit(0);
            break;
        default:
            assert(0);
            break;
        }
    }
    argc -= optind;
    argv += optind;

    /* configure */
    if ((config_yoml = load_config(config_file)) == NULL)
        exit(EX_CONFIG);
    if (h2o_config_configure(&config.global_config, config_file, config_yoml) != 0)
        exit(EX_CONFIG);
    yoml_free(config_yoml);

    setup_signal_handlers();

    if (config.num_threads <= 1) {
        run_loop(&config);
    } else {
        config.thread_ids = alloca(sizeof(pthread_t) * config.num_threads);
        unsigned i;
        for (i = 0; i != config.num_threads; ++i) {
            pthread_create(config.thread_ids + i, NULL, run_loop, &config);
        }
        for (i = 0; i < config.num_threads; ++i) {
            pthread_join(config.thread_ids[i], NULL);
        }
    }

    return 0;
}
