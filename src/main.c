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
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include "yoml-parser.h"
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

/* taken from sysexits.h */
#ifndef EX_CONFIG
# define EX_CONFIG 78
#endif

struct config_t {
    h2o_global_configuration_t global_config;
    unsigned short listen_port;
    int listen_fd;
    unsigned max_connections;
    unsigned num_threads;
    pthread_t *thread_ids;
    struct {
        /* unused buffers exist to avoid false sharing of the cache line */
        char _unused1[32];
        unsigned num_connections; /* should use atomic functions to update the value */
        char _unused2[32];
    } state;
    h2o_configurator_t port_configurator;
    h2o_configurator_t max_connections_configurator;
    h2o_configurator_t num_threads_configurator;
};

static h2o_ssl_context_t *ssl_ctx = NULL;

static int on_config_port(h2o_configurator_t *_conf, void *ctx, const char *config_file, yoml_t *config_node)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, port_configurator, _conf);
    return h2o_config_scanf(&conf->port_configurator, config_file, config_node, "%hu", &conf->listen_port);
}

static int on_config_port_complete(h2o_configurator_t *_conf, void *_global_config)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, port_configurator, _conf);
    struct sockaddr_in addr;
    int reuseaddr_flag = 1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0);
    addr.sin_port = htons(conf->listen_port);

    if ((conf->listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1
        || setsockopt(conf->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0
        || bind(conf->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0
        || listen(conf->listen_fd, SOMAXCONN) != 0) {
        fprintf(stderr, "failed to listen to port %hu:%s\n", conf->listen_port, strerror(errno));
        return -1;
    }

    return 0;
}

static int on_config_max_connections(h2o_configurator_t *_conf, void *ctx, const char *config_file, yoml_t *config_node)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, max_connections_configurator, _conf);
    return h2o_config_scanf(&conf->max_connections_configurator, config_file, config_node, "%u", &conf->max_connections);
}


static int on_config_num_threads(h2o_configurator_t *_conf, void *ctx, const char *config_file, yoml_t *config_node)
{
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, num_threads_configurator, _conf);
    return h2o_config_scanf(&conf->num_threads_configurator, config_file, config_node, "%u", &conf->num_threads);
}

static void usage_print_directives(h2o_linklist_t *configurators)
{
    h2o_linklist_t *node;

    for (node = configurators->next; node != configurators; node = node->next) {
        h2o_configurator_t *c = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        const char **desc;
        printf("    %s:\n", c->cmd);
        for (desc = c->description; *desc != NULL; ++desc)
            printf("      %s\n", *desc);
    }
}

static void usage(h2o_global_configuration_t *config)
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
    usage_print_directives(&config->global_configurators);
    printf(
        "  per-host:\n");
    usage_print_directives(&config->host_configurators);
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
    h2o_context_t *ctx = listener->data;
    struct config_t *conf = H2O_STRUCT_FROM_MEMBER(struct config_t, global_config, ctx->global_config);
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

        if (ssl_ctx != NULL)
            h2o_accept_ssl(ctx, sock, ssl_ctx);
        else
            h2o_http1_accept(ctx, sock);

    } while (--num_accepts != 0);
}


static void *run_loop(void *_conf)
{
    struct config_t *conf = _conf;
    h2o_evloop_t *loop;
    h2o_context_t ctx;
    h2o_socket_t *listener;

    /* setup loop and context */
    loop = h2o_evloop_create();
    h2o_context_init(&ctx, loop, &conf->global_config);
    /* ssl_ctx = h2o_ssl_new_server_context("server.crt", "server.key", h2o_http2_tls_identifiers); */

    listener = h2o_evloop_socket_create(ctx.loop, conf->listen_fd, H2O_SOCKET_FLAG_IS_ACCEPT);
    listener->data = &ctx;

    /* the main loop */
    while (1) {
        /* start / stop trying to accept new connections */
        if (conf->state.num_connections < conf->max_connections) {
            if (! h2o_socket_is_reading(listener))
                h2o_socket_read_start(listener, on_accept);
        } else {
            if (h2o_socket_is_reading(listener))
                h2o_socket_read_stop(listener);
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

    static const char *port_configurator_desc[] = {
        "TCP port number to which the server should listen (mandatory)",
        NULL
    };
    static const char *num_threads_configurator_desc[] = {
        "number of worker threads (default: 1)",
        NULL
    };
    static const char *max_connections_configurator_desc[] = {
        "max connections (default: 1024)",
        NULL
    };
    static struct config_t config = {
        {}, /* global_config */
        0, /* listen_port */
        -1, /* listen_fd */
        1024, /* max_connections */
        1, /* num_threads */
        NULL, /* thread_ids */
        {}, /* state */
        { {}, "port", port_configurator_desc, NULL, on_config_port, on_config_port_complete, NULL },
        { {}, "max-connections", max_connections_configurator_desc, NULL, on_config_max_connections, NULL, NULL },
        { {}, "num-threads", num_threads_configurator_desc, NULL, on_config_num_threads, NULL, NULL }
    };

    const char *config_file = "h2o.conf";
    int opt_ch;
    yoml_t *config_yoml;
    h2o_config_init(&config.global_config);
    config.global_config.close_cb = on_close;
    h2o_linklist_insert(&config.global_config.global_configurators, &config.port_configurator._link);
    h2o_linklist_insert(&config.global_config.global_configurators, &config.max_connections_configurator._link);
    h2o_linklist_insert(&config.global_config.global_configurators, &config.num_threads_configurator._link);

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
