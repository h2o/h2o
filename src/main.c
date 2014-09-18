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
#include <stdio.h>
#include <sys/socket.h>
#include "yoml-parser.h"
#include "h2o.h"

/* taken from sysexits.h */
#ifndef EX_CONFIG
# define EX_CONFIG 78
#endif

struct port_configurator_t {
    h2o_configurator_t super;
    unsigned short port;
};

static int on_config_port(h2o_configurator_t *_conf, h2o_context_t *ctx, const char *config_file, yoml_t *config_node)
{
    struct port_configurator_t *conf = (void*)_conf;

    if (config_node->type != YOML_TYPE_SCALAR
        || sscanf(config_node->data.scalar, "%hu", &conf->port) != 1) {
        h2o_context_print_config_error(&conf->super, config_file, config_node, "argument is not a valid port number");
        return -1;
    }

    return 0;
}

static void on_config_port_accept(h2o_socket_t *listener, int status)
{
    h2o_context_t *ctx = listener->data;
    h2o_socket_t *sock;

    if (status == -1) {
        return;
    }

    if ((sock = h2o_evloop_socket_accept(listener)) == NULL) {
        return;
    }
    h2o_accept(ctx, sock);
}

static int on_config_port_complete(h2o_configurator_t *_conf, h2o_context_t *ctx)
{
    struct port_configurator_t *conf = (void*)_conf;
    struct sockaddr_in addr;
    int fd, reuseaddr_flag = 1;
    h2o_socket_t *sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0);
    addr.sin_port = htons(conf->port);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1
        || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0
        || bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0
        || listen(fd, SOMAXCONN) != 0) {
        fprintf(stderr, "failed to listen to port %hu:%s\n", conf->port, strerror(errno));
        return -1;
    }

    sock = h2o_evloop_socket_create(ctx->loop, fd, H2O_SOCKET_FLAG_IS_ACCEPT);
    sock->data = ctx;
    h2o_socket_read_start(sock, on_config_port_accept);

    return 0;
}

static void usage(void)
{
    printf(
        "Command:\n"
        "  h2o [options]\n"
        "\n"
        "Options:\n"
        "  --conf=file  configuration file (default: h2o.conf)\n"
        "  --help       print this help\n"
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

int main(int argc, char **argv)
{
    static struct option longopts[] = {
        { "conf", required_argument, NULL, 'c' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    static struct port_configurator_t port_configurator = {
        { {}, "port", NULL, on_config_port, on_config_port_complete },
        0
    };


    const char *conf_fn = "h2o.conf";
    int opt_ch;
    yoml_t *config;
    h2o_context_t ctx;

    /* parse options */
    while ((opt_ch = getopt_long(argc, argv, "c:h", longopts, NULL)) != -1) {
        switch (opt_ch) {
        case 'c':
            conf_fn = optarg;
            break;
        case 'h':
            usage();
            exit(0);
            break;
        default:
            assert(0);
            break;
        }
    }
    argc -= optind;
    argv += optind;

    /* load configuration */
    if ((config = load_config(conf_fn)) == NULL)
        exit(EX_CONFIG);

    /* setup h2o context */
    h2o_context_init(&ctx, h2o_evloop_create());
    h2o_context_init_global_configurators(&ctx);
    h2o_linklist_insert(&ctx.configurators, &port_configurator.super._link);

    /* apply the configuration */
    if (h2o_context_configure(&ctx, conf_fn, config) != 0)
        exit(EX_CONFIG);

    while (h2o_evloop_run(ctx.loop) == 0)
        ;

    return 0;
}
