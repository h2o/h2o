/*
 * Copyright (c) 2026 Fastly, Kazuho Oku
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
#include "h2o.h"
#include "h2o/configurator.h"

static int on_config_webtransport_moq(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    yoml_t **url_node, **qmux_cleartext_node;
    h2o_iovec_t host;
    uint16_t port;
    int qmux_cleartext = 0;

    if (h2o_configurator_parse_mapping(cmd, node, "url:s", "qmux-cleartext:s", &url_node, &qmux_cleartext_node) != 0)
        return -1;

    /* the URL of the relay, in the form of `moqt://host:port` */
    const char *url = (*url_node)->data.scalar;
    if (strncmp(url, "moqt://", 7) != 0 || h2o_url_parse_hostport(url + 7, strlen(url + 7), &host, &port) == NULL ||
        port == 65535) {
        h2o_configurator_errprintf(cmd, *url_node, "url must be in the form of `moqt://host:port`");
        return -1;
    }

    /* for testing; connects to the relay using QMux over cleartext TCP */
    if (qmux_cleartext_node != NULL && (qmux_cleartext = h2o_configurator_get_one_of(cmd, *qmux_cleartext_node, "OFF,ON")) == -1)
        return -1;

    h2o_webtransport_moq_register(ctx->pathconf, host, port, qmux_cleartext);
    return 0;
}

void h2o_webtransport_moq_register_configurator(h2o_globalconf_t *conf)
{
    struct st_h2o_configurator_t *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    h2o_configurator_define_command(
        c, "webtransport.moq", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING,
        on_config_webtransport_moq);
}
