/*
 * Copyright (c) 2022 Fastly, Inc., Goro Fuji, Kazuho Oku
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
#include "yoml-parser.h"

struct st_h2olog_configurator {
    h2o_configurator_t super;
};

static int on_config_h2olog(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    if (node->type == YOML_TYPE_SCALAR) {
        switch (h2o_configurator_get_one_of(cmd, node, "OFF,ON")) {
        case 0: /* OFF */
            return 0;
        case 1: /* ON */
            break;
        default:
            return -1;
        }
    } else {
        assert(node->type == YOML_TYPE_MAPPING);
        yoml_t **appdata_node;
        if (h2o_configurator_parse_mapping(cmd, node, NULL, "appdata:s", &appdata_node) != 0)
            return -1;

        if (appdata_node != NULL) {
            ssize_t v;
            if ((v = h2o_configurator_get_one_of(cmd, *appdata_node, "OFF,ON")) == -1)
                return -1;
            ptls_log.include_appdata = (unsigned)v;
        }
    }

    h2o_log_register(ctx->hostconf);
    return 0;
}

void h2o_log_register_configurator(h2o_globalconf_t *conf)
{
    struct st_h2olog_configurator *c = (void *)h2o_configurator_create(conf, sizeof(*c));

    // it takes either a scalar ("OFF,ON") or a mapping for customized configuration
    h2o_configurator_define_command(
        &c->super, "h2olog",
        H2O_CONFIGURATOR_FLAG_HOST | H2O_CONFIGURATOR_FLAG_EXPECT_SCALAR | H2O_CONFIGURATOR_FLAG_EXPECT_MAPPING, on_config_h2olog);
}
