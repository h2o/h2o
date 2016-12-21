/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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

static int on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    yoml_t *url;
    int status = 302; /* default is temporary redirect */
    int internal = 0; /* default is external redirect */

    switch (node->type) {
    case YOML_TYPE_SCALAR:
        url = node;
        break;
    case YOML_TYPE_MAPPING: {
        yoml_t *status_node, *internal_node;
        if (h2o_configurator_parse_attributes(cmd, node, {"url", &url}, {"status", &status_node}, {"internal", &internal_node}) !=
            0)
            return -1;
        if (url == NULL) {
            h2o_configurator_errprintf(cmd, node, "mandatory property `url` is missing");
            return -1;
        }
        if (url->type != YOML_TYPE_SCALAR) {
            h2o_configurator_errprintf(cmd, url, "property `url` must be a string");
            return -1;
        }
        if (status_node == NULL) {
            h2o_configurator_errprintf(cmd, node, "mandatory property `status` is missing");
            return -1;
        }
        if (h2o_configurator_scanf(cmd, status_node, "%d", &status) != 0)
            return -1;
        if (!(300 <= status && status <= 399)) {
            h2o_configurator_errprintf(cmd, status_node, "value of property `status` should be within 300 to 399");
            return -1;
        }
        if (internal_node != NULL) {
            if ((internal = (int)h2o_configurator_get_one_of(cmd, internal_node, "NO,YES")) == -1)
                return -1;
        }
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "value must be a string or a mapping");
        return -1;
    }

    h2o_redirect_register(ctx->pathconf, internal, status, url->data.scalar);

    return 0;
}

void h2o_redirect_register_configurator(h2o_globalconf_t *conf)
{
    h2o_configurator_t *c = h2o_configurator_create(conf, sizeof(*c));

    h2o_configurator_define_command(c, "redirect", H2O_CONFIGURATOR_FLAG_PATH | H2O_CONFIGURATOR_FLAG_DEFERRED, on_config);
}
