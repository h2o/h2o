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
#include "h2o.h"
#include "h2o/configurator.h"

static int on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, const char *file, yoml_t *node)
{
    const char *path, *fmt = NULL;

    switch (node->type) {
    case  YOML_TYPE_SCALAR:
        path = node->data.scalar;
        break;
    case YOML_TYPE_MAPPING:
        {
            yoml_t *t;
            /* get path */
            if ((t = yoml_get(node, "path")) == NULL) {
                h2o_configurator_errprintf(cmd, file, node, "could not find mandatory key `path`");
                return -1;
            }
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, file, t, "`path` must be scalar");
                return -1;
            }
            path = t->data.scalar;
            /* get format */
            if ((t = yoml_get(node, "format")) != NULL) {
                if (t->type != YOML_TYPE_SCALAR) {
                    h2o_configurator_errprintf(cmd, file, t, "`format` must be a scalar");
                    return -1;
                }
                fmt = t->data.scalar;
            }
        }
        break;
    default:
        h2o_configurator_errprintf(cmd, file, node, "node must be a scalar or a mapping");
        return -1;
    }

    h2o_access_log_register(ctx->pathconf, path, fmt);
    return 0;
}

void h2o_access_log_register_configurator(h2o_globalconf_t *conf)
{
    h2o_configurator_t *c = h2o_configurator_create(conf, sizeof(*c));
    h2o_configurator_define_command(c, "access-log", H2O_CONFIGURATOR_FLAG_PATH,
        on_config,
        "path (and optionally the format) of the access log (default: none)",
        " - if the value is a scalar, it is treated as the path of the log file",
        " - if the value is a mapping, its `path` property is treated as the path",
        "   and `format` property is treated as the format",
        " - if the path starts with `|`, the rest of the path is considered as a ",
        "   command pipe to which the logs should be emitted"
    );
}
