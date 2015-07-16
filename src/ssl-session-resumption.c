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
#include <inttypes.h>
#include "yoml-parser.h"
#include "h2o.h"
#include "h2o/configurator.h"
#include "standalone.h"

static struct {
    void (*setup)(SSL_CTX **contexts, size_t num_contexts);
    struct {
        char *host;
        uint16_t port;
        size_t num_threads;
        char *prefix;
        unsigned timeout;
    } memcached;
} conf;

static void setup_disable(SSL_CTX **contexts, size_t num_contexts)
{
    size_t i;
    for (i = 0; i != num_contexts; ++i)
        SSL_CTX_set_session_cache_mode(contexts[i], SSL_SESS_CACHE_OFF);
}

static void setup_memcached(SSL_CTX **contexts, size_t num_contexts)
{
    h2o_memcached_context_t *memc_ctx =
        h2o_memcached_create_context(conf.memcached.host, conf.memcached.port, conf.memcached.num_threads, conf.memcached.prefix);
    h2o_accept_setup_async_ssl_resumption(memc_ctx, conf.memcached.timeout);
    size_t i;
    for (i = 0; i != num_contexts; ++i)
        h2o_socket_ssl_async_resumption_setup_ctx(contexts[i]);
}

int ssl_session_resumption_on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    yoml_t *mode;

    if ((mode = yoml_get(node, "mode")) == NULL) {
        h2o_configurator_errprintf(cmd, mode, "mandatory attribute `mode` is missing");
        return -1;
    }

    if (mode->type == YOML_TYPE_SCALAR) {

        if (strcmp(mode->data.scalar, "off") == 0) {

            conf.setup = setup_disable;
            return 0;

        } else if (strcmp(mode->data.scalar, "internal") == 0) {

            conf.setup = NULL;
            return 0;

        } else if (strcmp(mode->data.scalar, "memcached") == 0) {

            const char *host = NULL, *prefix = ":h2o:ssl-resumption:";
            uint16_t port = 11211;
            size_t num_threads = 1;
            unsigned timeout = 3600;
            size_t index;
            for (index = 0; index != node->data.mapping.size; ++index) {
                yoml_t *key = node->data.mapping.elements[index].key;
                yoml_t *value = node->data.mapping.elements[index].value;
                if (value == mode)
                    continue;
                if (key->type != YOML_TYPE_SCALAR) {
                    h2o_configurator_errprintf(cmd, key, "attribute must be a string");
                    return -1;
                }
                if (strcmp(key->data.scalar, "host") == 0) {
                    if (value->type != YOML_TYPE_SCALAR) {
                        h2o_configurator_errprintf(cmd, value, "`host` must be a string");
                        return -1;
                    }
                    host = value->data.scalar;
                } else if (strcmp(key->data.scalar, "port") == 0) {
                    if (!(value->type == YOML_TYPE_SCALAR && sscanf(value->data.scalar, "%" SCNu16, &port) == 1)) {
                        h2o_configurator_errprintf(cmd, value, "`port` must be a number");
                        return -1;
                    }
                } else if (strcmp(key->data.scalar, "num-threads") == 0) {
                    if (!(value->type == YOML_TYPE_SCALAR && sscanf(value->data.scalar, "%zu", &num_threads) == 1 &&
                          num_threads != 0)) {
                        h2o_configurator_errprintf(cmd, value, "`num-threads` must be a positive number");
                        return -1;
                    }
                } else if (strcmp(key->data.scalar, "prefix") == 0) {
                    if (value->type != YOML_TYPE_SCALAR) {
                        h2o_configurator_errprintf(cmd, value, "`prefix` must be a string");
                        return -1;
                    }
                    prefix = value->data.scalar;
                } else if (strcmp(key->data.scalar, "timeout") == 0) {
                    if (!(value->type == YOML_TYPE_SCALAR && sscanf(value->data.scalar, "%u", &timeout) == 1 && timeout != 0)) {
                        h2o_configurator_errprintf(cmd, value, "`timeout` must be a positive number (in seconds)");
                        return -1;
                    }
                } else {
                    h2o_configurator_errprintf(cmd, key, "unknown attribute: %s", key->data.scalar);
                    return -1;
                }
            }
            if (host == NULL) {
                h2o_configurator_errprintf(cmd, node, "mandatory attribute `host` is missing");
                return -1;
            }
            conf.setup = setup_memcached;
            conf.memcached.host = h2o_strdup(NULL, host, SIZE_MAX).base;
            conf.memcached.port = port;
            conf.memcached.num_threads = num_threads;
            conf.memcached.prefix = h2o_strdup(NULL, prefix, SIZE_MAX).base;
            conf.memcached.timeout = timeout;
            return 0;
        }
    }

    h2o_configurator_errprintf(cmd, mode, "`mode` must be one of: `off`, `internal`, `memached`");
    return -1;
}

void ssl_session_resumption_setup(SSL_CTX **contexts, size_t num_contexts)
{
    if (conf.setup != NULL)
        conf.setup(contexts, num_contexts);
}
