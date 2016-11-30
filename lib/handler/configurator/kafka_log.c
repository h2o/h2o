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
#include <stdlib.h>
#include "h2o.h"
#include "h2o/configurator.h"
#include "librdkafka/rdkafka.h"

typedef H2O_VECTOR(h2o_kafka_log_handle_t *) st_h2o_kafka_log_handle_vector_t;

struct st_h2o_kafka_log_configurator_t {
    h2o_configurator_t super;
    st_h2o_kafka_log_handle_vector_t *handles;
    st_h2o_kafka_log_handle_vector_t _handles_stack[H2O_CONFIGURATOR_NUM_LEVELS + 1];
};

void kafka_conf_set(rd_kafka_conf_t *rk_conf, const char* key, const char* value)
{
    char errbuf[512];

    int res = rd_kafka_conf_set(rk_conf, key, value, &(errbuf[0]), sizeof(errbuf));
    if (res != RD_KAFKA_CONF_OK)
    {
        fprintf(stderr, "Abort: %s\n", &(errbuf[0]));
        abort();
    }
}

void kafka_topic_conf_set(rd_kafka_topic_conf_t *rk_conf, const char* key, const char* value)
{
    char errbuf[512];

    int res = rd_kafka_topic_conf_set(rk_conf, key, value, &(errbuf[0]), sizeof(errbuf));
    if (res != RD_KAFKA_CONF_OK)
    {
        fprintf(stderr, "Abort: %s\n", &(errbuf[0]));
        abort();
    }
}

static int on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_kafka_log_configurator_t *self = (void *)cmd->configurator;
    h2o_kafka_log_handle_t *kh;
    char* topic = "h2o";
    rd_kafka_conf_t* rk_conf = NULL;
    rd_kafka_topic_conf_t* rkt_conf = NULL;
    int32_t partition = RD_KAFKA_PARTITION_UA;
    const char *fmt = NULL;

    switch (node->type) {
    // case YOML_TYPE_SCALAR:
    //     break;
    case YOML_TYPE_MAPPING: {
        rk_conf = rd_kafka_conf_new();
        rkt_conf = rd_kafka_topic_conf_new();
        // kafka_conf_set(rk_conf, "metadata.broker.list", "localhost");
        // kafka_conf_set(rk_conf, "group.id", "rdkafkad");
        for (size_t i = 0; i != node->data.mapping.size; ++i) {
            yoml_t *key = node->data.mapping.elements[i].key;
            if (
                    key->type == YOML_TYPE_SCALAR &&
                    strcmp(key->data.scalar, "topic")
                )
            {
                kafka_conf_set(rk_conf, key->data.scalar, node->data.mapping.elements[i].value->data.scalar);
            }
        }

        yoml_t *t;
        /* topic */
        if ((t = yoml_get(node, "topic")) != NULL) {
            switch (t->type)
            {
                case YOML_TYPE_MAPPING:
                    for (size_t i = 0; i != t->data.mapping.size; ++i)
                    {
                        yoml_t *key = t->data.mapping.elements[i].key;
                        if (
                                key->type == YOML_TYPE_SCALAR && 
                                strcmp(key->data.scalar, "name") &&
                                strcmp(key->data.scalar, "partition") &&
                                strcmp(key->data.scalar, "message")
                            )
                        {
                            kafka_topic_conf_set(rkt_conf, key->data.scalar, t->data.mapping.elements[i].value->data.scalar);
                        }
                    }
                    yoml_t *y;
                    /* get name */
                    if ((y = yoml_get(t, "name")) != NULL) {
                        if (y->type != YOML_TYPE_SCALAR) {
                            h2o_configurator_errprintf(cmd, y, "`name` must be scalar");
                            return -1;
                        }
                        topic = y->data.scalar;
                    }
                    /* get partition */
                    if ((y = yoml_get(t, "partition")) != NULL) {
                        if (y->type != YOML_TYPE_SCALAR) {
                            h2o_configurator_errprintf(cmd, y, "`partition` must be scalar");
                            return -1;
                        }
                        partition = atoi(y->data.scalar);
                    }
                    /* get message */
                    if ((y = yoml_get(node, "message")) != NULL) {
                        if (y->type != YOML_TYPE_SCALAR) {
                            h2o_configurator_errprintf(cmd, y, "`message` must be a scalar");
                            return -1;
                        }
                        fmt = y->data.scalar;
                    }
                    break;
                case YOML_TYPE_SCALAR:
                    topic = t->data.scalar;
                    break;
                default:
                    h2o_configurator_errprintf(cmd, t, "`topic` must be scalar");
                    return -1;
            }
        }
    } break;
    default:
        h2o_configurator_errprintf(cmd, node, "node must be a scalar or a mapping");
        return -1;
    }

    if (!ctx->dry_run) {
        if ((kh = h2o_kafka_log_open_handle(rk_conf, rkt_conf, topic, partition, fmt)) == NULL)
            return -1;
        h2o_vector_reserve(NULL, self->handles, self->handles->size + 1);
        self->handles->entries[self->handles->size++] = kh;
    }

    return 0;
}

static int on_config_enter(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_kafka_log_configurator_t *self = (void *)_self;
    size_t i;

    /* push the stack pointer */
    ++self->handles;

    /* link the handles */
    memset(self->handles, 0, sizeof(*self->handles));
    h2o_vector_reserve(NULL, self->handles, self->handles[-1].size + 1);
    for (i = 0; i != self->handles[-1].size; ++i) {
        h2o_kafka_log_handle_t *kh = self->handles[-1].entries[i];
        self->handles[0].entries[self->handles[0].size++] = kh;
        h2o_mem_addref_shared(kh);
    }

    return 0;
}

static int on_config_exit(h2o_configurator_t *_self, h2o_configurator_context_t *ctx, yoml_t *node)
{
    struct st_h2o_kafka_log_configurator_t *self = (void *)_self;
    size_t i;

    /* register all handles, and decref them */
    for (i = 0; i != self->handles->size; ++i) {
        h2o_kafka_log_handle_t *kh = self->handles->entries[i];
        if (ctx->pathconf != NULL)
            h2o_kafka_log_register(ctx->pathconf, kh);
        h2o_mem_release_shared(kh);
    }
    /* free the vector */
    free(self->handles->entries);

    /* pop the stack pointer */
    --self->handles;

    return 0;
}

void h2o_kafka_log_register_configurator(h2o_globalconf_t *conf)
{
    struct st_h2o_kafka_log_configurator_t *self = (void *)h2o_configurator_create(conf, sizeof(*self));

    self->super.enter = on_config_enter;
    self->super.exit = on_config_exit;
    self->handles = self->_handles_stack;

    h2o_configurator_define_command(&self->super, "kafka-log", H2O_CONFIGURATOR_FLAG_ALL_LEVELS, on_config);
}
