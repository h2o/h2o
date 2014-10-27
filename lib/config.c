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
#include <stdarg.h>
#include <stdio.h>
#include "h2o.h"

static void destroy_configurator(h2o_configurator_t *configurator)
{
    if (configurator->dispose != NULL)
        configurator->dispose(configurator);
    free(configurator->commands.entries);
    free(configurator);
}

static int setup_configurators(void *config, h2o_linklist_t *list, int flags_mask, int is_enter)
{
    h2o_linklist_t *node;

    for (node = list->next; node != list; node = node->next) {
        h2o_configurator_t *c = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if ((c->flags & flags_mask) != 0) {
            if (is_enter) {
                if (c->enter != NULL && c->enter(c, config) != 0)
                    return -1;
            } else {
                if (c->exit != NULL && c->exit(c, config) != 0)
                    return -1;
            }
        }
    }

    return 0;
}

static int apply_commands(void *config, const char *file, yoml_t *node, h2o_globalconf_t *global_config)
{
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(NULL, file, node, "node must be a MAPPING");
        return -1;
    }

    /* call on_enter of every configurator */
    setup_configurators(
        config,
        &global_config->configurators,
        (config == global_config ? H2O_CONFIGURATOR_FLAG_GLOBAL: 0)
            | H2O_CONFIGURATOR_FLAG_HOST,
        1);

    /* handle the configuration commands */
    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key,
            *value = node->data.mapping.elements[i].value;
        h2o_configurator_command_t *cmd;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(NULL, file, key, "command must be a string");
            return -1;
        }
        if ((cmd = h2o_config_get_configurator(global_config, key->data.scalar)) == NULL) {
            h2o_config_print_error(NULL, file, key, "unknown command: %s", key->data.scalar);
            return -1;
        }
        if ((cmd->configurator->flags & (config == global_config ? H2O_CONFIGURATOR_FLAG_GLOBAL : H2O_CONFIGURATOR_FLAG_HOST)) == 0) {
            h2o_config_print_error(cmd, file, key, "the command cannot be used at this level");
            return -1;
        }
        if (cmd->cb(cmd, config, file, value) != 0)
            return -1;
    }

    /* call on_enter of every configurator */
    setup_configurators(
        config,
        &global_config->configurators,
        (config == global_config ? H2O_CONFIGURATOR_FLAG_GLOBAL: 0)
            | H2O_CONFIGURATOR_FLAG_HOST,
        0);

    return 0;
}

static int on_config_files(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_hostconf_t *host_config = _config;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(cmd, file, node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, key, "key (representing the virtual path) must be a string");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, key, "value (representing the local path) must be a string");
            return -1;
        }
        h2o_file_register(host_config, key->data.scalar, value->data.scalar, "index.html" /* FIXME */);
    }

    return 0;
}

static int on_config_mime_types(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_hostconf_t *host_config = _config;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(cmd, file, node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, key, "key (representing the extension) must be a string");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, node, "value (representing the mime-type) must be a string");
            return -1;
        }
        h2o_define_mimetype(&host_config->mimemap, key->data.scalar, value->data.scalar);
    }

    return 0;
}

static int on_config_hosts(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_globalconf_t *config = _config;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(cmd, file, node, "argument must be a mapping");
        return -1;
    }

    if (node->data.mapping.size == 0) {
        h2o_config_print_error(cmd, file, node, "the mapping cannot be empty");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        h2o_hostconf_t *host_config;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(cmd, file, key, "key (representing the hostname) must be a string");
            return -1;
        }
        host_config = h2o_config_register_host(config, key->data.scalar);
        if (apply_commands(host_config, file, value, config) != 0)
            return -1;
    }

    return 0;
}

static int on_config_request_timeout(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_globalconf_t *config = _config;
    unsigned timeout_in_secs;

    if (h2o_config_scanf(cmd, file, node, "%u", &timeout_in_secs) != 0)
        return -1;

    config->req_timeout = timeout_in_secs * 1000;
    return 0;
}

static int on_config_limit_request_body(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_globalconf_t *config = _config;
    return h2o_config_scanf(cmd, file, node, "%zu", &config->max_request_entity_size);
}

static int on_config_http1_upgrade_to_http2(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_globalconf_t *config = _config;
    ssize_t ret = h2o_config_get_one_of(cmd, file, node, "OFF,ON");
    if (ret == -1)
        return -1;
    config->http1_upgrade_to_http2 = (int)ret;
    return 0;
}

static int on_config_http2_max_concurrent_requests_per_connection(h2o_configurator_command_t *cmd, void *_config, const char *file, yoml_t *node)
{
    h2o_globalconf_t *config = _config;
    return h2o_config_scanf(cmd, file, node, "%zu", &config->http2_max_concurrent_requests_per_connection);
}

static void init_core_configurators(h2o_globalconf_t *conf)
{
    /* check if already initialized */
    if (h2o_config_get_configurator(conf, "files") != NULL)
        return;

    { /* setup host configurators */
        h2o_configurator_t *c = h2o_config_create_configurator(conf, sizeof(*c), H2O_CONFIGURATOR_FLAG_HOST);
        h2o_config_define_command(
            c, "files", on_config_files,
            "map of URL-path -> local directory");
        h2o_config_define_command(
            c, "mime-types", on_config_mime_types, NULL, NULL,
            "map of extension -> mime-type");
    };

    { /* setup global configurators */
        h2o_configurator_t *c = h2o_config_create_configurator(conf, sizeof(*c), H2O_CONFIGURATOR_FLAG_GLOBAL);
        h2o_config_define_command(
            c, "hosts", on_config_hosts,
            "map of hostname -> map of per-host configs");
        h2o_config_define_command(
            c, "request-timeout", on_config_request_timeout,
            "timeout for incoming requests in seconds (default: " H2O_TO_STR(H2O_DEFAULT_REQ_TIMEOUT) ")");
        h2o_config_define_command(
            c, "limit-request-body", on_config_limit_request_body,
            "maximum size of request body in bytes (e.g. content of POST)",
            "(default: unlimited)");
        h2o_config_define_command(
            c, "http1-upgrade-to-http2", on_config_http1_upgrade_to_http2,
            "boolean flag (ON/OFF) indicating whether or not to allow upgrade to HTTP/2",
            "(default: ON)");
        h2o_config_define_command(
            c, "http2-max-concurrent-requests-per-connection", on_config_http2_max_concurrent_requests_per_connection,
            "max. number of requests to be handled concurrently within a single HTTP/2",
            "stream (default: 16)");
    }
}

static void init_host_config(h2o_hostconf_t *hostconf, h2o_globalconf_t *globalconf)
{
    memset(hostconf, 0, sizeof(*hostconf));
    hostconf->global = globalconf;
    h2o_linklist_init_anchor(&hostconf->handlers);
    h2o_linklist_init_anchor(&hostconf->filters);
    h2o_linklist_init_anchor(&hostconf->loggers);
    h2o_chunked_register(hostconf);
    h2o_init_mimemap(&hostconf->mimemap, H2O_DEFAULT_MIMETYPE);
}

static void dispose_host_config(h2o_hostconf_t *host_config)
{
    free(host_config->hostname.base);

#define DESTROY_LIST(type, anchor) do { \
    while (! h2o_linklist_is_empty(&anchor)) { \
        type *e = H2O_STRUCT_FROM_MEMBER(type, _link, anchor.next); \
        h2o_linklist_unlink(&e->_link); \
        if (e->dispose != NULL) \
            e->dispose(e); \
        free(e); \
    } \
} while (0)

    DESTROY_LIST(h2o_handler_t, host_config->handlers);
    DESTROY_LIST(h2o_filter_t, host_config->filters);
    DESTROY_LIST(h2o_logger_t, host_config->loggers);

#undef DESTROY_LIST

    h2o_dispose_mimemap(&host_config->mimemap);
}

void h2o_config_init(h2o_globalconf_t *config)
{
    memset(config, 0, sizeof(*config));
    h2o_linklist_init_anchor(&config->configurators);
    config->server_name = h2o_buf_init(H2O_STRLIT("h2o/0.1"));
    config->req_timeout = H2O_DEFAULT_REQ_TIMEOUT;
    config->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    config->http1_upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    config->http2_max_concurrent_requests_per_connection = H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION;

    init_core_configurators(config);
}

h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *config, const char *hostname)
{
    h2o_hostconf_t *hostconf;
    size_t i;

    h2o_vector_reserve(NULL, (void*)&config->hosts, sizeof(config->hosts.entries[0]), config->hosts.size + 1);
    hostconf = config->hosts.entries + config->hosts.size++;

    init_host_config(hostconf, config);
    hostconf->hostname = h2o_strdup(NULL, hostname, SIZE_MAX);
    for (i = 0; i != hostconf->hostname.len; ++i)
        hostconf->hostname.base[i] = h2o_tolower(hostconf->hostname.base[i]);

    return hostconf;
}

void h2o_config_dispose(h2o_globalconf_t *config)
{
    size_t i;

    for (i = 0; i != config->hosts.size; ++i) {
        h2o_hostconf_t *hostconf = config->hosts.entries + i;
        dispose_host_config(hostconf);
    }
    free(config->hosts.entries);

    while (! h2o_linklist_is_empty(&config->configurators)) {
        h2o_configurator_t *c = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, config->configurators.next);
        h2o_linklist_unlink(&c->_link);
        if (c->dispose != NULL)
            c->dispose(c);
        destroy_configurator(c);
    }
}

h2o_configurator_t *h2o_config_create_configurator(h2o_globalconf_t *conf, size_t sz, int flags)
{
    h2o_configurator_t *c;

    assert(sz >= sizeof(*c));
    assert("configurator should be either global or per-host (not both)"
        && (flags & (H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST)) != (H2O_CONFIGURATOR_FLAG_GLOBAL | H2O_CONFIGURATOR_FLAG_HOST));

    c = h2o_malloc(sz);
    memset(c, 0, sz);
    c->flags = flags;
    h2o_linklist_insert(&conf->configurators, &c->_link);

    return c;
}

void h2o_config__define_command(h2o_configurator_t *configurator, const char *name, h2o_configurator_command_cb cb, const char **desc)
{
    h2o_configurator_command_t *cmd;

    h2o_vector_reserve(NULL, (void*)&configurator->commands, sizeof(configurator->commands.entries[0]), configurator->commands.size + 1);
    cmd = configurator->commands.entries + configurator->commands.size++;
    cmd->configurator = configurator;
    cmd->name = name;
    cmd->cb = cb;
    cmd->description = desc;
}

h2o_configurator_command_t *h2o_config_get_configurator(h2o_globalconf_t *conf, const char *name)
{
    h2o_linklist_t *node;
    size_t i;

    for (node = conf->configurators.next; node != &conf->configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        for (i = 0; i != configurator->commands.size; ++i) {
            h2o_configurator_command_t *cmd = configurator->commands.entries + i;
            if (strcmp(cmd->name, name) == 0) {
                return cmd;
            }
        }
    }

    return NULL;
}

int h2o_config_configure(h2o_globalconf_t *config, const char *file, yoml_t *node)
{
    if (apply_commands(config, file, node, config) != 0)
        return -1;
    if (config->hosts.size == 0) {
        h2o_config_print_error(NULL, file, node, "mandatory configuration directive `hosts` is missing");
        return -1;
    }
    return 0;
}

void h2o_config_print_error(h2o_configurator_command_t *cmd, const char *file, yoml_t *node, const char *reason, ...)
{
    va_list args;

    fprintf(stderr, "[%s:%zu] ", file, node->line + 1);
    if (cmd != NULL)
        fprintf(stderr, "in command %s, ", cmd->name);
    va_start(args, reason);
    vfprintf(stderr, reason, args);
    va_end(args);
    fputc('\n', stderr);
}

int h2o_config_scanf(h2o_configurator_command_t *cmd, const char *file, yoml_t *node, const char *fmt, ...)
{
    va_list args;
    int sscan_ret;

    if (node->type != YOML_TYPE_SCALAR)
        goto Error;
    va_start(args, fmt);
    sscan_ret = vsscanf(node->data.scalar, fmt, args);
    va_end(args);
    if (sscan_ret != 1)
        goto Error;

    return 0;
Error:
    h2o_config_print_error(cmd, file, node, "argument must match the format: %s", fmt);
    return -1;
}

ssize_t h2o_config_get_one_of(h2o_configurator_command_t *cmd, const char *file, yoml_t *node, const char *candidates)
{
    const char *config_str, *cand_str;
    ssize_t config_str_len, cand_index;

    if (node->type != YOML_TYPE_SCALAR)
        goto Error;

    config_str = node->data.scalar;
    config_str_len = strlen(config_str);

    cand_str = candidates;
    for (cand_index = 0; ; ++cand_index) {
        if (strncasecmp(cand_str, config_str, config_str_len) == 0
            && (cand_str[config_str_len] == '\0' || cand_str[config_str_len] == ',')) {
            /* found */
            return cand_index;
        }
        cand_str = strchr(cand_str, ',');
        if (cand_str == NULL)
            goto Error;
        cand_str += 1; /* skip ',' */
    }
    /* not reached */

Error:
    h2o_config_print_error(cmd, file, node, "argument must be one of: %s", candidates);
    return -1;
}

h2o_handler_t *h2o_create_handler(h2o_hostconf_t *conf, size_t sz)
{
    h2o_handler_t *handler = h2o_malloc(sz);

    memset(handler, 0, sz);
    handler->_config_slot = conf->global->_num_config_slots++;
    h2o_linklist_insert(&conf->handlers, &handler->_link);

    return handler;
}

h2o_filter_t *h2o_create_filter(h2o_hostconf_t *conf, size_t sz)
{
    h2o_filter_t *filter = h2o_malloc(sz);

    memset(filter, 0, sz);
    filter->_config_slot = conf->global->_num_config_slots++;
    h2o_linklist_insert(&conf->filters, &filter->_link);

    return filter;
}

h2o_logger_t *h2o_create_logger(h2o_hostconf_t *conf, size_t sz)
{
    h2o_logger_t *logger = h2o_malloc(sz);

    memset(logger, 0, sz);
    logger->_config_slot = conf->global->_num_config_slots++;
    h2o_linklist_insert(&conf->loggers, &logger->_link);

    return logger;
}
