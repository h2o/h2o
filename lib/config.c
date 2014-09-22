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

static int complete_configurators(h2o_linklist_t *configurators, void *config)
{
    h2o_linklist_t *node;
    for (node = configurators->next; node != configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if (configurator->on_complete != NULL)
            if (configurator->on_complete(configurator, config) != 0)
                return -1;
    }
    return 0;
}

static int complete_host_configurators(h2o_host_configuration_t *host_config, void *_host_configurators)
{
    h2o_linklist_t *host_configurators = _host_configurators;
    return complete_configurators(host_configurators, host_config);
}

static int for_each_host_context(h2o_global_configuration_t *config, int (*cb)(h2o_host_configuration_t *host_config, void *cb_arg), void *cb_arg)
{
    h2o_linklist_t *node;
    int ret;

    if ((ret = cb(&config->default_host, cb_arg)) != 0)
        return ret;
    for (node = config->virtual_hosts.next; node != &config->virtual_hosts; node = node->next) {
        h2o_host_configuration_t *host_config = H2O_STRUCT_FROM_MEMBER(h2o_host_configuration_t, _link, node);
        if ((ret = cb(host_config, cb_arg)) != 0)
            return ret;
    }

    return 0;
}

static int apply_commands(void *config, const char *file, yoml_t *node, h2o_global_configuration_t *global_config)
{
    yoml_t *key, *value;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(NULL, file, node, "node must be a MAPPING");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        h2o_configurator_t *configurator;
        key = node->data.mapping.elements[i].key;
        value = node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(NULL, file, key, "command must be a string");
            return -1;
        }
        if (config == global_config) {
            if ((configurator = h2o_config_get_configurator(&global_config->global_configurators, key->data.scalar)) != NULL) {
                if (configurator->on_cmd(configurator, config, file, value) != 0)
                    return -1;
            } else if ((configurator = h2o_config_get_configurator(&global_config->host_configurators, key->data.scalar)) != NULL) {
                if (configurator->on_cmd(configurator, &global_config->default_host, file, value) != 0)
                    return -1;
            } else {
                goto UnknownCommand;
            }
        } else {
            if ((configurator = h2o_config_get_configurator(&global_config->host_configurators, key->data.scalar)) == NULL)
                goto UnknownCommand;
            if (configurator->on_cmd(configurator, config, file, value) != 0)
                return -1;
        }
    }

    return 0;

UnknownCommand:
    h2o_config_print_error(NULL, file, key, "unknown command: %s", key->data.scalar);
    return -1;
}

static int on_config_files(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_host_configuration_t *host_config = _config;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(configurator, file, node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(configurator, file, key, "key (representing the virtual path) must be a string");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(configurator, file, key, "value (representing the local path) must be a string");
            return -1;
        }
        h2o_register_file_handler(host_config, key->data.scalar, value->data.scalar, "index.html" /* FIXME */);
    }

    return 0;
}

static int on_config_mime_types(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_host_configuration_t *host_config = _config;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(configurator, file, node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(configurator, file, key, "key (representing the extension) must be a string");
            return -1;
        }
        if (value->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(configurator, file, node, "value (representing the mime-type) must be a string");
            return -1;
        }
        h2o_define_mimetype(&host_config->mimemap, key->data.scalar, value->data.scalar);
    }

    return 0;
}

static int on_config_virtual_host(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_global_configuration_t *config = _config;
    size_t i;

    if (node->type != YOML_TYPE_MAPPING) {
        h2o_config_print_error(configurator, file, node, "argument must be a mapping");
        return -1;
    }

    for (i = 0; i != node->data.mapping.size; ++i) {
        yoml_t *key = node->data.mapping.elements[i].key;
        yoml_t *value = node->data.mapping.elements[i].value;
        h2o_host_configuration_t *host_config;
        if (key->type != YOML_TYPE_SCALAR) {
            h2o_config_print_error(configurator, file, key, "key (representing the hostname) must be a string");
            return -1;
        }
        host_config = h2o_config_register_virtual_host(config, key->data.scalar);
        if (apply_commands(host_config, file, value, config) != 0)
            return -1;
    }

    return 0;
}

static int on_config_request_timeout(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_global_configuration_t *config = _config;
    unsigned timeout_in_secs;

    if (h2o_config_scanf(configurator, file, node, "%u", &timeout_in_secs) != 0)
        return -1;

    config->req_timeout = timeout_in_secs * 1000;
    return 0;
}

static int on_config_limit_request_body(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_global_configuration_t *config = _config;
    return h2o_config_scanf(configurator, file, node, "%zu", &config->max_request_entity_size);
}

static int on_config_http1_upgrade_to_http2(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_global_configuration_t *config = _config;
    ssize_t ret = h2o_config_get_one_of(configurator, file, node, "OFF,ON");
    if (ret == -1)
        return -1;
    config->http1_upgrade_to_http2 = (int)ret;
    return 0;
}

static int on_config_http2_max_concurrent_requests_per_connection(h2o_configurator_t *configurator, void *_config, const char *file, yoml_t *node)
{
    h2o_global_configuration_t *config = _config;
    return h2o_config_scanf(configurator, file, node, "%zu", &config->http2_max_concurrent_requests_per_connection);
}

static void setup_configurator(h2o_linklist_t *anchor, const char *cmd, int (*on_cmd)(h2o_configurator_t *, void *, const char *, yoml_t*), ...)
{
    h2o_configurator_t *configurator = h2o_malloc(sizeof(*configurator));
    const char **desc = h2o_malloc(sizeof(*desc) * 16);
    size_t i;
    va_list args;

    /* setup desc */
    va_start(args, on_cmd);
    for (i = 0; ; ++i)
        if ((desc[i] = va_arg(args, const char*)) == NULL)
            break;
    va_end(args);

    memset(configurator, 0, sizeof(*configurator));
    configurator->cmd = cmd;
    configurator->description = desc;
    configurator->destroy = (void*)free;
    configurator->on_cmd = on_cmd;

    h2o_linklist_insert(anchor, &configurator->_link);
}

static void init_core_configurators(h2o_global_configuration_t *config)
{
    /* check if already initialized */
    if (h2o_config_get_configurator(&config->host_configurators, "files") != NULL)
        return;

    setup_configurator(&config->host_configurators, "files", on_config_files,
        "map of URL-path -> local directory",
        NULL);
    setup_configurator(&config->host_configurators, "mime-types", on_config_mime_types,
        "map of extension -> mime-type",
        NULL);
    setup_configurator(&config->global_configurators, "virtual-host", on_config_virtual_host,
        "map of hostname -> map of per-host configs",
        NULL);
    setup_configurator(&config->global_configurators, "request-timeout", on_config_request_timeout,
        "timeout for incoming requests in seconds (default: " H2O_TO_STR(H2O_DEFAULT_REQ_TIMEOUT) ")",
        NULL);
    setup_configurator(&config->global_configurators, "limit-request-body", on_config_limit_request_body,
        "maximum size of request body in bytes (e.g. content of POST)",
        "(default: unlimited)",
        NULL);
    setup_configurator(&config->global_configurators, "http1-upgrade-to-http2", on_config_http1_upgrade_to_http2,
        "boolean flag (ON/OFF) indicating whether or not to allow upgrade to HTTP/2",
        "(default: ON)",
        NULL);
    setup_configurator(&config->global_configurators, "http2-max-concurrent-requests-per-connection", on_config_http2_max_concurrent_requests_per_connection,
        "max. number of requests to be handled concurrently within a single HTTP/2",
        "stream (default: 16)",
        NULL);
}

#define DESTROY_LIST(type, anchor) do { \
    while (! h2o_linklist_is_empty(&anchor)) { \
        type *e = H2O_STRUCT_FROM_MEMBER(type, _link, anchor.next); \
        h2o_linklist_unlink(&e->_link); \
        if (e->destroy != NULL) \
            e->destroy(e); \
    } \
} while (0)

static void init_host_config(h2o_host_configuration_t *host_config)
{
    h2o_linklist_init_anchor(&host_config->handlers);
    h2o_linklist_init_anchor(&host_config->filters);
    h2o_linklist_init_anchor(&host_config->loggers);
    h2o_register_chunked_filter(host_config);
    h2o_init_mimemap(&host_config->mimemap, H2O_DEFAULT_MIMETYPE);
}

static void dispose_host_config(h2o_host_configuration_t *host_config)
{
    free(host_config->hostname.base);
    DESTROY_LIST(h2o_handler_t, host_config->handlers);
    DESTROY_LIST(h2o_filter_t, host_config->filters);
    DESTROY_LIST(h2o_logger_t, host_config->loggers);
    h2o_dispose_mimemap(&host_config->mimemap);
}

void h2o_config_init(h2o_global_configuration_t *config)
{
    memset(config, 0, sizeof(*config));
    h2o_linklist_init_anchor(&config->virtual_hosts);
    init_host_config(&config->default_host);
    h2o_linklist_init_anchor(&config->global_configurators);
    h2o_linklist_init_anchor(&config->host_configurators);
    config->server_name = h2o_buf_init(H2O_STRLIT("h2o/0.1"));
    config->req_timeout = H2O_DEFAULT_REQ_TIMEOUT;
    config->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    config->http1_upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    config->http2_max_concurrent_requests_per_connection = H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION;

    init_core_configurators(config);
}

h2o_host_configuration_t *h2o_config_register_virtual_host(h2o_global_configuration_t *config, const char *hostname)
{
    h2o_host_configuration_t *host_config = h2o_malloc(sizeof(*host_config));
    size_t i;

    memset(host_config, 0, sizeof(*host_config));
    init_host_config(host_config);
    host_config->hostname = h2o_strdup(NULL, hostname, SIZE_MAX);
    for (i = 0; i != host_config->hostname.len; ++i)
        host_config->hostname.base[i] = h2o_tolower(host_config->hostname.base[i]);

    h2o_linklist_insert(&config->virtual_hosts, &host_config->_link);

    return host_config;
}

void h2o_config_dispose(h2o_global_configuration_t *config)
{
    while (! h2o_linklist_is_empty(&config->virtual_hosts)) {
        h2o_host_configuration_t *host_config = H2O_STRUCT_FROM_MEMBER(h2o_host_configuration_t, _link, config->virtual_hosts.next);
        h2o_linklist_unlink(&host_config->_link);
        dispose_host_config(host_config);
        free(host_config);
    }
    dispose_host_config(&config->default_host);
    DESTROY_LIST(h2o_configurator_t, config->global_configurators);
    DESTROY_LIST(h2o_configurator_t, config->host_configurators);

}

h2o_configurator_t *h2o_config_get_configurator(h2o_linklist_t *anchor, const char *cmd)
{
    h2o_linklist_t *node;

    for (node = anchor->next; node != anchor; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if (strcmp(configurator->cmd, cmd) == 0)
            return configurator;
    }

    return NULL;
}

int h2o_config_configure(h2o_global_configuration_t *config, const char *file, yoml_t *node)
{
    /* apply the configuration */
    if (apply_commands(config, file, node, config) != 0)
        return -1;

    /* call the complete callbacks */
    if (complete_configurators(&config->global_configurators, config) != 0)
        return -1;
    if (for_each_host_context(config, complete_host_configurators, &config->host_configurators) != 0)
        return -1;

    return 0;
}

int h2o_config_on_context_create(h2o_global_configuration_t *config, h2o_context_t *ctx)
{
    h2o_linklist_t *node;

    for (node = config->global_configurators.next; node != &config->global_configurators; node = node->next) {
        h2o_configurator_t *configurator = H2O_STRUCT_FROM_MEMBER(h2o_configurator_t, _link, node);
        if (configurator->on_context_create != NULL)
            if (configurator->on_context_create(configurator, ctx) != 0)
                return -1;
    }

    return 0;
}

void h2o_config_print_error(h2o_configurator_t *configurator, const char *file, yoml_t *node, const char *reason, ...)
{
    va_list args;

    fprintf(stderr, "[%s:%zu] ", file, node->line + 1);
    if (configurator != NULL)
        fprintf(stderr, "in command %s, ", configurator->cmd);
    va_start(args, reason);
    vfprintf(stderr, reason, args);
    va_end(args);
    fputc('\n', stderr);
}

int h2o_config_scanf(h2o_configurator_t *configurator, const char *file, yoml_t *node, const char *fmt, ...)
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
    h2o_config_print_error(configurator, file, node, "argument must match the format: %s", fmt);
    return -1;
}

ssize_t h2o_config_get_one_of(h2o_configurator_t *configurator, const char *file, yoml_t *node, const char *candidates)
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
    h2o_config_print_error(configurator, file, node, "argument must be one of: %s", candidates);
    return -1;
}
