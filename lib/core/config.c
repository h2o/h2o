/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd.
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
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h2o.h"
#include "h2o/configurator.h"
#include "h2o/http1.h"
#include "h2o/http2.h"

static h2o_hostconf_t *create_hostconf(h2o_globalconf_t *globalconf)
{
    h2o_hostconf_t *hostconf = h2o_mem_alloc(sizeof(*hostconf));
    *hostconf = (h2o_hostconf_t){globalconf};
    hostconf->http2.push_preload = 1; /* enabled by default */
    h2o_config_init_pathconf(&hostconf->fallback_path, globalconf, NULL, globalconf->mimemap);
    hostconf->mimemap = globalconf->mimemap;
    h2o_mem_addref_shared(hostconf->mimemap);
    return hostconf;
}

static void destroy_hostconf(h2o_hostconf_t *hostconf)
{
    size_t i;

    if (hostconf->authority.hostport.base != hostconf->authority.host.base)
        free(hostconf->authority.hostport.base);
    free(hostconf->authority.host.base);
    for (i = 0; i != hostconf->paths.size; ++i) {
        h2o_pathconf_t *pathconf = hostconf->paths.entries + i;
        h2o_config_dispose_pathconf(pathconf);
    }
    free(hostconf->paths.entries);
    h2o_config_dispose_pathconf(&hostconf->fallback_path);
    h2o_mem_release_shared(hostconf->mimemap);

    free(hostconf);
}

static void on_dispose_envconf(void *_envconf)
{
    h2o_envconf_t *envconf = _envconf;
    size_t i;

    if (envconf->parent != NULL)
        h2o_mem_release_shared(envconf->parent);

    for (i = 0; i != envconf->unsets.size; ++i)
        h2o_mem_release_shared(envconf->unsets.entries[i].base);
    free(envconf->unsets.entries);
    for (i = 0; i != envconf->sets.size; ++i)
        h2o_mem_release_shared(envconf->sets.entries[i].base);
    free(envconf->sets.entries);
}

h2o_envconf_t *h2o_config_create_envconf(h2o_envconf_t *parent)
{
    h2o_envconf_t *envconf = h2o_mem_alloc_shared(NULL, sizeof(*envconf), on_dispose_envconf);
    *envconf = (h2o_envconf_t){NULL};

    if (parent != NULL) {
        envconf->parent = parent;
        h2o_mem_addref_shared(parent);
    }
    return envconf;
}

void h2o_config_setenv(h2o_envconf_t *envconf, const char *name, const char *value)
{
    size_t name_len = strlen(name), i;
    h2o_iovec_t *value_slot;

    /* remove from the list of unsets */
    for (i = 0; i != envconf->unsets.size; ++i) {
        if (h2o_memis(envconf->unsets.entries[i].base, envconf->unsets.entries[i].len, name, name_len)) {
            h2o_mem_release_shared(envconf->unsets.entries[i].base);
            h2o_vector_erase(&envconf->unsets, i);
            break;
        }
    }
    /* find the slot */
    for (i = 0; i != envconf->sets.size; i += 2) {
        if (h2o_memis(envconf->sets.entries[i].base, envconf->sets.entries[i].len, name, name_len)) {
            value_slot = envconf->sets.entries + i + 1;
            h2o_mem_release_shared(value_slot->base);
            goto SetValue;
        }
    }
    /* name not found in existing sets */
    h2o_vector_reserve(NULL, &envconf->sets, envconf->sets.size + 2);
    envconf->sets.entries[envconf->sets.size++] = h2o_strdup_shared(NULL, name, name_len);
    value_slot = envconf->sets.entries + envconf->sets.size++;
SetValue:
    *value_slot = h2o_strdup_shared(NULL, value, SIZE_MAX);
}

void h2o_config_unsetenv(h2o_envconf_t *envconf, const char *name)
{
    size_t i, name_len = strlen(name);

    /* do nothing if already set */
    for (i = 0; i != envconf->unsets.size; ++i)
        if (h2o_memis(envconf->unsets.entries[i].base, envconf->unsets.entries[i].len, name, name_len))
            return;
    /* register */
    h2o_vector_reserve(NULL, &envconf->unsets, envconf->unsets.size + 1);
    envconf->unsets.entries[envconf->unsets.size++] = h2o_strdup_shared(NULL, name, name_len);
}

void h2o_config_init_pathconf(h2o_pathconf_t *pathconf, h2o_globalconf_t *globalconf, const char *path, h2o_mimemap_t *mimemap)
{
    memset(pathconf, 0, sizeof(*pathconf));
    pathconf->global = globalconf;
    h2o_chunked_register(pathconf);
    if (path != NULL)
        pathconf->path = h2o_strdup(NULL, path, SIZE_MAX);
    h2o_mem_addref_shared(mimemap);
    pathconf->mimemap = mimemap;
    pathconf->error_log.emit_request_errors = 1;
}

void h2o_config_dispose_pathconf(h2o_pathconf_t *pathconf)
{
#define DESTROY_LIST(type, list)                                                                                                   \
    do {                                                                                                                           \
        size_t i;                                                                                                                  \
        for (i = 0; i != list.size; ++i) {                                                                                         \
            type *e = list.entries[i];                                                                                             \
            if (e->dispose != NULL)                                                                                                \
                e->dispose(e);                                                                                                     \
            free(e);                                                                                                               \
        }                                                                                                                          \
        free(list.entries);                                                                                                        \
    } while (0)
    DESTROY_LIST(h2o_handler_t, pathconf->handlers);
    DESTROY_LIST(h2o_filter_t, pathconf->filters);
    DESTROY_LIST(h2o_logger_t, pathconf->loggers);
#undef DESTROY_LIST

    free(pathconf->path.base);
    if (pathconf->mimemap != NULL)
        h2o_mem_release_shared(pathconf->mimemap);
    if (pathconf->env != NULL)
        h2o_mem_release_shared(pathconf->env);
}

void h2o_config_init(h2o_globalconf_t *config)
{
    memset(config, 0, sizeof(*config));
    config->hosts = h2o_mem_alloc(sizeof(config->hosts[0]));
    config->hosts[0] = NULL;
    h2o_linklist_init_anchor(&config->configurators);
    config->server_name = h2o_iovec_init(H2O_STRLIT("h2o/" H2O_VERSION));
    config->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    config->max_delegations = H2O_DEFAULT_MAX_DELEGATIONS;
    config->handshake_timeout = H2O_DEFAULT_HANDSHAKE_TIMEOUT;
    config->http1.req_timeout = H2O_DEFAULT_HTTP1_REQ_TIMEOUT;
    config->http1.upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    config->http1.callbacks = H2O_HTTP1_CALLBACKS;
    config->http2.idle_timeout = H2O_DEFAULT_HTTP2_IDLE_TIMEOUT;
    config->proxy.io_timeout = H2O_DEFAULT_PROXY_IO_TIMEOUT;
    config->proxy.emit_x_forwarded_headers = 1;
    config->http2.max_concurrent_requests_per_connection = H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams;
    config->http2.max_streams_for_priority = 16;
    config->http2.latency_optimization.min_rtt = 50; // milliseconds
    config->http2.latency_optimization.max_additional_delay = 10;
    config->http2.latency_optimization.max_cwnd = 65535;
    config->http2.callbacks = H2O_HTTP2_CALLBACKS;
    config->mimemap = h2o_mimemap_create();

    h2o_configurator__init_core(config);
}

h2o_pathconf_t *h2o_config_register_path(h2o_hostconf_t *hostconf, const char *path, int flags)
{
    h2o_pathconf_t *pathconf;

    h2o_vector_reserve(NULL, &hostconf->paths, hostconf->paths.size + 1);
    pathconf = hostconf->paths.entries + hostconf->paths.size++;

    h2o_config_init_pathconf(pathconf, hostconf->global, path, hostconf->mimemap);

    return pathconf;
}

void h2o_config_register_status_handler(h2o_globalconf_t *config, h2o_status_handler_t status_handler)
{
    h2o_vector_reserve(NULL, &config->statuses, config->statuses.size + 1);
    config->statuses.entries[config->statuses.size++] = status_handler;
}

void h2o_config_register_simple_status_handler(h2o_globalconf_t *config, h2o_iovec_t name, final_status_handler_cb status_handler)
{
    h2o_status_handler_t *sh;

    h2o_vector_reserve(NULL, &config->statuses, config->statuses.size + 1);
    sh = &config->statuses.entries[config->statuses.size++];
    memset(sh, 0, sizeof(*sh));
    sh->name = h2o_strdup(NULL, name.base, name.len);
    sh->final = status_handler;
}

h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *config, h2o_iovec_t host, uint16_t port)
{
    h2o_hostconf_t *hostconf = NULL;
    h2o_iovec_t host_lc;

    assert(host.len != 0);

    /* convert hostname to lowercase */
    host_lc = h2o_strdup(NULL, host.base, host.len);
    h2o_strtolower(host_lc.base, host_lc.len);

    { /* return NULL if given authority is already registered */
        h2o_hostconf_t **p;
        for (p = config->hosts; *p != NULL; ++p)
            if (h2o_memis((*p)->authority.host.base, (*p)->authority.host.len, host_lc.base, host_lc.len) &&
                (*p)->authority.port == port)
                goto Exit;
    }

    /* create hostconf */
    hostconf = create_hostconf(config);
    hostconf->authority.host = host_lc;
    host_lc = (h2o_iovec_t){NULL};
    hostconf->authority.port = port;
    if (hostconf->authority.port == 65535) {
        hostconf->authority.hostport = hostconf->authority.host;
    } else {
        hostconf->authority.hostport.base = h2o_mem_alloc(hostconf->authority.host.len + sizeof("[]:" H2O_UINT16_LONGEST_STR));
        if (strchr(hostconf->authority.host.base, ':') != NULL) {
            hostconf->authority.hostport.len =
                sprintf(hostconf->authority.hostport.base, "[%s]:%" PRIu16, hostconf->authority.host.base, port);
        } else {
            hostconf->authority.hostport.len =
                sprintf(hostconf->authority.hostport.base, "%s:%" PRIu16, hostconf->authority.host.base, port);
        }
    }

    /* append to the list */
    h2o_append_to_null_terminated_list((void *)&config->hosts, hostconf);

Exit:
    free(host_lc.base);
    return hostconf;
}

void h2o_config_dispose(h2o_globalconf_t *config)
{
    size_t i;

    for (i = 0; config->hosts[i] != NULL; ++i) {
        h2o_hostconf_t *hostconf = config->hosts[i];
        destroy_hostconf(hostconf);
    }
    free(config->hosts);

    h2o_mem_release_shared(config->mimemap);
    h2o_configurator__dispose_configurators(config);
}

h2o_handler_t *h2o_create_handler(h2o_pathconf_t *conf, size_t sz)
{
    h2o_handler_t *handler = h2o_mem_alloc(sz);

    memset(handler, 0, sz);
    handler->_config_slot = conf->global->_num_config_slots++;

    h2o_vector_reserve(NULL, &conf->handlers, conf->handlers.size + 1);
    conf->handlers.entries[conf->handlers.size++] = handler;

    return handler;
}

h2o_filter_t *h2o_create_filter(h2o_pathconf_t *conf, size_t sz)
{
    h2o_filter_t *filter = h2o_mem_alloc(sz);

    memset(filter, 0, sz);
    filter->_config_slot = conf->global->_num_config_slots++;

    h2o_vector_reserve(NULL, &conf->filters, conf->filters.size + 1);
    memmove(conf->filters.entries + 1, conf->filters.entries, conf->filters.size * sizeof(conf->filters.entries[0]));
    conf->filters.entries[0] = filter;
    ++conf->filters.size;

    return filter;
}

h2o_logger_t *h2o_create_logger(h2o_pathconf_t *conf, size_t sz)
{
    h2o_logger_t *logger = h2o_mem_alloc(sz);

    memset(logger, 0, sz);
    logger->_config_slot = conf->global->_num_config_slots++;

    h2o_vector_reserve(NULL, &conf->loggers, conf->loggers.size + 1);
    conf->loggers.entries[conf->loggers.size++] = logger;

    return logger;
}
