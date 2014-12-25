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
#include <stdlib.h>
#include "h2o.h"
#include "h2o/configurator.h"

static void init_pathconf(h2o_pathconf_t *pathconf, h2o_hostconf_t *hostconf)
{
    memset(pathconf, 0, sizeof(*pathconf));
    pathconf->host = hostconf;
    h2o_chunked_register(pathconf);
}

static void dispose_pathconf(h2o_pathconf_t *pathconf)
{
#define DESTROY_LIST(type, list) do { \
    size_t i; \
    for (i = 0; i != list.size; ++i) { \
        type *e = list.entries[i]; \
        if (e->dispose != NULL) \
            e->dispose(e); \
        free(e); \
    } \
    free(list.entries); \
} while (0)

    DESTROY_LIST(h2o_handler_t, pathconf->handlers);
    DESTROY_LIST(h2o_filter_t, pathconf->filters);
    DESTROY_LIST(h2o_logger_t, pathconf->loggers);

#undef DESTROY_LIST
}

static void init_hostconf(h2o_hostconf_t *hostconf, h2o_globalconf_t *globalconf)
{
    memset(hostconf, 0, sizeof(*hostconf));
    hostconf->global = globalconf;
    init_pathconf(&hostconf->fallback_path, hostconf);
}

static void dispose_hostconf(h2o_hostconf_t *hostconf)
{
    size_t i;

    free(hostconf->hostname.base);
    for (i = 0; i != hostconf->paths.size; ++i) {
        h2o_pathconf_t *pathconf = hostconf->paths.entries + i;
        dispose_pathconf(pathconf);
    }
    dispose_pathconf(&hostconf->fallback_path);
}

void h2o_config_init(h2o_globalconf_t *config)
{
    memset(config, 0, sizeof(*config));
    h2o_linklist_init_anchor(&config->configurators);
    config->server_name = h2o_iovec_init(H2O_STRLIT("h2o/" H2O_VERSION));
    config->max_request_entity_size = H2O_DEFAULT_MAX_REQUEST_ENTITY_SIZE;
    config->http1.req_timeout = H2O_DEFAULT_HTTP1_REQ_TIMEOUT;
    config->http1.upgrade_to_http2 = H2O_DEFAULT_HTTP1_UPGRADE_TO_HTTP2;
    config->http2.idle_timeout = H2O_DEFAULT_HTTP2_IDLE_TIMEOUT;
    config->http2.max_concurrent_requests_per_connection = H2O_DEFAULT_HTTP2_MAX_CONCURRENT_REQUESTS_PER_CONNECTION;

    h2o_configurator__init_core(config);
}

h2o_pathconf_t *h2o_config_register_path(h2o_hostconf_t *hostconf, const char *pathname)
{
    h2o_pathconf_t *pathconf;

    h2o_vector_reserve(NULL, (void*)&hostconf->paths, sizeof(hostconf->paths.entries[0]), hostconf->paths.size + 1);
    pathconf = hostconf->paths.entries + hostconf->paths.size++;

    init_pathconf(pathconf, hostconf);
    pathconf->path = h2o_strdup_slashed(NULL, pathname, SIZE_MAX);

    return pathconf;
}

h2o_hostconf_t *h2o_config_register_host(h2o_globalconf_t *config, const char *hostname)
{
    h2o_hostconf_t *hostconf;
    size_t i;

    h2o_vector_reserve(NULL, (void*)&config->hosts, sizeof(config->hosts.entries[0]), config->hosts.size + 1);
    hostconf = config->hosts.entries + config->hosts.size++;

    init_hostconf(hostconf, config);
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
        dispose_hostconf(hostconf);
    }
    free(config->hosts.entries);

    h2o_configurator__dispose_configurators(config);
}

h2o_handler_t *h2o_create_handler(h2o_pathconf_t *conf, size_t sz)
{
    h2o_handler_t *handler = h2o_mem_alloc(sz);

    memset(handler, 0, sz);
    handler->_config_slot = conf->host->global->_num_config_slots++;

    h2o_vector_reserve(NULL, (void*)&conf->handlers, sizeof(conf->handlers.entries[0]), conf->handlers.size + 1);
    conf->handlers.entries[conf->handlers.size++] = handler;

    return handler;
}

h2o_filter_t *h2o_create_filter(h2o_pathconf_t *conf, size_t sz)
{
    h2o_filter_t *filter = h2o_mem_alloc(sz);

    memset(filter, 0, sz);
    filter->_config_slot = conf->host->global->_num_config_slots++;

    h2o_vector_reserve(NULL, (void*)&conf->filters, sizeof(conf->filters.entries[0]), conf->filters.size + 1);
    conf->filters.entries[conf->filters.size++] = filter;

    return filter;
}

h2o_logger_t *h2o_create_logger(h2o_pathconf_t *conf, size_t sz)
{
    h2o_logger_t *logger = h2o_mem_alloc(sz);

    memset(logger, 0, sz);
    logger->_config_slot = conf->host->global->_num_config_slots++;

    h2o_vector_reserve(NULL, (void*)&conf->loggers, sizeof(conf->loggers.entries[0]), conf->loggers.size + 1);
    conf->loggers.entries[conf->loggers.size++] = logger;

    return logger;
}
