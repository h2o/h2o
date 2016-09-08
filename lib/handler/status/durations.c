/*
 * Copyright (c) 2016 Fastly
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
#include "gkc.h"
#include <inttypes.h>
#include <pthread.h>

#define GK_EPSILON 0.01

struct st_duration_stats_t {
    struct gkc_summary *connect_time;
    struct gkc_summary *header_time;
    struct gkc_summary *body_time;
    struct gkc_summary *request_total_time;
    struct gkc_summary *process_time;
    struct gkc_summary *response_time;
    struct gkc_summary *duration;
};

struct st_duration_agg_stats_t {
    struct st_duration_stats_t stats;
    pthread_mutex_t mutex;
};

static h2o_logger_t *durations_logger;
static void durations_status_per_thread(void *priv, h2o_context_t *ctx)
{
    struct st_duration_agg_stats_t *agg_stats = priv;
    if (durations_logger) {
        struct st_duration_stats_t *ctx_stats = h2o_context_get_logger_context(ctx, durations_logger);
        pthread_mutex_lock(&agg_stats->mutex);
#define ADD_DURATION(x)                                                                                                            \
    do {                                                                                                                           \
        struct gkc_summary *tmp;                                                                                                   \
        tmp = gkc_combine(agg_stats->stats.x, ctx_stats->x);                                                                       \
        gkc_summary_free(agg_stats->stats.x);                                                                                      \
        agg_stats->stats.x = tmp;                                                                                                  \
    } while (0)
        ADD_DURATION(connect_time);
        ADD_DURATION(header_time);
        ADD_DURATION(body_time);
        ADD_DURATION(request_total_time);
        ADD_DURATION(process_time);
        ADD_DURATION(response_time);
        ADD_DURATION(duration);
#undef ADD_DURATION
        pthread_mutex_unlock(&agg_stats->mutex);
    }
}

static void duration_stats_init(struct st_duration_stats_t *stats)
{
    stats->connect_time = gkc_summary_alloc(GK_EPSILON);
    stats->header_time = gkc_summary_alloc(GK_EPSILON);
    stats->body_time = gkc_summary_alloc(GK_EPSILON);
    stats->request_total_time = gkc_summary_alloc(GK_EPSILON);
    stats->process_time = gkc_summary_alloc(GK_EPSILON);
    stats->response_time = gkc_summary_alloc(GK_EPSILON);
    stats->duration = gkc_summary_alloc(GK_EPSILON);
}

static void *durations_status_init(void)
{
    struct st_duration_agg_stats_t *agg_stats;

    agg_stats = h2o_mem_alloc(sizeof(*agg_stats));

    duration_stats_init(&agg_stats->stats);
    pthread_mutex_init(&agg_stats->mutex, NULL);

    return agg_stats;
}

static void duration_stats_free(struct st_duration_stats_t *stats)
{
    gkc_summary_free(stats->connect_time);
    gkc_summary_free(stats->header_time);
    gkc_summary_free(stats->body_time);
    gkc_summary_free(stats->request_total_time);
    gkc_summary_free(stats->process_time);
    gkc_summary_free(stats->response_time);
    gkc_summary_free(stats->duration);
}

static h2o_iovec_t durations_status_final(void *priv, h2o_globalconf_t *gconf, h2o_req_t *req)
{
    struct st_duration_agg_stats_t *agg_stats = priv;
    h2o_iovec_t ret;

#define BUFSIZE 16384
#define DURATION_FMT(x)                                                                                                            \
    " \"" x "-0\": %lu,\n"                                                                                                         \
    " \"" x "-25\": %lu,\n"                                                                                                        \
    " \"" x "-50\": %lu,\n"                                                                                                        \
    " \"" x "-75\": %lu,\n"                                                                                                        \
    " \"" x "-99\": %lu\n"
#define DURATION_VALS(x)                                                                                                           \
    gkc_query(agg_stats->stats.x, 0), gkc_query(agg_stats->stats.x, 0.25), gkc_query(agg_stats->stats.x, 0.5),                     \
        gkc_query(agg_stats->stats.x, 0.75), gkc_query(agg_stats->stats.x, 0.99)

    ret.base = h2o_mem_alloc_pool(&req->pool, BUFSIZE);
    ret.len = snprintf(
        ret.base, BUFSIZE,
        ",\n" DURATION_FMT("connect-time") "," DURATION_FMT("header-time") "," DURATION_FMT("body-time") "," DURATION_FMT(
            "request-total-time") "," DURATION_FMT("process-time") "," DURATION_FMT("response-time") "," DURATION_FMT("duration"),
        DURATION_VALS(connect_time), DURATION_VALS(header_time), DURATION_VALS(body_time), DURATION_VALS(request_total_time),
        DURATION_VALS(process_time), DURATION_VALS(response_time), DURATION_VALS(duration));

#undef BUFSIZE
#undef DURATION_FMT
#undef DURATION_VALS

    duration_stats_free(&agg_stats->stats);
    pthread_mutex_destroy(&agg_stats->mutex);

    free(agg_stats);
    return ret;
}

static void stat_access(h2o_logger_t *_self, h2o_req_t *req)
{
    struct st_duration_stats_t *ctx_stats = h2o_context_get_logger_context(req->conn->ctx, _self);
#define ADD_OBSERVATION(x, from, until)                                                                                            \
    do {                                                                                                                           \
        int64_t dur;                                                                                                               \
        if (h2o_time_compute_##x(req, &dur)) {                                                                                     \
            gkc_insert_value(ctx_stats->x, dur);                                                                                   \
        }                                                                                                                          \
    } while (0)

    ADD_OBSERVATION(connect_time, &req->conn->connected_at, &req->timestamps.request_begin_at);
    ADD_OBSERVATION(header_time, &req->timestamps.request_begin_at, h2o_timeval_is_null(&req->timestamps.request_body_begin_at)
                                                                        ? &req->processed_at.at
                                                                        : &req->timestamps.request_body_begin_at);
    ADD_OBSERVATION(body_time, h2o_timeval_is_null(&req->timestamps.request_body_begin_at) ? &req->processed_at.at
                                                                                           : &req->timestamps.request_body_begin_at,
                    &req->processed_at.at);
    ADD_OBSERVATION(request_total_time, &req->timestamps.request_begin_at, &req->processed_at.at);
    ADD_OBSERVATION(process_time, &req->processed_at.at, &req->timestamps.response_start_at);
    ADD_OBSERVATION(response_time, &req->timestamps.response_start_at, &req->timestamps.response_end_at);
    ADD_OBSERVATION(duration, &req->timestamps.request_begin_at, &req->timestamps.response_end_at);
#undef ADD_OBSERVATION
}

void on_context_init(struct st_h2o_logger_t *self, h2o_context_t *ctx)
{
    struct st_duration_stats_t *duration_stats = h2o_mem_alloc(sizeof(struct st_duration_stats_t));
    duration_stats_init(duration_stats);
    h2o_context_set_logger_context(ctx, self, duration_stats);
}

void on_context_dispose(struct st_h2o_logger_t *self, h2o_context_t *ctx)
{
    struct st_duration_stats_t *duration_stats;
    duration_stats = h2o_context_get_logger_context(ctx, self);
    duration_stats_free(duration_stats);
}

void h2o_duration_stats_register(h2o_globalconf_t *conf)
{
    int i, k;
    h2o_logger_t *logger;
    h2o_hostconf_t *hconf;

    durations_logger = logger = h2o_mem_alloc(sizeof(*logger));
    memset(logger, 0, sizeof(*logger));
    logger->_config_slot = conf->_num_config_slots++;
    logger->log_access = stat_access;
    logger->on_context_init = on_context_init;
    logger->on_context_dispose = on_context_dispose;

    for (k = 0; conf->hosts[k]; k++) {
        hconf = conf->hosts[k];
        for (i = 0; i < hconf->paths.size; i++) {
            int j;
            for (j = 0; j < hconf->paths.entries[i].handlers.size; j++) {
                h2o_pathconf_t *pathconf = &hconf->paths.entries[i];
                h2o_vector_reserve(NULL, &pathconf->loggers, pathconf->loggers.size + 1);
                pathconf->loggers.entries[pathconf->loggers.size++] = (void *)logger;
            }
        }
    }
}

h2o_status_handler_t durations_status_handler = {
    {H2O_STRLIT("durations")}, durations_status_init, durations_status_per_thread, durations_status_final,
};
