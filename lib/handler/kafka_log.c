/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "h2o.h"
#include "h2o/serverutil.h"
#include "librdkafka/rdkafka.h"

struct st_h2o_kafka_log_handle_t {
    h2o_logconf_t *logconf_message;
    h2o_logconf_t *logconf_key;
    h2o_logconf_t *logconf_hash;
    // h2o_logconf_t *logconf;

    rd_kafka_t *rk;

     // rkt is the target topic which must have been previously created with
     // `rd_kafka_topic_new()`.
    rd_kafka_topic_t *rkt;

    // - RD_KAFKA_PARTITION_UA (unassigned) for
    //    automatic partitioning using the topic's partitioner function, or
    // - a fixed partition (0..N)
    int32_t partition;

    /// ... other feilds if required.
};

struct st_h2o_kafka_logger_t {
    h2o_logger_t super;
    h2o_kafka_log_handle_t *kh;
};

static void log_access(h2o_logger_t *_self, h2o_req_t *req)
{
    struct st_h2o_kafka_logger_t *self = (struct st_h2o_kafka_logger_t *)_self;
    h2o_kafka_log_handle_t *kh = self->kh;
    char *logline_message;
    char *logline_key = NULL;
    char *logline_hash = NULL;
    char buf_message[4096];
    char buf_key[4096];
    char buf_hash[4096];
    size_t len_message = sizeof(buf_message);
    size_t len_hash = 0;
    size_t len_key = 0;

    /* stringify */
    len_message = sizeof(buf_message);
    logline_message = h2o_log_request(kh->logconf_message, req, &len_message, buf_message);
    
    if(kh->logconf_hash)
    {
    len_hash    = sizeof(buf_hash   );
    logline_hash    = h2o_log_request(kh->logconf_hash   , req, &len_hash   , buf_hash   );
    }
    
    if(kh->logconf_key)
    {
    len_key     = sizeof(buf_key    );
    logline_key     = h2o_log_request(kh->logconf_key    , req, &len_key    , buf_key    );
    }

    int attempt = 0;
    rd_kafka_poll(self->kh->rk, 0);
    /* emit */
    struct timeval ts = req->timestamps.request_begin_at;
    L:
    attempt++;
    int res = rd_kafka_producev(
        self->kh->rk,
        RD_KAFKA_V_RKT(self->kh->rkt),
        RD_KAFKA_V_PARTITION(self->kh->partition),
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
        RD_KAFKA_V_VALUE(logline_message, len_message),
        RD_KAFKA_V_KEY(logline_key, len_key),
        RD_KAFKA_V_TIMESTAMP((int64_t)(ts.tv_sec) * 1000 + (int64_t)(ts.tv_usec) / 1000),
        RD_KAFKA_V_END
        );
    if (res)
    {
        int err = rd_kafka_errno();
        rd_kafka_resp_err_t error = rd_kafka_errno2err(err);
        fprintf(stderr, "Error: %s\n", rd_kafka_err2str(error));
        switch(err)
        {
            case ENOBUFS:
                if(attempt < 2)
                {
                    rd_kafka_poll(self->kh->rk, 10);
                    goto L;
                }
                break;
            case EMSGSIZE:
                break;
            case ESRCH:
                break;
            case ENOENT:
                break;
        }
    }

    /* free memory */
    if (logline_message != buf_message) free(logline_message);
    
    if (logline_key != NULL)
    if (logline_hash    != buf_hash   ) free(logline_hash   );
    
    if (logline_key != NULL)
    if (logline_key     != buf_key    ) free(logline_key    );
}

// int h2o_kafka_log_open_log(const char *path)
// {
//     int fd;

//     if (path[0] == '|') {
//         int pipefds[2];
//         pid_t pid;
//         char *argv[4] = {"/bin/sh", "-c", (char *)(path + 1), NULL};
//         /* create pipe */
//         if (pipe(pipefds) != 0) {
//             perror("pipe failed");
//             return -1;
//         }
//         if (fcntl(pipefds[1], F_SETFD, FD_CLOEXEC) == -1) {
//             perror("failed to set FD_CLOEXEC on pipefds[1]");
//             return -1;
//         }
//         /* spawn the logger */
//         int mapped_fds[] = {pipefds[0], 0, /* map pipefds[0] to stdin */
//                             -1};
//         if ((pid = h2o_spawnp(argv[0], argv, mapped_fds, 0)) == -1) {
//             fprintf(stderr, "failed to open logger: %s:%s\n", path + 1, strerror(errno));
//             return -1;
//         }
//         /* close the read side of the pipefds and return the write side */
//         close(pipefds[0]);
//         fd = pipefds[1];
//     } else {
//         if ((fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0644)) == -1) {
//             fprintf(stderr, "failed to open log file:%s:%s\n", path, strerror(errno));
//             return -1;
//         }
//     }

//     return fd;
// }


static void on_dispose_handle(void *_kh)
{
    h2o_kafka_log_handle_t *kh = _kh;

    h2o_logconf_dispose(kh->logconf_message);
    h2o_logconf_dispose(kh->logconf_key);
    h2o_logconf_dispose(kh->logconf_hash);
    // close(kh->fd);
}

h2o_kafka_log_handle_t *h2o_kafka_log_open_handle(
    rd_kafka_conf_t* rk_conf,
    rd_kafka_topic_conf_t* rkt_conf,
    const char *topic,
    int32_t partition,
    const char *fmt_messages,
    const char *fmt_key,
    const char *fmt_hash)
{
    h2o_logconf_t *logconf_message;
    h2o_logconf_t *logconf_key= NULL;
    h2o_logconf_t *logconf_hash = NULL;
    h2o_kafka_log_handle_t *kh;
    char errbuf[512];

    if (fmt_messages == NULL)
        fmt_messages = "{\"tsusec\": %{usec}t,\"remote\": \"%h\",\"status\":%s,\"proto\":\"%H\",\"method\":\"%m\",\"query\":\"%q\",\"date\":\"%{%Y-%m-%d}t\",\"path\":\"%U\",\"server\":\"%V\",\"responseSize\": %b, \"connectionId\":%{connection-id}x, \"http2StreamId\": %{http2.stream-id}x, \"connectTime\": %{connect-time}x, \"timeHeader\": %{request-header-time}x, \"timeBody\": %{request-body-time}x, \"timeProcess\": %{process-time}x, \"timeResponse\": %{response-time}x, \"timeDuration\": %{duration}x, \"sslVersion\":\"%{ssl.protocol-version}x\",\"sslReused\": %{ssl.session-reused}x,\"sslCipher\":\"%{ssl.cipher}x\",\"sslCipherBits\": %{ssl.cipher-bits}x,\"headers\":{ \"user-agent\":\"%{user-agent}i\", \"accept\":\"%{accept}i\", \"accept-encoding\":\"%{accept-encoding}i\", \"accept-language\":\"%{accept-language}i\", \"cache-control\":\"%{cache-control}i\", \"connection\":\"%{connection}i\", \"cookie\":\"%{cookie}i\", \"host\":\"%{host}i\",\"referer\":\"%{referer}i\",\"upgrade-insecure-requests\":\"%{upgrade-insecure-requests}i\"}}";
    if ((logconf_message = h2o_logconf_compile(fmt_messages, H2O_LOGCONF_ESCAPE_JSON, errbuf)) == NULL)
    {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }
    if (fmt_key != NULL)
    if ((logconf_key     = h2o_logconf_compile(fmt_key     , H2O_LOGCONF_ESCAPE_JSON, errbuf)) == NULL)
    {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }
    if (fmt_hash != NULL)
    if ((logconf_hash    = h2o_logconf_compile(fmt_hash    , H2O_LOGCONF_ESCAPE_JSON, errbuf)) == NULL)
    {
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }

    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_PRODUCER, rk_conf, errbuf, sizeof(errbuf));
    if (rk == NULL)
    {
        h2o_logconf_dispose(logconf_message);
        if(logconf_key)
        h2o_logconf_dispose(logconf_key    );
        if(logconf_hash)
        h2o_logconf_dispose(logconf_hash   );
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }

    rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, topic, rkt_conf);
    if (rkt == NULL)
    {
        h2o_logconf_dispose(logconf_message);
        if(logconf_key)
        h2o_logconf_dispose(logconf_key    );
        if(logconf_hash)
        h2o_logconf_dispose(logconf_hash   );
        fprintf(stderr, "%s\n", errbuf);
        return NULL;
    }

    // /* open log file */
    // if ((fd = h2o_kafka_log_open_log(path)) == -1) {
    //     h2o_logconf_dispose(logconf);
    //     return NULL;
    // }

    kh = h2o_mem_alloc_shared(NULL, sizeof(*kh), on_dispose_handle);
    kh->logconf_message = logconf_message;
    kh->logconf_key     = logconf_key    ;
    kh->logconf_hash    = logconf_hash   ;
    kh->rk = rk;
    kh->rkt = rkt;
    kh->partition = partition;
    return kh;
}

static void dispose(h2o_logger_t *_self)
{
    struct st_h2o_kafka_logger_t *self = (void *)_self;

    h2o_mem_release_shared(self->kh);
}

h2o_logger_t *h2o_kafka_log_register(h2o_pathconf_t *pathconf, h2o_kafka_log_handle_t *kh)
{
    struct st_h2o_kafka_logger_t *self = (void *)h2o_create_logger(pathconf, sizeof(*self));

    self->super.dispose = dispose;
    self->super.log_access = log_access;
    self->kh = kh;
    h2o_mem_addref_shared(kh);

    return &self->super;
}
