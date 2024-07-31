#include "h2o/httpclient.h"

struct st_h2o_accept_ctx_t;

typedef struct st_h2o_reverse_config_t {
    uint64_t reconnect_interval;
    void (*setup_socket)(h2o_socket_t *sock, void *data);
} h2o_reverse_config_t;

typedef struct st_h2o_reverse_ctx_t {
    h2o_reverse_config_t config;
    h2o_url_t *client;
    struct st_h2o_accept_ctx_t *accept_ctx;
    h2o_timer_t reconnect_timer;
    void *data;
    struct {
        h2o_httpclient_t *client;
        h2o_httpclient_ctx_t ctx;
        h2o_httpclient_connection_pool_t connpool;
        h2o_socketpool_t sockpool;
    } httpclient;
    h2o_mem_pool_t pool;
} h2o_reverse_ctx_t;

void h2o_reverse_start_listening(h2o_reverse_ctx_t *reverse);
void h2o_reverse_init(h2o_reverse_ctx_t *reverse, h2o_url_t *client, struct st_h2o_accept_ctx_t *accept_ctx, h2o_reverse_config_t config, void *data);
