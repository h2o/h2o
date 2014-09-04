#ifndef h2o__websocket_h
#define h2o__websocket_h

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include "h2o.h"
#include "h2o/http1.h"

typedef struct st_h2o_websocket_conn_t h2o_websocket_conn_t;

/* arg is NULL if the connection has been closed */
typedef void (*h2o_websocket_msg_callback)(h2o_websocket_conn_t *conn, const struct wslay_event_on_msg_recv_arg *arg);

struct st_h2o_websocket_conn_t {
    h2o_socket_t *sock;
    wslay_event_context_ptr ws_ctx;
    struct wslay_event_callbacks ws_callbacks;
    void *data;
    h2o_websocket_msg_callback cb;
    void *_write_buf;
};

int h2o_is_websocket_handshake(h2o_req_t *req, const char** client_key);
void h2o_websocket_create_accept_key(char *dst, const char *client_key);
h2o_websocket_conn_t *h2o_upgrade_to_websocket(h2o_http1_conn_t *conn, const char *client_key, void *user_data, h2o_websocket_msg_callback msg_cb);
void h2o_websocket_close(h2o_websocket_conn_t *conn);
void h2o_websocket_proceed(h2o_websocket_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif
