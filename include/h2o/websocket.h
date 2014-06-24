#ifndef h2o__websocket_h
#define h2o__websocket_h

#ifdef __cplusplus
extern "C" {
#endif

#include "h2o.h"
#include "h2o/http1.h"
#include "uvwslay.h"

int h2o_is_websocket_handshake(h2o_req_t *req, const char** client_key);
uvwslay_t *h2o_upgrade_to_websocket(h2o_http1_conn_t *conn, const char *client_key, void *user_data, uvwslay_msg_callback msg_cb);

#ifdef __cplusplus
}
#endif

#endif
