#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "h2o/websocket.h"

int h2o_is_websocket_handshake(h2o_req_t *req, const char **ws_client_key)
{
    ssize_t key_header_index;

    *ws_client_key = NULL;

    /* method */
    if (h2o_memis(req->method, req->method_len, H2O_STRLIT("GET"))) {
        /* ok */
    } else {
        return 0;
    }

    /* upgrade header */
    if (req->upgrade.base != NULL && h2o_lcstris(req->upgrade.base, req->upgrade.len, H2O_STRLIT("websocket"))) {
        /* ok */
    } else {
        return 0;
    }
    /* sec-websocket-key header */
    if ((key_header_index = h2o_find_header_by_str(&req->headers, H2O_STRLIT("sec-websocket-key"), -1)) != -1) {
        if (req->headers.entries[key_header_index].value.len != 24) {
            return -1;
        }
    } else {
        return 0;
    }

    *ws_client_key = req->headers.entries[key_header_index].value.base;
    return 0;
}

static void on_complete(void *user_data, uv_stream_t *stream, h2o_input_buffer_t *buffered_input, size_t reqsize)
{
    uvwslay_t *uvwslay = user_data;

    if (buffered_input != NULL && buffered_input->size != reqsize) {
        fprintf(stderr, "ignoring already-received data\n");
    }
    free(buffered_input);

    /* close the connection on error */
    if (stream == NULL) {
        (*uvwslay->msg_cb)(uvwslay, NULL);
        return;
    }
    assert(uvwslay->stream == stream);

    uvwslay_proceed(uvwslay);
}

uvwslay_t *h2o_upgrade_to_websocket(h2o_http1_conn_t *conn, const char *client_key, void *user_data, uvwslay_msg_callback msg_cb)
{
    uvwslay_t *uvwslay;
    char accept_key[29];

    /* setup the context */
    uvwslay = uvwslay_new(conn->stream, user_data, msg_cb);

    /* build response */
    uvwslay_create_accept_key(accept_key, client_key);
    conn->req.res.status = 101;
    conn->req.res.reason = "Switching Protocols";
    h2o_add_header(&conn->req.pool, &conn->req.res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("websocket"));
    h2o_add_header_by_str(&conn->req.pool, &conn->req.res.headers, H2O_STRLIT("sec-websocket-accept"), 0, accept_key, strlen(accept_key));

    /* send */
    h2o_http1_upgrade(conn, NULL, 0, on_complete, uvwslay);

    return uvwslay;
}
