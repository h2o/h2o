#ifndef uvwslay_h
#define uvwslay_h

#ifdef __cplusplus
extern "C" {
#endif

#include <uv.h>
#include <wslay/wslay.h>

struct uvwslay_t;

/* arg is NULL if the connection has been closed */
typedef void (*uvwslay_msg_callback)(struct uvwslay_t *uvwslay, const struct wslay_event_on_msg_recv_arg *arg);

typedef struct uvwslay_t {
    uv_write_t wreq;
    uv_buf_t wbuf; /* buf.base == NULL if ready to write */
    uv_stream_t *stream;
    wslay_event_context_ptr ws_ctx;
    struct wslay_event_callbacks ws_callbacks;
    void *user_data;
    uvwslay_msg_callback msg_cb;
    size_t rbuf_start, rbuf_end;
    char rbuf[65536];
} uvwslay_t;

uvwslay_t *uvwslay_new(uv_stream_t *stream, void *user_data, uvwslay_msg_callback msg_cb);
void uvwslay_free(uvwslay_t *self);
void uvwslay_proceed(uvwslay_t *self);

void uvwslay_create_accept_key(char *dst, const char *client_key);

#ifdef __cplusplus
}
#endif

#endif
