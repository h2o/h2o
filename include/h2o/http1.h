#ifndef h2o__http1_h
#define h2o__http1_h

typedef struct st_h2o_http1_conn_t h2o_http1_conn_t;
typedef void (*h2o_http1_close_cb)(h2o_http1_conn_t *conn);
typedef void (*h2o_http1_timeout_cb)(h2o_http1_conn_t *conn);
typedef void (*h2o_http1_upgrade_cb)(void *user_data, uv_stream_t *stream, h2o_input_buffer_t *buffered_input, size_t reqsize);

typedef struct st_h2o_http1_finalostream_t {
    h2o_ostream_t super;
    int sent_headers;
} h2o_http1_finalostream_t;

struct st_h2o_http1_conn_t {
    uv_stream_t *stream;
    h2o_loop_context_t *ctx;
    /* callbacks that should be set by the user */
    h2o_req_cb req_cb;
    h2o_http1_close_cb close_cb;
    /* internal structure */
    h2o_timeout_t *_timeout;
    h2o_http1_timeout_cb _timeout_cb;
    h2o_timeout_entry_t _timeout_entry;
    h2o_input_buffer_t *_input;
    size_t _reqsize;
    h2o_http1_finalostream_t _ostr_final;
    uv_write_t _wreq;
    struct {
        void *data;
        h2o_http1_upgrade_cb cb;
    } upgrade;
    /* the HTTP request / response */
    h2o_req_t req;
};

/* http1 */

void h2o_http1_init(h2o_http1_conn_t *conn);
void h2o_http1_close_and_free(h2o_http1_conn_t *conn);
void h2o_http1_upgrade(h2o_http1_conn_t *conn, uv_buf_t *inbufs, size_t inbufcnt, h2o_http1_upgrade_cb on_complete, void *user_data);
void h2o_http1_set_timeout(h2o_http1_conn_t *conn, h2o_timeout_t *timeout, h2o_http1_timeout_cb cb);
void h2o_http1_on_timeout(h2o_timeout_entry_t *entry);

#endif
