#ifndef h2o__http2_h
#define h2o__http2_h

/* hpack */

#define H2O_HTTP2_ENCODE_INT_MAX_LENGTH 5

typedef struct st_h2o_hpack_header_table_t {
    /* ring buffer */
    struct st_h2o_hpack_header_table_entry_t *entries;
    size_t num_entries, entry_capacity, entry_start_index;
    /* size and capacity are 32+name_len+value_len (as defined by hpack spec.) */
    size_t hpack_size;
    size_t hpack_capacity;
} h2o_hpack_header_table_t;

void h2o_dispose_hpack_header_table(h2o_mempool_t *pool, h2o_hpack_header_table_t *header_table);
size_t h2o_http2_encode_string(uint8_t *dst, const char *s, size_t len);
uv_buf_t h2o_http2_flatten_headers(h2o_mempool_t *pool, size_t max_frame_size, h2o_res_t *res);

/* settings */

typedef struct st_h2o_http2_conn_t h2o_http2_conn_t;

#define H2O_HTTP2_SETTINGS_HEADER_TABLE_SIZE 1
#define H2O_HTTP2_SETTINGS_ENABLE_PUSH 2
#define H2O_HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 3
#define H2O_HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 4
#define H2O_HTTP2_SETTINGS_MAX_FRAME_SIZE 5
#define H2O_HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 6

typedef struct st_h2o_http2_settings_t {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
} h2o_http2_settings_t;

/* frames */

#define H2O_HTTP2_FRAME_HEADER_SIZE 9

#define H2O_HTTP2_DATA_FRAME_TYPE 0
#define H2O_HTTP2_HEADERS_FRAME_TYPE 1
#define H2O_HTTP2_PRIORITY_FRAME_TYPE 2
#define H2O_HTTP2_RST_STREAM_FRAME_TYPE 3
#define H2O_HTTP2_SETTINGS_FRAME_TYPE 4
#define H2O_HTTP2_PUSH_PROMISE_FRAME_TYPE 5
#define H2O_HTTP2_PING_FRAME_TYPE 6
#define H2O_HTTP2_GOAWAY_FRAME_TYPE 7
#define H2O_HTTP2_WINDOW_UPDATE_FRAME_TYPE 8
#define H2O_HTTP2_CONTINUATION_FRAME_TYPE 9

#define H2O_HTTP2_END_STREAM_FRAME_FLAG 0x1
#define H2O_HTTP2_END_HEADERS_FRAME_FLAG 0x4

typedef struct st_h2o_http2_frame_header_t {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
} h2o_http2_frame_header_t;

typedef struct st_h2o_http2_finalostream_t {
    h2o_ostream_t super;
    int sent_headers;
    struct {
        h2o_http2_frame_header_t *bufs;
        size_t capacity;
    } header_bufs;
} h2o_http2_finalostream_t;

typedef void (*h2o_http2_close_cb)(h2o_http2_conn_t *conn);

struct st_h2o_http2_conn_t {
    uv_stream_t *stream;
    h2o_loop_context_t *ctx;
    /* callbacks that should be set by the user */
    h2o_req_cb req_cb;
    h2o_http2_close_cb close_cb;
    /* settings */
    h2o_http2_settings_t peer_settings;
    /* only handle one request at a time */
    h2o_req_t req;
    /* internal */
    int (*_read_expect)(h2o_http2_conn_t *conn);
    h2o_input_buffer_t *_input;
    h2o_input_buffer_t *_http1_req_input; /* contains data referred to by original request via HTTP/1.1 */
    uv_write_t _wreq;
    h2o_http2_finalostream_t _ostr_final;
};

void h2o_http2_settings_init(h2o_http2_settings_t *settings);
int h2o_http2_settings_set_header_table_size(h2o_http2_settings_t *settings, uint32_t value);
int h2o_http2_settings_set_enable_push(h2o_http2_settings_t *settings, uint32_t value);
int h2o_http2_settings_set_max_concurrent_streams(h2o_http2_settings_t *settings, uint32_t value);
int h2o_http2_settings_set_initial_window_size(h2o_http2_settings_t *settings, uint32_t value);
int h2o_http2_settings_set_max_frame_size(h2o_http2_settings_t *settings, uint32_t value);
int h2o_http2_settings_decode_payload(h2o_http2_settings_t *settings, uint8_t *src, size_t len);

/* core */
void h2o_http2_encode_frame_header(uint8_t *dst, size_t length, uint8_t type, uint8_t flags, int32_t stream_id);
void h2o_http2_close_and_free(h2o_http2_conn_t *conn);
int h2o_http2_parse_request(h2o_mempool_t *pool, h2o_req_t *req, h2o_hpack_header_table_t *header_table, const uint8_t *src, size_t len);
int h2o_http2_handle_upgrade(h2o_req_t *req, h2o_http2_conn_t *conn);

#endif
