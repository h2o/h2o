/*
 * Copyright (c) 2016 DeNA Co., Ltd., Ichito Nagata
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

#include <inttypes.h>
#include "h2o/http2.h"
#include "h2o/http2_internal.h"

static const char *debug_state_string_open = "OPEN";
static const char *debug_state_string_half_closed_remote = "HALF_CLOSED_REMOTE";
static const char *debug_state_string_reserved_local = "RESERVED_LOCAL";

struct st_h2o_root_debug_state_handler_t {
    h2o_handler_t super;
};

const char *get_debug_state_string(h2o_http2_stream_t *stream)
{
    if (h2o_http2_stream_is_push(stream->stream_id)) {
        switch (stream->state) {
            case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
            case H2O_HTTP2_STREAM_STATE_RECV_BODY:
            case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
                return debug_state_string_reserved_local;
            case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
            case H2O_HTTP2_STREAM_STATE_SEND_BODY:
            case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
                return debug_state_string_half_closed_remote;
            case H2O_HTTP2_STREAM_STATE_IDLE:
            case H2O_HTTP2_STREAM_STATE_END_STREAM:
                return NULL;
        }
    } else {
        switch (stream->state) {
            case H2O_HTTP2_STREAM_STATE_RECV_HEADERS:
            case H2O_HTTP2_STREAM_STATE_RECV_BODY:
            case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
            case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
            case H2O_HTTP2_STREAM_STATE_SEND_BODY:
            case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
                return debug_state_string_open;
            case H2O_HTTP2_STREAM_STATE_IDLE:
            case H2O_HTTP2_STREAM_STATE_END_STREAM:
                return NULL;
        }
    }
    return NULL;
}

static int on_req(h2o_handler_t *_self, h2o_req_t *req)
{
    static h2o_generator_t generator = {NULL, NULL};

    /* if the request is sent via HTTP/1, return 404 response */
    if (req->version < 0x200) {
        req->res.status = 404;
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("text/plain; charset=utf-8"));
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("no-cache, no-store"));
        h2o_start_response(req, &generator);
        h2o_send(req, NULL, 0, 1);
        return 0;
    }

    h2o_http2_conn_t *conn = (void *)req->conn;

    size_t nr_resp = 4; // others
    nr_resp += conn->num_streams.pull.open + conn->num_streams.push.open; // streams
    nr_resp += conn->_input_header_table.num_entries + conn->_output_header_table.num_entries; // hpack

    h2o_iovec_t resp[nr_resp];
    int cur_resp = 0;
    memset(resp, 0, sizeof(resp[0]) * nr_resp);


#define BUFSIZE (2 * 1024)
#define OUTPUT(_fmt, ...)                                     \
    do {                                                      \
        h2o_iovec_t v;                                        \
        v.base = h2o_mem_alloc_pool(&req->pool, BUFSIZE);     \
        v.len = snprintf(v.base, BUFSIZE, _fmt, __VA_ARGS__); \
        resp[cur_resp++] = v;                                 \
    } while (0)

#define OUTPUT_HEADER_TABLE(ht)                                                               \
    do {                                                                                         \
        h2o_hpack_header_table_t *header_table = ht;                                   \
        int i, coma_removed = 0;                                                                    \
        for (i = 0; i < header_table->num_entries; i++) {                                    \
            h2o_hpack_header_table_entry_t *entry = h2o_hpack_header_table_get(header_table, i); \
            OUTPUT(                                                                              \
                   ",\n"                                                                         \
                   "      [ \"%s\", \"%s\" ]",                                                    \
                   entry->name->base,                                                            \
                   entry->value->base);                                                          \
            if (resp[cur_resp - 1].len > 0 && !coma_removed) {                                   \
                resp[cur_resp - 1].base[0] = ' ';                                                \
                coma_removed = 1;                                                                \
            }                                                                                    \
        }                                                                                        \
    } while (0)

    // stringify these variables to use later in Debug Header
    h2o_iovec_t conn_flow_out;
    conn_flow_out.base = h2o_mem_alloc_pool(&req->pool, sizeof(H2O_INT64_LONGEST_STR));
    conn_flow_out.len = sprintf(conn_flow_out.base, "%zd", conn->_write.window._avail);


    h2o_iovec_t conn_flow_in;
    conn_flow_in.base = h2o_mem_alloc_pool(&req->pool, sizeof(H2O_INT64_LONGEST_STR));
    conn_flow_in.len = sprintf(conn_flow_in.base, "%zd", conn->_input_window._avail);

    OUTPUT("{\n"
         "  \"settings\": {\n"
         "    \"SETTINGS_HEADER_TABLE_SIZE\": %" PRIu32 ",\n"
         "    \"SETTINGS_ENABLE_PUSH\": %" PRIu32 ",\n"
         "    \"SETTINGS_MAX_CONCURRENT_STREAMS\": %" PRIu32 ",\n"
         "    \"SETTINGS_INITIAL_WINDOW_SIZE\": %" PRIu32 ",\n"
         "    \"SETTINGS_MAX_FRAME_SIZE\": %" PRIu32 "\n"
         "  },\n"
         "  \"peerSettings\": {\n"
         "    \"SETTINGS_HEADER_TABLE_SIZE\": %" PRIu32 ",\n"
         "    \"SETTINGS_ENABLE_PUSH\": %" PRIu32 ",\n"
         "    \"SETTINGS_MAX_CONCURRENT_STREAMS\": %" PRIu32 ",\n"
         "    \"SETTINGS_INITIAL_WINDOW_SIZE\": %" PRIu32 ",\n"
         "    \"SETTINGS_MAX_FRAME_SIZE\": %" PRIu32 "\n"
         "  },\n"
         "  \"connFlowOut\": %s,\n"
         "  \"connFlowIn\": %s,\n"
         "  \"streams\": {",
         H2O_HTTP2_SETTINGS_HOST.header_table_size,
         H2O_HTTP2_SETTINGS_HOST.enable_push,
         H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams,
         H2O_HTTP2_SETTINGS_HOST.initial_window_size,
         H2O_HTTP2_SETTINGS_HOST.max_frame_size,
         conn->peer_settings.header_table_size,
         conn->peer_settings.enable_push,
         conn->peer_settings.max_concurrent_streams,
         conn->peer_settings.initial_window_size,
         conn->peer_settings.max_frame_size,
         conn_flow_out.base,
         conn_flow_in.base);

    /* encode streams */
    {
        int coma_removed = 0;
        h2o_http2_stream_t *stream;
        kh_foreach_value(conn->streams, stream, {
            const char *state_string = get_debug_state_string(stream);
            if (state_string == NULL)
                continue;

            OUTPUT(",\n"
                   "    \"%" PRIu32 "\": {\n"
                   "      \"state\": \"%s\",\n"
                   "      \"flowIn\": %zd,\n"
                   "      \"flowOut\": %zd,\n"
                   "      \"dataIn\": %zu,\n"
                   "      \"dataOut\": %zu\n"
                   "    }",
                   stream->stream_id,
                   state_string,
                   stream->input_window._avail,
                   stream->output_window._avail,
                   (stream->_req_body == NULL ? 0 : stream->_req_body->size),
                   stream->req.bytes_sent);

            if (resp[cur_resp - 1].len > 0 && !coma_removed) {
                resp[cur_resp - 1].base[0] = ' ';
                coma_removed = 1;
            }

        });
    }

    /* encode inbound header table */
    OUTPUT("\n"
           "  },\n"
           "  \"hpack\": {\n"
           "    \"inbound_table_size\": %zd,\n"
           "    \"inbound_dynamic_header_table\": [",
           conn->_input_header_table.num_entries);
    OUTPUT_HEADER_TABLE(&conn->_input_header_table);

    /* encode outbound header table */
    OUTPUT("\n"
           "    ],\n"
           "    \"outbound_table_size\": %zd,\n"
           "    \"outbound_dynamic_header_table\": [",
           conn->_output_header_table.num_entries);
    OUTPUT_HEADER_TABLE(&conn->_output_header_table);

    OUTPUT("\n"
           "    ]\n"
           "  },\n"
           "  \"sentGoAway\": %s\n"
           "}\n",
           (conn->_sent_goaway ? "true" : "false"));

    req->res.status = 200;
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, H2O_STRLIT("application/json; charset=utf-8"));
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CACHE_CONTROL, H2O_STRLIT("no-cache, no-store"));
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONN_FLOW_IN, conn_flow_in.base, conn_flow_in.len);
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONN_FLOW_OUT, conn_flow_out.base, conn_flow_out.len);
    h2o_start_response(req, &generator);
    h2o_send(req, resp, h2o_memis(req->input.method.base, req->input.method.len, H2O_STRLIT("HEAD")) ? 0 : nr_resp, 1);
    return 0;
#undef BUFSIZE
#undef OUTPUT
#undef OUTPUT_HEADER_TABLE
}

void h2o_debug_state_register(h2o_hostconf_t *conf)
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(conf, "/.well-known/h2interop/state", 0);
    struct st_h2o_root_debug_state_handler_t *self = (void *)h2o_create_handler(pathconf, sizeof(*self));
    self->super.on_req = on_req;
}
