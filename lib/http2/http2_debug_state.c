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
#include <inttypes.h>
#include "h2o.h"
#include "h2o/http2.h"
#include "h2o/http2_internal.h"

static const char *debug_state_string_open = "OPEN";
static const char *debug_state_string_half_closed_remote = "HALF_CLOSED_REMOTE";
static const char *debug_state_string_reserved_local = "RESERVED_LOCAL";

static const char *get_debug_state_string(h2o_http2_stream_t *stream)
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
            return debug_state_string_open;
        case H2O_HTTP2_STREAM_STATE_REQ_PENDING:
        case H2O_HTTP2_STREAM_STATE_SEND_HEADERS:
        case H2O_HTTP2_STREAM_STATE_SEND_BODY:
        case H2O_HTTP2_STREAM_STATE_SEND_BODY_IS_FINAL:
            return debug_state_string_half_closed_remote;
        case H2O_HTTP2_STREAM_STATE_IDLE:
        case H2O_HTTP2_STREAM_STATE_END_STREAM:
            return NULL;
        }
    }
    return NULL;
}

__attribute__((format(printf, 3, 4))) static void append_chunk(h2o_mem_pool_t *pool, h2o_iovec_vector_t *chunks, const char *fmt,
                                                               ...)
{
    va_list args;

    va_start(args, fmt);
    int size = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    assert(size > 0);

    h2o_iovec_t v;
    v.base = h2o_mem_alloc_pool(pool, size + 1);

    va_start(args, fmt);
    v.len = vsnprintf(v.base, size + 1, fmt, args);
    va_end(args);

    h2o_vector_reserve(pool, chunks, chunks->size + 1);
    chunks->entries[chunks->size++] = v;
}

static void append_header_table_chunks(h2o_mem_pool_t *pool, h2o_iovec_vector_t *chunks, h2o_hpack_header_table_t *header_table)
{
    int i;
    for (i = 0; i < header_table->num_entries; i++) {
        h2o_hpack_header_table_entry_t *entry = h2o_hpack_header_table_get(header_table, i);
        append_chunk(pool, chunks, "\n"
                                   "      [ \"%.*s\", \"%.*s\" ],",
                     (int)entry->name->len, entry->name->base, (int)entry->value->len, entry->value->base);
    }

    if (i > 0) {
        // remove the last commna
        --chunks->entries[chunks->size - 1].len;
    }
}

h2o_http2_debug_state_t *h2o_http2_get_debug_state(h2o_req_t *req, int hpack_enabled)
{
    h2o_http2_conn_t *conn = (h2o_http2_conn_t *)req->conn;
    h2o_http2_debug_state_t *state = h2o_mem_alloc_pool(&req->pool, sizeof(*state));
    *state = (h2o_http2_debug_state_t){{NULL}};

    state->conn_flow_in = conn->_write.window._avail;
    state->conn_flow_out = conn->_write.window._avail;

    append_chunk(&req->pool, &state->json, "{\n"
                                           "  \"version\": \"draft-01\",\n"
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
                                           "  \"connFlowIn\": %zd,\n"
                                           "  \"connFlowOut\": %zd,\n"
                                           "  \"streams\": {",
                 H2O_HTTP2_SETTINGS_HOST.header_table_size, H2O_HTTP2_SETTINGS_HOST.enable_push,
                 H2O_HTTP2_SETTINGS_HOST.max_concurrent_streams, H2O_HTTP2_SETTINGS_HOST.initial_window_size,
                 H2O_HTTP2_SETTINGS_HOST.max_frame_size, conn->peer_settings.header_table_size, conn->peer_settings.enable_push,
                 conn->peer_settings.max_concurrent_streams, conn->peer_settings.initial_window_size,
                 conn->peer_settings.max_frame_size, conn->_input_window._avail, conn->_write.window._avail);

    /* encode streams */
    {
        h2o_http2_stream_t *stream;
        kh_foreach_value(conn->streams, stream, {
            const char *state_string = get_debug_state_string(stream);
            if (state_string == NULL)
                continue;

            append_chunk(&req->pool, &state->json, "\n"
                                                   "    \"%" PRIu32 "\": {\n"
                                                   "      \"state\": \"%s\",\n"
                                                   "      \"flowIn\": %zd,\n"
                                                   "      \"flowOut\": %zd,\n"
                                                   "      \"dataIn\": %zu,\n"
                                                   "      \"dataOut\": %zu,\n"
                                                   "      \"created\": %" PRIu64 "\n"
                                                   "    },",
                         stream->stream_id, state_string, stream->input_window._avail, stream->output_window._avail,
                         (stream->_req_body == NULL ? 0 : stream->_req_body->size), stream->req.bytes_sent,
                         (uint64_t)stream->req.timestamps.request_begin_at.tv_sec);
        });

        if (conn->streams->size > 0) {
            // remove the last commna
            --state->json.entries[state->json.size - 1].len;
        }
    }

    append_chunk(&req->pool, &state->json, "\n"
                                           "  }");

    if (hpack_enabled) {
        /* encode inbound header table */
        append_chunk(&req->pool, &state->json, ",\n"
                                               "  \"hpack\": {\n"
                                               "    \"inboundTableSize\": %zd,\n"
                                               "    \"inboundDynamicHeaderTable\": [",
                     conn->_input_header_table.num_entries);
        append_header_table_chunks(&req->pool, &state->json, &conn->_input_header_table);

        /* encode outbound header table */
        append_chunk(&req->pool, &state->json, "\n"
                                               "    ],\n"
                                               "    \"outboundTableSize\": %zd,\n"
                                               "    \"outboundDynamicHeaderTable\": [",
                     conn->_output_header_table.num_entries);
        append_header_table_chunks(&req->pool, &state->json, &conn->_output_header_table);

        append_chunk(&req->pool, &state->json, "\n"
                                               "    ]\n"
                                               "  }");
    }

    append_chunk(&req->pool, &state->json, "\n"
                                           "}\n");

    return state;
}
