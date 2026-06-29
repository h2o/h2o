/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#ifndef h2o__qpack_h
#define h2o__qpack_h

#include "h2o/hpack.h"

typedef struct st_h2o_qpack_decoder_t h2o_qpack_decoder_t;
typedef struct st_h2o_qpack_encoder_t h2o_qpack_encoder_t;

extern const char *h2o_qpack_err_header_name_too_long;
extern const char *h2o_qpack_err_header_value_too_long;
extern const char *h2o_qpack_err_header_exceeds_table_size;
extern const char *h2o_qpack_err_invalid_max_size;
extern const char *h2o_qpack_err_invalid_static_reference;
extern const char *h2o_qpack_err_invalid_dynamic_reference;
extern const char *h2o_qpack_err_invalid_duplicate;
extern const char *h2o_qpack_err_invalid_pseudo_header;

/**
 * Field-section statistics accumulated by QPACK parse and flatten functions. Callers are responsible for initializing or resetting
 * the struct; QPACK functions *updates* the stats for the field section being processed. Counts and byte sums cover every field in
 * the section, including pseudo-header fields (`:method`, `:status` etc.) and any synthesized fields the encoder adds
 * (`server`, `content-length`).
 */
typedef struct st_h2o_qpack_section_stats_t {
    /**
     * number of fields
     */
    size_t count;
    /**
     * sum of (name.len + value.len) over all fields
     */
    size_t text_bytes;
} h2o_qpack_section_stats_t;

h2o_qpack_decoder_t *h2o_qpack_create_decoder(uint32_t header_table_size, uint64_t max_blocked);
void h2o_qpack_destroy_decoder(h2o_qpack_decoder_t *qpack);
/**
 * This function processes a stream of QPACK encoder instructions provided in [*src, src_end), and updates `*src` to point to the
 * beginning of the first partial instruction being found.
 * This decoder does not enforce its own limits to the instruction size. Instead, it relies on the caller's receive window to be
 * set to `h2o_http3_calc_min_flow_control_size(H2O_MAX_REQLEN)` and flow control to block encoder instructions that exceed that
 * (see the assert_literal_length function in lib/http3/qpack.c).
 */
int h2o_qpack_decoder_handle_input(h2o_qpack_decoder_t *qpack, uint64_t *insert_count, const uint8_t **src, const uint8_t *src_end,
                                   const char **err_desc);
size_t h2o_qpack_decoder_send_state_sync(h2o_qpack_decoder_t *qpack, uint8_t *outbuf);
size_t h2o_qpack_decoder_send_stream_cancel(h2o_qpack_decoder_t *qpack, uint8_t *outbuf, int64_t stream_id);

/**
 * Parses a QPACK request. The input should be the *payload* of the HTTP/3 HEADERS frame. `num_blocked` is the caller's current
 * count of header sections that are blocked on dynamic-table references; it is compared against the decoder's negotiated
 * max_blocked to decide whether one more may be parked. If the decoder allows blocked streams, `blocked_ref` must be non-NULL;
 * when the field section is blocked, returns success with `*blocked_ref` set to the Required Insert Count. When the decoder
 * does not allow blocked streams, `blocked_ref` may be NULL and a blocked field section is treated as a decompression error.
 */
int h2o_qpack_parse_request(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, h2o_iovec_t *method,
                            const h2o_url_scheme_t **scheme, h2o_iovec_t *authority, h2o_iovec_t *path, h2o_iovec_t *protocol,
                            h2o_headers_t *headers, int *pseudo_header_exists_map, size_t *content_length, h2o_iovec_t *expect,
                            h2o_cache_digests_t **digests, h2o_iovec_t *datagram_flow_id, uint64_t num_blocked,
                            uint64_t *blocked_ref, h2o_qpack_section_stats_t *stats_updated, uint8_t *outbuf, size_t *outbufsize,
                            const uint8_t *src, size_t len, const char **err_desc);
/**
 * Parses a QPACK response. The input should be the *payload* of the HTTP/3 HEADERS frame. `outbuf` should be at least
 * H2O_HPACK_ENCODE_INT_MAX_LENGTH long. `num_blocked` and `blocked_ref` follow the same rules as `h2o_qpack_parse_request`.
 */
int h2o_qpack_parse_response(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, int *status,
                             h2o_headers_t *headers, h2o_iovec_t *datagram_flow_id, uint64_t num_blocked, uint64_t *blocked_ref,
                             h2o_qpack_section_stats_t *stats_updated, uint8_t *outbuf, size_t *outbufsize, const uint8_t *src,
                             size_t len, const char **err_desc);

h2o_qpack_encoder_t *h2o_qpack_create_encoder(uint32_t header_table_size, uint64_t max_blocked);
void h2o_qpack_destroy_encoder(h2o_qpack_encoder_t *qpack);
/**
 * Handles packets sent to the QPACK encoder (i.e., the bytes carried by the "decoder" stream)
 * @param qpack can be NULL
 */
int h2o_qpack_encoder_handle_input(h2o_qpack_encoder_t *qpack, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
/**
 * Flattens a QPACK request. The output includes the HTTP/3 frame header.
 * @param encoder_buf optional parameter pointing to buffer to store encoder stream data. Set to NULL to avoid blocking.
 */
h2o_iovec_t h2o_qpack_flatten_request(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, int64_t stream_id,
                                      h2o_byte_vector_t *encoder_buf, h2o_iovec_t method, const h2o_url_scheme_t *scheme,
                                      h2o_iovec_t authority, h2o_iovec_t path, h2o_iovec_t protocol, const h2o_header_t *headers,
                                      size_t num_headers, h2o_iovec_t datagram_flow_id, h2o_qpack_section_stats_t *stats_updated);
/**
 * Flattens a QPACK response. The output includes the HTTP/3 frame header.
 */
h2o_iovec_t h2o_qpack_flatten_response(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, int64_t stream_id,
                                       h2o_byte_vector_t *encoder_buf, int status, const h2o_header_t *headers, size_t num_headers,
                                       const h2o_iovec_t *server_name, size_t content_length, h2o_iovec_t datagram_flow_id,
                                       h2o_qpack_section_stats_t *stats_updated, size_t *serialized_header_len);

#endif
