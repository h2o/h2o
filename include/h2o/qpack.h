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

h2o_qpack_decoder_t *h2o_qpack_create_decoder(uint32_t header_table_size, uint16_t max_blocked);
void h2o_qpack_destroy_decoder(h2o_qpack_decoder_t *qpack);
int h2o_qpack_decoder_handle_input(h2o_qpack_decoder_t *qpack, int64_t **unblocked_stream_ids, size_t *num_unblocked,
                                   const uint8_t **src, const uint8_t *src_end, const char **err_desc);
size_t h2o_qpack_decoder_send_state_sync(h2o_qpack_decoder_t *qpack, uint8_t *outbuf);
size_t h2o_qpack_decoder_send_stream_cancel(h2o_qpack_decoder_t *qpack, uint8_t *outbuf, int64_t stream_id);

int h2o_qpack_parse_request(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, h2o_iovec_t *method,
                            const h2o_url_scheme_t **scheme, h2o_iovec_t *authority, h2o_iovec_t *path, h2o_headers_t *headers,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests, uint8_t *outbuf,
                            size_t *outbufsize, const uint8_t *src, size_t len, const char **err_desc);
/**
 * outbuf should be at least H2O_HPACK_ENCODE_INT_MAX_LENGTH long
 */
int h2o_qpack_parse_response(h2o_mem_pool_t *pool, h2o_qpack_decoder_t *qpack, int64_t stream_id, int *status,
                             h2o_headers_t *headers, uint8_t *outbuf, size_t *outbufsize, const uint8_t *src, size_t len,
                             const char **err_desc);

h2o_qpack_encoder_t *h2o_qpack_create_encoder(uint32_t header_table_size, uint16_t max_blocked);
void h2o_qpack_destroy_encoder(h2o_qpack_encoder_t *qpack);
/**
 * Handles packets sent to the QPACK encoder (i.e., the bytes carried by the "decoder" stream)
 * @param qpack can be NULL
 */
int h2o_qpack_encoder_handle_input(h2o_qpack_encoder_t *qpack, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
/**
 * flattens a QPACK request.
 * @param encoder_buf optional parameter pointing to buffer to store encoder stream data. Set to NULL to avoid blocking.
 */
h2o_iovec_t h2o_qpack_flatten_request(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, int64_t stream_id,
                                      h2o_byte_vector_t *encoder_buf, h2o_iovec_t method, const h2o_url_scheme_t *scheme,
                                      h2o_iovec_t authority, h2o_iovec_t path, const h2o_header_t *headers, size_t num_headers);
h2o_iovec_t h2o_qpack_flatten_response(h2o_qpack_encoder_t *qpack, h2o_mem_pool_t *pool, int64_t stream_id,
                                       h2o_byte_vector_t *encoder_buf, int status, const h2o_header_t *headers, size_t num_headers,
                                       const h2o_iovec_t *server_name, size_t content_length);

#endif
