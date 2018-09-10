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

#include "quicly/sendbuf.h"

typedef struct st_h2o_qpack_context_t {
    size_t header_table_size;
} h2o_qpack_context_t;

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

h2o_qpack_decoder_t *h2o_qpack_create_decoder(h2o_qpack_context_t *ctx);
void h2o_qpack_destroy_decoder(h2o_qpack_decoder_t *qpack);
int h2o_qpack_decoder_handle_input(h2o_qpack_decoder_t *qpack, const uint8_t **input, size_t input_len, const char **err_desc);
int h2o_qpack_decoder_send_state_sync(h2o_qpack_decoder_t *qpack, quicly_sendbuf_t *sendbuf);
int h2o_qpack_decoder_send_header_ack(h2o_qpack_decoder_t *qpack, quicly_sendbuf_t *sendbuf, int64_t stream_id);
int h2o_qpack_decoder_send_stream_cancel(h2o_qpack_decoder_t *qpack, quicly_sendbuf_t *sendbuf, int64_t stream_id);

int h2o_qpack_parse_headers(h2o_req_t *req, h2o_qpack_decoder_t *qpack, int64_t stream_id, const uint8_t *src, size_t len,
                            int *pseudo_header_exists_map, size_t *content_length, h2o_cache_digests_t **digests,
                            quicly_sendbuf_t *sendbuf, const char **err_desc);

h2o_qpack_encoder_t *h2o_qpack_create_encoder(h2o_qpack_context_t *ctx);
void h2o_qpack_destroy_encoder(h2o_qpack_encoder_t *qpack);
int h2o_qpack_encoder_handle_input(h2o_qpack_encoder_t *qpack, const uint8_t **input, size_t input_len, const char **err_desc);
int h2o_qpack_flatten_headers(h2o_qpack_encoder_t *qpack, quicly_sendbuf_t *sendbuf, h2o_header_t *headers, size_t num_headers);

#endif
