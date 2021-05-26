/*
 * Copyright (c) 2018 Fastly, Kazuho
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
#ifndef h2o__http3_server_h
#define h2o__http3_server_h

#include <sys/socket.h>
#include "quicly.h"
#include "h2o/http3_common.h"
#include "h2o.h"

typedef struct st_h2o_http3_server_ctx_t {
    h2o_quic_ctx_t super;
    h2o_accept_ctx_t *accept_ctx;
    unsigned send_retry : 1;
    h2o_http3_qpack_context_t qpack;
} h2o_http3_server_ctx_t;

extern const h2o_protocol_callbacks_t H2O_HTTP3_SERVER_CALLBACKS;
extern const h2o_http3_conn_callbacks_t H2O_HTTP3_CONN_CALLBACKS;

/**
 * the acceptor callback to be used together with h2o_http3_server_ctx_t
 * @return a pointer to a new connection object upon success, NULL or H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED upon failure.
 */
h2o_http3_conn_t *h2o_http3_server_accept(h2o_http3_server_ctx_t *ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                          quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token,
                                          int skip_tracing, const h2o_http3_conn_callbacks_t *h3_callbacks);
/**
 * amends the quicly context so that it could be used for the server
 */
void h2o_http3_server_amend_quicly_context(h2o_globalconf_t *conf, quicly_context_t *quic);

#endif
