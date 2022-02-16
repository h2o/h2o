/*
 * Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__standalone_h
#define h2o__standalone_h

#include <openssl/ssl.h>
#include "quicly.h"

#if defined(SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB) && !defined(OPENSSL_NO_TLSEXT)
#define H2O_USE_SESSION_TICKETS 1
#else
#define H2O_USE_SESSION_TICKETS 0
#endif

void init_openssl(void);

struct st_h2o_quic_resumption_args_t {
    int is_clustered;
};

void ssl_setup_session_resumption(SSL_CTX **contexts, size_t num_contexts, struct st_h2o_quic_resumption_args_t *quic_args,
                                  h2o_barrier_t *startup_barrier);
void ssl_setup_session_resumption_ptls(ptls_context_t *ptls, quicly_context_t *quic);
int ssl_session_resumption_on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);

extern quicly_cid_encryptor_t quic_cid_encryptor;
int quic_decrypt_address_token(quicly_address_token_plaintext_t *pt, ptls_iovec_t input, const char **err_desc);
ptls_aead_context_t *quic_get_address_token_encryptor(uint8_t *prefix);
extern quicly_generate_resumption_token_t quic_resumption_token_generator;

struct st_h2o_quic_forward_node_t {
    uint64_t id;
    int fd;
};

typedef H2O_VECTOR(struct st_h2o_quic_forward_node_t) h2o_quic_forward_node_vector_t;

#endif
