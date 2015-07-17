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

#if defined(SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB) && !defined(OPENSSL_NO_TLSEXT)
#define H2O_USE_SESSION_TICKETS 1
#else
#define H2O_USE_SESSION_TICKETS 0
#endif

void init_openssl(void);
void ssl_setup_session_resumption(SSL_CTX **contexts, size_t num_contexts);
int ssl_session_resumption_on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node);

#endif
