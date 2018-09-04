/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#ifndef test_h
#define test_h

#include "quicly.h"
#include "picotest.h"

extern int64_t quic_now;
extern quicly_context_t quic_ctx;

void free_packets(quicly_datagram_t **packets, size_t cnt);
size_t decode_packets(quicly_decoded_packet_t *decoded, quicly_datagram_t **raw, size_t cnt, size_t host_cidl);
int on_update_noop(quicly_stream_t *stream);
int on_stream_open_buffering(quicly_stream_t *stream);
int recvbuf_is(quicly_recvbuf_t *buf, const char *s);
size_t transmit(quicly_conn_t *src, quicly_conn_t *dst);
int max_data_is_equal(quicly_conn_t *client, quicly_conn_t *server);

void test_ranges(void);
void test_frame(void);
void test_maxsender(void);
void test_ack(void);
void test_simple(void);
void test_loss(void);
void test_stream_concurrency(void);

#endif
