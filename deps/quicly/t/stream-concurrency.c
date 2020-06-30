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
#include <string.h>
#include "quicly/streambuf.h"
#include "test.h"

void test_stream_concurrency(void)
{
    quicly_conn_t *client, *server;
    size_t limit = quic_ctx.transport_params.max_streams_bidi;
    quicly_stream_t *client_streams[limit + 2], *server_stream;
    test_streambuf_t *client_streambufs[limit + 1], *server_streambuf;
    size_t i;
    int ret;

    { /* connect */
        quicly_address_t dest, src;
        struct iovec raw;
        uint8_t rawbuf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &dest, &src, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        ok(decode_packets(&decoded, &raw, 1) == 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
        ok(ret == 0);
        transmit(server, client);
    }

    /* open as many streams as we can */
    for (i = 0; i < limit + 1; ++i) {
        ret = quicly_open_stream(client, client_streams + i, 0);
        assert(ret == 0);
        client_streambufs[i] = client_streams[i]->data;
        if (client_streams[i]->streams_blocked)
            break;
        ret = quicly_streambuf_egress_write(client_streams[i], "hello", 5);
        assert(ret == 0);
    }
    ok(i == limit);

    transmit(client, server);
    transmit(server, client);

    /* the last stream is still ID-blocked after 1RT */
    ok(client_streams[i]->streams_blocked);

    /* reset one stream in both directions and close on the client-side */
    server_stream = quicly_get_stream(server, client_streams[i - 1]->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    quicly_reset_stream(client_streams[i - 1], QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(123));
    quicly_request_stop(client_streams[i - 1], QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(456));
    transmit(client, server);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(123));
    ok(server_streambuf->error_received.stop_sending == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(456));
    ok(!server_streambuf->is_detached); /* haven't gotten ACK for reset */
    ok(client_streambufs[i - 1]->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(456));
    ok(client_streambufs[i - 1]->is_detached);

    /* the last stream is still ID-blocked */
    ok(client_streams[i]->streams_blocked);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    transmit(server, client);

    /* we would have free room now that RST of the server-sent side is ACKed */
    ok(server_streambuf->is_detached);
    ok(!client_streams[i]->streams_blocked);
    ++i;

    /* but we cannot open one more */
    ret = quicly_open_stream(client, client_streams + i, 0);
    ok(ret == 0);
    ok(client_streams[i]->streams_blocked);

    quicly_free(client);
    quicly_free(server);
}
