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
#include "test.h"

void test_stream_concurrency(void)
{
    quicly_conn_t *client, *server;
    size_t limit = quic_ctx.max_streams_bidi;
    quicly_stream_t *client_streams[limit + 1], *server_stream;
    size_t i;
    int ret;

    { /* connect */
        quicly_datagram_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        ok(decode_packets(&decoded, &raw, 1, 8) == 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, &decoded);
        ok(ret == 0);
        free_packets(&raw, 1);
        transmit(server, client);
    }

    /* open as many streams as we can */
    for (i = 0; i < limit + 1; ++i) {
        ret = quicly_open_stream(client, client_streams + i, 0);
        if (ret != 0)
            break;
        client_streams[i]->on_update = on_update_noop;
        quicly_sendbuf_write(&client_streams[i]->sendbuf, "hello", 5, NULL);
    }
    ok(i == limit);

    transmit(client, server);
    transmit(server, client);

    /* cannot open more even after 1RT */
    ret = quicly_open_stream(client, client_streams + i, 0);
    ok(ret != 0);

    /* reset one stream in both directions and close on the client-side */
    server_stream = quicly_get_stream(server, client_streams[i - 1]->stream_id);
    ok(server_stream != NULL);
    quicly_reset_stream(client_streams[i - 1], 0);
    quicly_request_stop(client_streams[i - 1], 0);
    transmit(client, server);
    transmit(server, client);
    ok(quicly_stream_is_closable(client_streams[i - 1]));
    quicly_close_stream(client_streams[i - 1]);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    /* still cannot open more */
    ret = quicly_open_stream(client, client_streams + i, 0);
    ok(ret != 0);

    /* close the stream on the server-side */
    ok(quicly_stream_is_closable(server_stream));
    quicly_close_stream(server_stream);
    transmit(server, client);

    --i;

    /* now we can open one more */
    ret = quicly_open_stream(client, client_streams + i, 0);
    ok(ret == 0);
    ++i;
    ret = quicly_open_stream(client, client_streams + i, 0);
    ok(ret != 0);

    quicly_free(client);
    quicly_free(server);
}
