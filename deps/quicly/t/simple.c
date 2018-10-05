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

static quicly_conn_t *client, *server;

static void test_handshake(void)
{
    quicly_datagram_t *packets[32];
    size_t num_packets, num_decoded;
    quicly_decoded_packet_t decoded[32];
    int ret, i;

    /* send CH */
    ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
    ok(ret == 0);
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(client, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets == 1);
    ok(packets[0]->data.len == 1280);

    /* receive CH, send handshake upto ServerFinished */
    num_decoded = decode_packets(decoded, packets, num_packets, 8);
    ok(num_decoded == 1);
    ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, decoded);
    ok(ret == 0);
    free_packets(packets, num_packets);
    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(server));
    num_packets = sizeof(packets) / sizeof(packets[0]);
    ret = quicly_send(server, packets, &num_packets);
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive ServerFinished */
    num_decoded = decode_packets(decoded, packets, num_packets, 0);
    for (i = 0; i != num_decoded; ++i) {
        ret = quicly_receive(client, decoded + i);
        ok(ret == 0);
    }
    free_packets(packets, num_packets);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));
}

static void simple_http(void)
{
    const char *req = "GET / HTTP/1.0\r\n\r\n", *resp = "HTTP/1.0 200 OK\r\n\r\nhello world";
    quicly_stream_t *client_stream, *server_stream;
    int ret;

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    ok(client_stream->stream_id == 0);
    client_stream->on_update = on_update_noop;
    quicly_sendbuf_write(&client_stream->sendbuf, req, strlen(req), NULL);
    quicly_sendbuf_shutdown(&client_stream->sendbuf);
    ok(quicly_num_streams(client) == 2);

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    ok(recvbuf_is(&server_stream->recvbuf, req));
    ok(quicly_recvbuf_get_error(&server_stream->recvbuf) == QUICLY_STREAM_ERROR_FIN_CLOSED);
    quicly_sendbuf_write(&server_stream->sendbuf, resp, strlen(resp), NULL);
    quicly_sendbuf_shutdown(&server_stream->sendbuf);
    ok(quicly_num_streams(server) == 2);

    transmit(server, client);

    ok(recvbuf_is(&client_stream->recvbuf, resp));
    ok(quicly_recvbuf_get_error(&client_stream->recvbuf) == QUICLY_STREAM_ERROR_FIN_CLOSED);
    quicly_close_stream(client_stream);
    ok(quicly_num_streams(client) == 1);
    assert(!quicly_stream_is_closable(server_stream));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    assert(quicly_stream_is_closable(server_stream));
    quicly_close_stream(server_stream);
    ok(quicly_num_streams(server) == 1);
}

static void test_rst_then_close(void)
{
    quicly_stream_t *client_stream, *server_stream;
    uint64_t stream_id;
    int ret;

    /* client sends STOP_SENDING and RST_STREAM */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_stream->on_update = on_update_noop;
    stream_id = client_stream->stream_id;
    quicly_reset_stream(client_stream, 12345);
    quicly_request_stop(client_stream, 12345);

    transmit(client, server);

    /* server sends RST_STREAM and ACKs to the packets received */
    ok(!quicly_stream_is_closable(client_stream));
    ok(quicly_num_streams(server) == 2);
    server_stream = quicly_get_stream(server, stream_id);
    ok(server_stream != NULL);
    ok(server_stream->_send_aux.rst.sender_state == QUICLY_SENDER_STATE_SEND);

    transmit(server, client);

    /* client closes the stream */
    ok(!quicly_stream_is_closable(server_stream));
    ok(quicly_stream_is_closable(client_stream));
    quicly_close_stream(client_stream);
    ok(quicly_num_streams(client) == 1);
    ok(quicly_num_streams(server) == 2);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    /* server becomes ready to close the stream, by receiving the ACK to the RST_STREAM */
    ok(quicly_stream_is_closable(server_stream));
    quicly_close_stream(server_stream);
    ok(quicly_num_streams(server) == 1);
}

static void tiny_stream_window(void)
{
    quicly_initial_max_stream_data_t initial_max_stream_data_orig = quic_ctx.initial_max_stream_data;
    quicly_stream_t *client_stream, *server_stream;
    int ret;

    quic_ctx.initial_max_stream_data = (quicly_initial_max_stream_data_t){4, 4, 4};

    ok(max_data_is_equal(client, server));

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_stream->on_update = on_update_noop;
    client_stream->_send_aux.max_stream_data = 4;

    quicly_sendbuf_write(&client_stream->sendbuf, "hello world", 11, NULL);
    quicly_sendbuf_shutdown(&client_stream->sendbuf);

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    ok(recvbuf_is(&server_stream->recvbuf, "hel"));
    ok(quicly_recvbuf_available(&server_stream->recvbuf) == 1);
    ok(server_stream->recvbuf.data.len == 1);

    transmit(server, client);
    transmit(client, server);

    ok(recvbuf_is(&server_stream->recvbuf, "lo w"));
    ok(quicly_recvbuf_available(&server_stream->recvbuf) == 0);
    ok(server_stream->recvbuf.data.len == 0);

    transmit(server, client);
    transmit(client, server);

    ok(recvbuf_is(&server_stream->recvbuf, "orld"));
    ok(server_stream->recvbuf.data.len == 0);
    ok(quicly_recvbuf_get_error(&server_stream->recvbuf) == QUICLY_STREAM_ERROR_FIN_CLOSED);

    quicly_request_stop(client_stream, 12345);

    transmit(client, server);

    /* client should have sent ACK(FIN),STOP_RESPONDING and waiting for response */
    ok(quicly_num_streams(client) == 2);

    transmit(server, client);

    /* client can close the stream when it receives an RST_STREAM in response */
    ok(quicly_stream_is_closable(client_stream));
    quicly_close_stream(client_stream);
    ok(quicly_num_streams(client) == 1);
    ok(quicly_num_streams(server) == 2);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    /* server should have recieved ACK to the RST_STREAM it has sent */
    ok(quicly_stream_is_closable(server_stream));
    quicly_close_stream(server_stream);
    ok(quicly_num_streams(server) == 1);

    ok(max_data_is_equal(client, server));

    quic_ctx.initial_max_stream_data = initial_max_stream_data_orig;
}

static void test_rst_during_loss(void)
{
    quicly_initial_max_stream_data_t initial_max_stream_data_orig = quic_ctx.initial_max_stream_data;
    quicly_stream_t *client_stream, *server_stream;
    quicly_datagram_t *reordered_packet;
    int ret;
    uint64_t max_data_at_start, tmp;

    quic_ctx.initial_max_stream_data = (quicly_initial_max_stream_data_t){4, 4, 4};

    ok(max_data_is_equal(client, server));
    quicly_get_max_data(client, NULL, &max_data_at_start, NULL);

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_stream->on_update = on_update_noop;
    client_stream->_send_aux.max_stream_data = 4;
    quicly_sendbuf_write(&client_stream->sendbuf, "hello world", 11, NULL);

    /* transmit first 4 bytes */
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    ok(recvbuf_is(&server_stream->recvbuf, "hell"));

    /* transmit ack */
    transmit(server, client);

    { /* loss of 4 bytes */
        size_t cnt = 1;
        ret = quicly_send(client, &reordered_packet, &cnt);
        ok(ret == 0);
        ok(cnt == 1);
    }

    /* transmit RST_STREAM */
    quicly_reset_stream(client_stream, 12345);
    transmit(client, server);

    ok(quicly_recvbuf_get_error(&server_stream->recvbuf) == 12345);
    quicly_reset_stream(server_stream, 12345);

    quicly_get_max_data(client, NULL, &tmp, NULL);
    ok(tmp == max_data_at_start + 8);
    quicly_get_max_data(server, NULL, NULL, &tmp);
    ok(tmp == max_data_at_start + 8);

    {
        quicly_decoded_packet_t decoded;
        decode_packets(&decoded, &reordered_packet, 1, 8);
        ret = quicly_receive(server, &decoded);
        ok(ret == 0);
    }

    quicly_get_max_data(server, NULL, NULL, &tmp);
    ok(tmp == max_data_at_start + 8);

    /* RST_STREAM for downstream is sent */
    transmit(server, client);
    ok(quicly_recvbuf_get_error(&client_stream->recvbuf) != QUICLY_STREAM_ERROR_IS_OPEN);
    ok(quicly_stream_is_closable(client_stream));
    quicly_close_stream(client_stream);
    ok(quicly_num_streams(client) == 1);
    ok(quicly_num_streams(server) == 2);
    ok(!quicly_stream_is_closable(server_stream));
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    ok(quicly_stream_is_closable(server_stream));
    quicly_close_stream(server_stream);
    ok(quicly_num_streams(server) == 1);

    quicly_get_max_data(server, NULL, NULL, &tmp);
    ok(tmp == max_data_at_start + 8);
    ok(max_data_is_equal(client, server));

    quic_ctx.initial_max_stream_data = initial_max_stream_data_orig;
}

static void tiny_connection_window(void)
{
    uint32_t initial_max_data_kb_orig = quic_ctx.initial_max_data;
    quicly_stream_t *client_stream, *server_stream;
    size_t i;
    int ret;
    char testdata[1025];

    quic_ctx.initial_max_data = 1024;
    for (i = 0; i < 1024 / 16; ++i)
        strcpy(testdata + i * 16, "0123456789abcdef");

    { /* create connection and write 16KB */
        quicly_datagram_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, NULL);
        ok(ret == 0);
        ret = quicly_open_stream(client, &client_stream, 0);
        ok(ret == 0);
        for (i = 0; i < 16; ++i)
            quicly_sendbuf_write(&client_stream->sendbuf, testdata, 1024, NULL);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        decode_packets(&decoded, &raw, 1, 8);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, NULL, &decoded);
        ok(ret == 0);
        free_packets(&raw, 1);
    }

    transmit(server, client);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    ok(recvbuf_is(&server_stream->recvbuf, testdata));
    ok(server_stream->recvbuf.data.len == 0);

    for (i = 1; i < 16; ++i) {
        transmit(server, client);
        transmit(client, server);
        ok(recvbuf_is(&server_stream->recvbuf, testdata));
        ok(server_stream->recvbuf.data.len == 0);
    }

    quic_ctx.initial_max_data = initial_max_data_kb_orig;
}

void test_simple(void)
{
    subtest("handshake", test_handshake);
    subtest("simple-http", simple_http);
    subtest("rst-then-close", test_rst_then_close);
    subtest("tiny-stream-window", tiny_stream_window);
    subtest("rst-during-loss", test_rst_during_loss);
    subtest("tiny-connection-window", tiny_connection_window);
}
