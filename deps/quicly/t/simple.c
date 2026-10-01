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

static quicly_conn_t *client, *server;

static void test_handshake(void)
{
    quicly_address_t dest, src;
    struct iovec packets[8];
    uint8_t packetsbuf[PTLS_ELEMENTSOF(packets) * quic_ctx.transport_params.max_udp_payload_size];
    size_t num_packets, num_decoded;
    quicly_decoded_packet_t decoded[PTLS_ELEMENTSOF(packets) * 4];
    int i;
    quicly_error_t ret;

    /* send CH */
    ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL, NULL);
    ok(ret == 0);
    num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(client, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_packets == 1);
    ok(packets[0].iov_len == 1280);

    /* receive CH, send handshake upto ServerFinished */
    num_decoded = decode_packets(decoded, packets, num_packets);
    ok(num_decoded == 1);
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL, NULL);
    ok(ret == 0);
    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(server));
    num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(server, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive server flight upto ServerFinished, send ClientFinished */
    num_decoded = decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_decoded; ++i) {
        ret = quicly_receive(client, NULL, &fake_address.sa, decoded + i);
        ok(ret == 0);
    }
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));
    num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(client, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_packets != 0);
    ok(ptls_handshake_is_complete(quicly_get_tls(client)));

    /* receive ClientFinished, send HANDSHAKE_DONE */
    num_decoded = decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_decoded; ++i) {
        ret = quicly_receive(server, NULL, &fake_address.sa, decoded + i);
        ok(ret == 0);
    }
    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);
    ok(ptls_handshake_is_complete(quicly_get_tls(server)));
    num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(server, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive HANDSHAKE_DONE, send ACK (after delay) */
    num_decoded = decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_decoded; ++i) {
        ret = quicly_receive(client, NULL, &fake_address.sa, decoded + i);
        ok(ret == 0);
    }
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_get_first_timeout(client) == quic_now + QUICLY_DELAYED_ACK_TIMEOUT);
    quic_now = quicly_get_first_timeout(client);
    num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(client, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_packets != 0);

    /* receive ACK */
    num_decoded = decode_packets(decoded, packets, num_packets);
    for (i = 0; i != num_decoded; ++i) {
        ret = quicly_receive(server, NULL, &fake_address.sa, decoded + i);
        ok(ret == 0);
    }
    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);

    /* both endpoints have nothing to send */
    ok(quicly_get_first_timeout(server) == quic_now + quic_ctx.transport_params.max_idle_timeout);
    ok(quicly_get_first_timeout(client) == quic_now + quic_ctx.transport_params.max_idle_timeout);
}

static void simple_http(void)
{
    const char *req = "GET / HTTP/1.0\r\n\r\n", *resp = "HTTP/1.0 200 OK\r\n\r\nhello world";
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    quicly_error_t ret;

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    ok(client_stream->stream_id == 0);
    client_streambuf = client_stream->data;

    quicly_streambuf_egress_write(client_stream, req, strlen(req));
    quicly_streambuf_egress_shutdown(client_stream);
    ok(quicly_num_streams(client) == 1);

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == -1);
    ok(buffer_is(&server_streambuf->super.ingress, req));
    quicly_streambuf_egress_write(server_stream, resp, strlen(resp));
    quicly_streambuf_egress_shutdown(server_stream);
    ok(quicly_num_streams(server) == 1);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    ok(client_streambuf->is_detached);
    ok(client_streambuf->error_received.reset_stream == -1);
    ok(buffer_is(&client_streambuf->super.ingress, resp));
    ok(quicly_num_streams(client) == 0);
    ok(!server_streambuf->is_detached);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    ok(server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 0);
}

static void test_reset_then_close(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    uint64_t stream_id;
    quicly_error_t ret;

    /* client sends STOP_SENDING and RESET_STREAM */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    stream_id = client_stream->stream_id;
    client_streambuf = client_stream->data;
    quicly_reset_stream(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    quicly_request_stop(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(7654321));

    transmit(client, server);

    /* server sends RESET_STREAM and ACKs to the packets received */
    ok(quicly_num_streams(server) == 1);
    server_stream = quicly_get_stream(server, stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(quicly_sendstate_transfer_complete(&server_stream->sendstate));
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(server_streambuf->error_received.stop_sending == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(7654321));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    /* client closes the stream */
    ok(client_streambuf->is_detached);
    ok(client_streambuf->error_received.stop_sending == -1);
    ok(client_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(7654321));
    ok(quicly_num_streams(client) == 0);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    ok(server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 0);
}

static void test_send_then_close(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    quicly_error_t ret;

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_streambuf = client_stream->data;
    quicly_streambuf_egress_write(client_stream, "hello", 5);

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    assert(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(buffer_is(&server_streambuf->super.ingress, "hello"));
    quicly_streambuf_ingress_shift(server_stream, 5);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    ok(client_stream->sendstate.acked.num_ranges == 1);
    ok(client_stream->sendstate.acked.ranges[0].start == 0);
    ok(client_stream->sendstate.acked.ranges[0].end == 5);
    quicly_streambuf_egress_shutdown(client_stream);
    ok(!quicly_sendstate_is_fully_inflight(&client_stream->sendstate));

    transmit(client, server);
    ok(quicly_sendstate_is_fully_inflight(&client_stream->sendstate));

    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, ""));
    quicly_streambuf_egress_shutdown(server_stream);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    ok(client_streambuf->is_detached);
    ok(!server_streambuf->is_detached);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    ok(server_streambuf->is_detached);
}

static void test_reset_after_close(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    quicly_error_t ret;

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_streambuf = client_stream->data;
    quicly_streambuf_egress_write(client_stream, "hello", 5);

    transmit(client, server);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    assert(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(buffer_is(&server_streambuf->super.ingress, "hello"));
    quicly_streambuf_ingress_shift(server_stream, 5);

    quicly_streambuf_egress_write(client_stream, "world", 5);
    quicly_streambuf_egress_shutdown(client_stream);
    quicly_reset_stream(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(
                                           12345)); /* resetting after indicating shutdown is legal; because we might want to
                                                     * abruptly close a stream with lots of data (up to FIN) */

    transmit(client, server);

    ok(buffer_is(&server_streambuf->super.ingress, ""));
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));

    quicly_streambuf_egress_shutdown(server_stream);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    ok(client_streambuf->is_detached);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    ok(server_streambuf->is_detached);
}

static void tiny_stream_window(void)
{
    quicly_max_stream_data_t max_stream_data_orig = quic_ctx.transport_params.max_stream_data;
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    quicly_stats_t stats;
    quicly_error_t ret;

    quic_ctx.transport_params.max_stream_data = (quicly_max_stream_data_t){4, 4, 4};

    ok(max_data_is_equal(client, server));

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_streambuf = client_stream->data;
    client_stream->_send_aux.max_stream_data = 4;

    quicly_streambuf_egress_write(client_stream, "hello world", 11);
    quicly_streambuf_egress_shutdown(client_stream);

    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.stream_data_blocked == 1);
    ok(stats.num_frames_sent.data_blocked == 0);
    quicly_get_stats(server, &stats);
    ok(stats.num_frames_received.stream_data_blocked == 1);
    ok(stats.num_frames_received.data_blocked == 0);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(buffer_is(&server_streambuf->super.ingress, "hell"));
    quicly_streambuf_ingress_shift(server_stream, 3);

    transmit(server, client);
    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.stream_data_blocked == 2);

    ok(buffer_is(&server_streambuf->super.ingress, "lo w"));
    quicly_streambuf_ingress_shift(server_stream, 4);

    transmit(server, client);
    transmit(client, server);

    ok(buffer_is(&server_streambuf->super.ingress, "orld"));
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));

    quicly_request_stop(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));

    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.stream_data_blocked == 2);

    /* client should have sent ACK(FIN),STOP_RESPONDING and waiting for response */
    ok(quicly_num_streams(client) == 1);
    ok(!server_streambuf->is_detached);
    ok(server_streambuf->error_received.stop_sending == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(quicly_sendstate_transfer_complete(&server_stream->sendstate));

    transmit(server, client);

    /* client can close the stream when it receives an RESET_STREAM in response */
    ok(client_streambuf->is_detached);
    ok(client_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(client_streambuf->error_received.stop_sending == -1);
    ok(quicly_num_streams(client) == 0);
    ok(quicly_num_streams(server) == 1);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    /* server should have received ACK to the RESET_STREAM it has sent */
    ok(server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 0);

    ok(max_data_is_equal(client, server));

    quic_ctx.transport_params.max_stream_data = max_stream_data_orig;
}

static void test_reset_during_loss(void)
{
    quicly_max_stream_data_t max_stream_data_orig = quic_ctx.transport_params.max_stream_data;
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    struct iovec reordered_packet;
    uint8_t reordered_packet_buf[quic_ctx.transport_params.max_udp_payload_size];
    quicly_error_t ret;
    uint64_t max_data_at_start, tmp;

    quic_ctx.transport_params.max_stream_data = (quicly_max_stream_data_t){4, 4, 4};

    ok(max_data_is_equal(client, server));
    quicly_get_max_data(client, NULL, &max_data_at_start, NULL, NULL);

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_streambuf = client_stream->data;
    client_stream->_send_aux.max_stream_data = 4;
    quicly_streambuf_egress_write(client_stream, "hello world", 11);

    /* transmit first 4 bytes */
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(buffer_is(&server_streambuf->super.ingress, "hell"));
    quicly_streambuf_ingress_shift(server_stream, 4);

    /* transmit ack */
    transmit(server, client);

    { /* loss of 4 bytes */
        quicly_address_t dest, src;
        size_t cnt = 1;
        ret = quicly_send(client, &dest, &src, &reordered_packet, &cnt, reordered_packet_buf, sizeof(reordered_packet_buf));
        ok(ret == 0);
        ok(cnt == 1);
    }

    /* transmit RESET_STREAM */
    quicly_reset_stream(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(quicly_sendstate_transfer_complete(&client_stream->sendstate));
    transmit(client, server);

    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    quicly_reset_stream(server_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(7654321));
    ok(!server_streambuf->is_detached);
    ok(quicly_sendstate_transfer_complete(&server_stream->sendstate));

    quicly_get_max_data(client, NULL, &tmp, NULL, NULL);
    ok(tmp == max_data_at_start + 8);
    quicly_get_max_data(server, NULL, NULL, &tmp, NULL);
    ok(tmp == max_data_at_start + 8);

    {
        quicly_decoded_packet_t decoded[4];
        size_t i, num_decoded = decode_packets(decoded, &reordered_packet, 1);
        ok(num_decoded != 0);
        for (i = 0; i < num_decoded; ++i) {
            ret = quicly_receive(server, NULL, &fake_address.sa, decoded + i);
            ok(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED);
        }
    }

    quicly_get_max_data(server, NULL, NULL, &tmp, NULL);
    ok(tmp == max_data_at_start + 8);

    /* RESET_STREAM for downstream is sent */
    transmit(server, client);
    ok(client_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(7654321));
    ok(client_streambuf->is_detached);
    ok(quicly_num_streams(client) == 0);
    ok(quicly_num_streams(server) == 1);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    ok(server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 0);

    quicly_get_max_data(server, NULL, NULL, &tmp, NULL);
    ok(tmp == max_data_at_start + 8);
    ok(max_data_is_equal(client, server));

    quic_ctx.transport_params.max_stream_data = max_stream_data_orig;
}

static void test_closed(quicly_closed_t *self, quicly_conn_t *conn)
{
    uint64_t frame_type;
    const char *reason;
    int is_remote;

    quicly_error_t err = quicly_get_close_reason(conn, &frame_type, &reason, &is_remote);
    ok(err == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(frame_type == UINT64_MAX);
    ok(strcmp(reason, "good bye") == 0);
    ok(is_remote == (conn == server));
}

static void test_close(void)
{
    quicly_closed_t closed = {test_closed}, *orig_closed = quic_ctx.closed;
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t datagram_buf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams;
    int64_t client_timeout, server_timeout;
    quicly_error_t ret;

    quic_ctx.closed = &closed;

    /* client sends close */
    ret = quicly_close(client, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), "good bye");
    ok(ret == 0);
    ok(quicly_get_state(client) == QUICLY_STATE_CLOSING);
    ok(quicly_get_first_timeout(client) <= quic_now);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &datagram, &num_datagrams, datagram_buf, sizeof(datagram_buf));
    assert(num_datagrams == 1);
    client_timeout = quicly_get_first_timeout(client);
    ok(quic_now < client_timeout && client_timeout < quic_now + 1000); /* 3 pto or something */

    { /* server receives close */
        quicly_decoded_packet_t decoded;
        decode_packets(&decoded, &datagram, 1);
        ret = quicly_receive(server, NULL, &fake_address.sa, &decoded);
        ok(ret == 0);
        ok(quicly_get_state(server) == QUICLY_STATE_DRAINING);
        server_timeout = quicly_get_first_timeout(server);
        ok(quic_now < server_timeout && server_timeout < quic_now + 1000); /* 3 pto or something */
    }

    /* nothing sent by the server in response */
    num_datagrams = 1;
    ret = quicly_send(server, &dest, &src, &datagram, &num_datagrams, datagram_buf, sizeof(datagram_buf));
    ok(ret == 0);
    ok(num_datagrams == 0);

    /* endpoints request discarding state after timeout */
    quic_now = client_timeout < server_timeout ? server_timeout : client_timeout;
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &datagram, &num_datagrams, datagram_buf, sizeof(datagram_buf));
    ok(ret == QUICLY_ERROR_FREE_CONNECTION);
    quicly_free(client);
    num_datagrams = 1;
    ret = quicly_send(server, &dest, &src, &datagram, &num_datagrams, datagram_buf, sizeof(datagram_buf));
    ok(ret == QUICLY_ERROR_FREE_CONNECTION);
    quicly_free(server);

    client = NULL;
    server = NULL;
    quic_ctx.closed = orig_closed;
}

static void tiny_connection_window(void)
{
    uint64_t max_data_orig = quic_ctx.transport_params.max_data;
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    size_t i;
    quicly_error_t ret;
    char testdata[1025];

    quic_ctx.transport_params.max_data = 1024;
    for (i = 0; i < 1024 / 16; ++i)
        strcpy(testdata + i * 16, "0123456789abcdef");
    testdata[1024] = '\0';

    { /* create connection and write 16KB */
        quicly_address_t dest, src;
        struct iovec raw;
        uint8_t rawbuf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                             NULL, NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &dest, &src, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        double now;
        quic_ctx.now->cb(quic_ctx.now, &now);
        ok(quicly_get_first_timeout(client) > now);
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL, NULL);
        ok(ret == 0);
    }

    transmit(server, client);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_streambuf = client_stream->data;
    for (i = 0; i < 16; ++i)
        quicly_streambuf_egress_write(client_stream, testdata, strlen(testdata));

    transmit(client, server);

    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(buffer_is(&server_streambuf->super.ingress, testdata));
    quicly_streambuf_ingress_shift(server_stream, strlen(testdata));

    for (i = 1; i < 16; ++i) {
        transmit(server, client);
        transmit(client, server);
        ok(buffer_is(&server_streambuf->super.ingress, testdata));
        quicly_streambuf_ingress_shift(server_stream, strlen(testdata));
    }

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    ok(client_streambuf->super.egress.vecs.size == 0);

    quic_ctx.transport_params.max_data = max_data_orig;
}

static void test_reliable_reset(int deliver_in_order)
{
    quicly_stream_t *client_stream, *server_stream;
    struct iovec *first, *second;
    test_streambuf_t *server_streambuf;
    quicly_address_t dest, src;
    struct iovec prefix_datagram, reset_datagram;
    uint8_t prefixbuf[quic_ctx.transport_params.max_udp_payload_size], resetbuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams;
    quicly_decoded_packet_t decoded;
    quicly_error_t ret;

    /* the client writes the prefix and puts it on the wire, but the datagram is withheld */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "hello", 5);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &prefix_datagram, &num_datagrams, prefixbuf, sizeof(prefixbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);

    /* the stream is reset, the client remaining committed to delivering those 5 bytes */
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 5) == 0);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &reset_datagram, &num_datagrams, resetbuf, sizeof(resetbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);

    /* Deliver the two datagrams. The reset is emitted behind the prefix, hence in-order delivery is what happens in the absence
     * of loss or reordering; either way the application learns of the reset only once the prefix has arrived. */
    first = deliver_in_order ? &prefix_datagram : &reset_datagram;
    second = deliver_in_order ? &reset_datagram : &prefix_datagram;

    /* after the first datagram the transfer is incomplete, and the application has not been notified */
    ok(decode_packets(&decoded, first, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == -1);

    /* the second completes the transfer, and it is then that the reset is surfaced */
    ok(decode_packets(&decoded, second, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(buffer_is(&server_streambuf->super.ingress, "hello"));

    /* the final size is charged to connection-level flow control exactly once */
    ok(max_data_is_equal(client, server));
}

static void test_reliable_reset_pending(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_stats_t before, after;
    quicly_error_t ret;

    /* three bytes are put on the wire */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "abc", 3);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;

    /* the stream is then reset, the commitment covering one byte that has yet to be sent */
    quicly_streambuf_egress_write(client_stream, "d", 1);
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 4) == 0);
    ok(client_stream->sendstate.final_size == 4);

    /* that byte goes out carrying no FIN, the stream being ended by the reset frame that follows it */
    quicly_get_stats(client, &before);
    transmit(client, server);
    quicly_get_stats(client, &after);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at + 1);
    ok(after.num_frames_sent.reset_stream == before.num_frames_sent.reset_stream);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(buffer_is(&server_streambuf->super.ingress, "abcd"));
    /* had a FIN been sent, the transfer would have completed before the reset arrived, leaving it unreported */
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(max_data_is_equal(client, server));
}

static void test_reliable_reset_tail(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_address_t dest, src;
    struct iovec data_datagram, reset_datagram;
    uint8_t databuf[quic_ctx.transport_params.max_udp_payload_size], resetbuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams;
    quicly_decoded_packet_t decoded;
    quicly_error_t ret;

    /* the client puts ten bytes on the wire, the datagram being withheld */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "helloworld", 10);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &data_datagram, &num_datagrams, databuf, sizeof(databuf));
    ok(ret == 0);
    ok(num_datagrams == 1);

    /* it then resets, remaining committed to only the first half of what is in flight; the stream still ends at ten, that being
     * the amount that has been sent and therefore charged to flow control */
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 5) == 0);
    ok(client_stream->sendstate.final_size == 10);
    ok(client_stream->sendstate.reliable_size == 5);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &reset_datagram, &num_datagrams, resetbuf, sizeof(resetbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    /* nothing is left to be sent; the bytes above the reliable size are never retransmitted */
    ok(client_stream->sendstate.pending.num_ranges == 0);

    /* the reset arrives first, telling the server that the stream ends at ten but that five bytes are to be delivered */
    ok(decode_packets(&decoded, &reset_datagram, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(server_stream->recvstate.eos == 5);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));

    /* The withheld bytes then arrive. Only the five committed to are handed to the application; the rest is dropped, the server
     * having returned the credit for it the moment the reset told it those bytes would never be delivered. */
    ok(decode_packets(&decoded, &data_datagram, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.eos == 5);
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(buffer_is(&server_streambuf->super.ingress, "hello"));

    /* the ten bytes are charged to connection-level flow control on both ends */
    ok(max_data_is_equal(client, server));
}

static void test_reliable_reset_lost_tail(void)
{
    quicly_stream_t *client_stream;
    quicly_sendstate_sent_t lost = {5, 10};
    quicly_stats_t before, after;
    quicly_error_t ret;

    /* ten bytes are put on the wire */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "helloworld", 10);
    transmit(client, server);
    ok(client_stream->sendstate.size_inflight == 10);

    /* the second half is then declared lost, and therefore awaits retransmission */
    ok(quicly_sendstate_lost(&client_stream->sendstate, &lost) == 0);
    ok(client_stream->sendstate.pending.num_ranges == 1);
    ok(client_stream->sendstate.pending.ranges[0].start == 5);

    /* resetting with a reliable size of five withdraws them; only the reset is left to be sent */
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 5) == 0);
    ok(client_stream->sendstate.final_size == 10);
    ok(client_stream->sendstate.pending.num_ranges == 0);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT &&
       quicly_sendstate_eos_type(&client_stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET_AT);

    /* hence the reset goes out without the lost bytes being retransmitted */
    quicly_get_stats(client, &before);
    transmit(client, server);
    quicly_get_stats(client, &after);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at + 1);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(client_stream->sendstate.pending.num_ranges == 0);

    /* the same holds when the loss is detected after the reset has been sent, those bytes having been declared acknowledged */
    ok(quicly_sendstate_lost(&client_stream->sendstate, &lost) == 0);
    ok(client_stream->sendstate.pending.num_ranges == 0);
}

static void test_reset_after_shutdown(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_error_t ret;

    /* five bytes are put on the wire */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "hello", 5);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(client_stream->sendstate.size_inflight == 5);

    /* five more are written and the stream is shut down, the FIN having yet to be sent */
    quicly_streambuf_egress_write(client_stream, "world", 5);
    ok(quicly_streambuf_egress_shutdown(client_stream) == 0);
    ok(client_stream->sendstate.final_size == 10);

    /* resetting before the FIN goes out declares the bytes that have been sent as the final size; the peer never saw the value
     * the shutdown had set, and declaring it would announce flow control credit that was never consumed */
    quicly_reset_stream(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(client_stream->sendstate.final_size == 5);
    transmit(client, server);

    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_stream->recvstate.eos == 5);
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(max_data_is_equal(client, server));
}

static void test_reliable_reset_data_below(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_sendstate_sent_t lost = {2, 4};
    quicly_stats_t before, after;
    quicly_error_t ret;

    /* ten bytes are put on the wire, of which [2,4) is then declared lost */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "helloworld", 10);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(quicly_sendstate_lost(&client_stream->sendstate, &lost) == 0);

    /* resetting with a reliable size of five leaves the data below it pending, the reset being tracked outside the ranges */
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 5) == 0);
    ok(client_stream->sendstate.final_size == 10);
    ok(client_stream->sendstate.pending.num_ranges == 1);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT &&
       quicly_sendstate_eos_type(&client_stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET_AT);
    ok(client_stream->sendstate.pending.ranges[0].start == 2 && client_stream->sendstate.pending.ranges[0].end == 4);

    /* both go out; the STREAM frame ends below the final size and so carries no FIN, the reset following it */
    quicly_get_stats(client, &before);
    transmit(client, server);
    quicly_get_stats(client, &after);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream + 1);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at + 1);
    ok(client_stream->sendstate.pending.num_ranges == 0);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(max_data_is_equal(client, server));
}

static void test_reliable_reset_beyond_window(void)
{
    quicly_max_stream_data_t max_stream_data_orig = quic_ctx.transport_params.max_stream_data;
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_stats_t before, after;
    quicly_error_t ret;

    /* the peer advertises a window of four bytes */
    quic_ctx.transport_params.max_stream_data = (quicly_max_stream_data_t){4, 4, 4};

    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    client_stream->_send_aux.max_stream_data = 4;
    quicly_streambuf_egress_write(client_stream, "helloworld", 10);

    /* the stream is reset with a Reliable Size of ten, which is beyond the window; the final size becomes ten as well */
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 10) == 0);
    ok(client_stream->sendstate.final_size == 10);

    /* only the four bytes that fit go out; RESET_STREAM_AT is deferred, as its Final Size would exceed the window (section 4 of
     * draft-ietf-quic-reliable-stream-reset) */
    quicly_get_stats(client, &before);
    transmit(client, server);
    quicly_get_stats(client, &after);
    ok(client_stream->sendstate.size_inflight == 4);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at);
    ok(after.num_frames_sent.stream_data_blocked > before.num_frames_sent.stream_data_blocked);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));

    /* the application reads, the window opens, and only once it reaches the final size does the reset go out */
    quicly_get_stats(client, &before);
    size_t i;
    for (i = 0; i < 10 && server_streambuf->error_received.reset_stream == -1; ++i) {
        quicly_streambuf_ingress_shift(server_stream, quicly_streambuf_ingress_get(server_stream).len);
        quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
        transmit(server, client);
        transmit(client, server);
    }
    quicly_get_stats(client, &after);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at + 1);
    ok(client_stream->sendstate.size_inflight == 10);
    ok(client_stream->_send_aux.max_stream_data >= 10);
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(server_stream->recvstate.eos == 10);

    quic_ctx.transport_params.max_stream_data = max_stream_data_orig;
}

static void test_reliable_reset_after_fin(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_address_t dest, src;
    struct iovec fin_datagram, reset_datagram;
    uint8_t finbuf[quic_ctx.transport_params.max_udp_payload_size], resetbuf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams;
    quicly_decoded_packet_t decoded;
    quicly_stats_t before, after;
    quicly_error_t ret;

    /* the client puts ten bytes and FIN on the wire, the datagram being withheld */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "helloworld", 10);
    ok(quicly_streambuf_egress_shutdown(client_stream) == 0);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &fin_datagram, &num_datagrams, finbuf, sizeof(finbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_INFLIGHT);
    ok(quicly_sendstate_is_fully_inflight(&client_stream->sendstate));

    /* It then resets, committing to the first half. The stream still ends at ten, that being where the FIN in flight says it
     * does, and RESET_STREAM_AT supersedes that FIN. */
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 5) == 0);
    ok(client_stream->sendstate.final_size == 10);
    ok(client_stream->sendstate.reliable_size == 5);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_UNSENT &&
       quicly_sendstate_eos_type(&client_stream->sendstate) == QUICLY_SENDSTATE_EOS_TYPE_RESET_AT);
    ok(!quicly_sendstate_is_fully_inflight(&client_stream->sendstate));
    quicly_get_stats(client, &before);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &reset_datagram, &num_datagrams, resetbuf, sizeof(resetbuf));
    ok(ret == 0);
    ok(num_datagrams == 1);
    quicly_get_stats(client, &after);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at + 1);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(quicly_sendstate_is_fully_inflight(&client_stream->sendstate));

    /* the reset arrives first, telling the server that only five bytes are to be delivered */
    ok(decode_packets(&decoded, &reset_datagram, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(server_stream->recvstate.eos == 5);
    ok(!quicly_recvstate_transfer_complete(&server_stream->recvstate));

    /* the reset is acknowledged ahead of the FIN, so that the acknowledgement of the latter cannot take back what the peer has
     * been told */
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED);
    ok(!quicly_sendstate_transfer_complete(&client_stream->sendstate));

    /* then the withheld datagram; the five bytes above the Reliable Size are dropped */
    ok(decode_packets(&decoded, &fin_datagram, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(buffer_is(&server_streambuf->super.ingress, "hello"));

    /* The acknowledgement of the FIN does not stand in for that of the reset, the marker being tracked by what it tells the peer
     * rather than by the offset it sits at; the send side is complete only once both have arrived. */
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED);
    ok(quicly_sendstate_transfer_complete(&client_stream->sendstate));
    ok(quicly_sendstate_is_fully_inflight(&client_stream->sendstate));
    ok(max_data_is_equal(client, server));

    /* On a second stream the FIN arrives first and is acknowledged, the reset being withheld. Every byte of the stream is then
     * acknowledged, yet the send side is not complete: the peer has not been told that the stream is reset. */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "helloworld", 10);
    ok(quicly_streambuf_egress_shutdown(client_stream) == 0);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &fin_datagram, &num_datagrams, finbuf, sizeof(finbuf));
    ok(ret == 0);
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 5) == 0);
    num_datagrams = 1;
    ret = quicly_send(client, &dest, &src, &reset_datagram, &num_datagrams, resetbuf, sizeof(resetbuf));
    ok(ret == 0);
    ok(decode_packets(&decoded, &fin_datagram, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->sendstate.acked.ranges[0].end == 10);
    ok(client_stream->sendstate.eos_state != QUICLY_SENDSTATE_EOS_STATE_DELIVERED); /* the FIN was superseded */
    ok(!quicly_sendstate_transfer_complete(&client_stream->sendstate));

    /* the reset then arrives, and its acknowledgement completes the send side */
    ok(decode_packets(&decoded, &reset_datagram, 1) == 1);
    ok(quicly_receive(server, NULL, &fake_address.sa, &decoded) == 0);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);
    ok(client_stream->sendstate.eos_state == QUICLY_SENDSTATE_EOS_STATE_DELIVERED);
    ok(quicly_sendstate_transfer_complete(&client_stream->sendstate));
    ok(max_data_is_equal(client, server));
}

static void test_reliable_reset_stop_sending(void)
{
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *server_streambuf;
    quicly_stats_t before, after;
    quicly_error_t ret;

    /* the client writes the first half of the stream and delivers it */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    quicly_streambuf_egress_write(client_stream, "hello", 5);
    transmit(client, server);
    server_stream = quicly_get_stream(server, client_stream->stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;

    /* the client then resets the stream, committing to deliver the second half as well */
    quicly_streambuf_egress_write(client_stream, "world", 5);
    ok(quicly_streambuf_egress_reset(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567), 10) == 0);

    /* before any of that is sent, the server declares that it will not read the stream */
    quicly_request_stop(server_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(7654321));
    transmit(server, client);
    ok(client_stream->sendstate.reliable_size == 0);

    /* hence what the client sends is a RESET_STREAM that retains the error code of the reset, rather than the bytes committed
     * to and a RESET_STREAM_AT */
    quicly_get_stats(client, &before);
    transmit(client, server);
    quicly_get_stats(client, &after);
    ok(after.num_frames_sent.reset_stream == before.num_frames_sent.reset_stream + 1);
    ok(after.num_frames_sent.reset_stream_at == before.num_frames_sent.reset_stream_at);
    ok(after.num_frames_sent.stream == before.num_frames_sent.stream);
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(1234567));
    ok(buffer_is(&server_streambuf->super.ingress, "hello"));
    ok(max_data_is_equal(client, server));
}

void test_simple(void)
{
    uint8_t reset_stream_at_orig = quic_ctx.transport_params.reset_stream_at;
    uint64_t max_streams_bidi_orig = quic_ctx.transport_params.max_streams_bidi;
    quic_ctx.transport_params.reset_stream_at = 1; /* the peer has to advertise it for `reliable-reset` below */
    /* the subtests below share one connection, each of them opening a stream that is never retired; raise the limit so that
     * adding a subtest does not silently exhaust the credit of those that follow */
    quic_ctx.transport_params.max_streams_bidi = 100;

    subtest("handshake", test_handshake);
    subtest("simple-http", simple_http);
    subtest("reset-then-close", test_reset_then_close);
    subtest("send-then-close", test_send_then_close);
    subtest("reset-after-close", test_reset_after_close);
    subtest("tiny-stream-window", tiny_stream_window);
    subtest("reset-during-loss", test_reset_during_loss);
    subtest("reliable-reset", test_reliable_reset, 0);
    subtest("reliable-reset-in-order", test_reliable_reset, 1);
    subtest("reliable-reset-pending", test_reliable_reset_pending);
    subtest("reliable-reset-tail", test_reliable_reset_tail);
    subtest("reliable-reset-lost-tail", test_reliable_reset_lost_tail);
    subtest("reliable-reset-data-below", test_reliable_reset_data_below);
    subtest("reset-after-shutdown", test_reset_after_shutdown);
    subtest("reliable-reset-beyond-window", test_reliable_reset_beyond_window);
    subtest("reliable-reset-after-fin", test_reliable_reset_after_fin);
    subtest("reliable-reset-stop-sending", test_reliable_reset_stop_sending);
    subtest("close", test_close);
    subtest("tiny-connection-window", tiny_connection_window);

    quic_ctx.transport_params.reset_stream_at = reset_stream_at_orig;
    quic_ctx.transport_params.max_streams_bidi = max_streams_bidi_orig;
}
