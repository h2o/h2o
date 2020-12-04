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
    int ret, i;

    /* send CH */
    ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0), NULL,
                         NULL);
    ok(ret == 0);
    num_packets = PTLS_ELEMENTSOF(packets);
    ret = quicly_send(client, &dest, &src, packets, &num_packets, packetsbuf, sizeof(packetsbuf));
    ok(ret == 0);
    ok(num_packets == 1);
    ok(packets[0].iov_len == 1280);

    /* receive CH, send handshake upto ServerFinished */
    num_decoded = decode_packets(decoded, packets, num_packets);
    ok(num_decoded == 1);
    ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, decoded, NULL, new_master_id(), NULL);
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
    int ret;

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
    int ret;

    /* client sends STOP_SENDING and RESET_STREAM */
    ret = quicly_open_stream(client, &client_stream, 0);
    ok(ret == 0);
    stream_id = client_stream->stream_id;
    client_streambuf = client_stream->data;
    quicly_reset_stream(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));
    quicly_request_stop(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(54321));

    transmit(client, server);

    /* server sends RESET_STREAM and ACKs to the packets received */
    ok(quicly_num_streams(server) == 1);
    server_stream = quicly_get_stream(server, stream_id);
    ok(server_stream != NULL);
    server_streambuf = server_stream->data;
    ok(quicly_sendstate_transfer_complete(&server_stream->sendstate));
    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));
    ok(server_streambuf->error_received.stop_sending == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(54321));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(server, client);

    /* client closes the stream */
    ok(client_streambuf->is_detached);
    ok(client_streambuf->error_received.stop_sending == -1);
    ok(client_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(54321));
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
    int ret;

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

    transmit(client, server);

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
    int ret;

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
    int ret;

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

    quicly_request_stop(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));

    transmit(client, server);

    quicly_get_stats(client, &stats);
    ok(stats.num_frames_sent.stream_data_blocked == 2);

    /* client should have sent ACK(FIN),STOP_RESPONDING and waiting for response */
    ok(quicly_num_streams(client) == 1);
    ok(!server_streambuf->is_detached);
    ok(server_streambuf->error_received.stop_sending == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));
    ok(quicly_sendstate_transfer_complete(&server_stream->sendstate));

    transmit(server, client);

    /* client can close the stream when it receives an RESET_STREAM in response */
    ok(client_streambuf->is_detached);
    ok(client_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));
    ok(client_streambuf->error_received.stop_sending == -1);
    ok(quicly_num_streams(client) == 0);
    ok(quicly_num_streams(server) == 1);

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);

    /* server should have recieved ACK to the RESET_STREAM it has sent */
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
    int ret;
    uint64_t max_data_at_start, tmp;

    quic_ctx.transport_params.max_stream_data = (quicly_max_stream_data_t){4, 4, 4};

    ok(max_data_is_equal(client, server));
    quicly_get_max_data(client, NULL, &max_data_at_start, NULL);

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
    quicly_reset_stream(client_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));
    ok(quicly_sendstate_transfer_complete(&client_stream->sendstate));
    transmit(client, server);

    ok(quicly_recvstate_transfer_complete(&server_stream->recvstate));
    ok(server_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345));
    quicly_reset_stream(server_stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(54321));
    ok(!server_streambuf->is_detached);
    ok(quicly_sendstate_transfer_complete(&server_stream->sendstate));

    quicly_get_max_data(client, NULL, &tmp, NULL);
    ok(tmp == max_data_at_start + 8);
    quicly_get_max_data(server, NULL, NULL, &tmp);
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

    quicly_get_max_data(server, NULL, NULL, &tmp);
    ok(tmp == max_data_at_start + 8);

    /* RESET_STREAM for downstream is sent */
    transmit(server, client);
    ok(client_streambuf->error_received.reset_stream == QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(54321));
    ok(client_streambuf->is_detached);
    ok(quicly_num_streams(client) == 0);
    ok(quicly_num_streams(server) == 1);
    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;
    transmit(client, server);
    ok(server_streambuf->is_detached);
    ok(quicly_num_streams(server) == 0);

    quicly_get_max_data(server, NULL, NULL, &tmp);
    ok(tmp == max_data_at_start + 8);
    ok(max_data_is_equal(client, server));

    quic_ctx.transport_params.max_stream_data = max_stream_data_orig;
}

static uint16_t test_close_error_code;

static void test_closed_by_remote(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err, uint64_t frame_type,
                                  const char *reason, size_t reason_len)
{
    ok(QUICLY_ERROR_IS_QUIC_APPLICATION(err));
    test_close_error_code = QUICLY_ERROR_GET_ERROR_CODE(err);
    ok(frame_type == UINT64_MAX);
    ok(reason_len == 8);
    ok(memcmp(reason, "good bye", 8) == 0);
}

static void test_close(void)
{
    quicly_closed_by_remote_t closed_by_remote = {test_closed_by_remote}, *orig_closed_by_remote = quic_ctx.closed_by_remote;
    quicly_address_t dest, src;
    struct iovec datagram;
    uint8_t datagram_buf[quic_ctx.transport_params.max_udp_payload_size];
    size_t num_datagrams;
    int64_t client_timeout, server_timeout;
    int ret;

    quic_ctx.closed_by_remote = &closed_by_remote;

    /* client sends close */
    ret = quicly_close(client, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(12345), "good bye");
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
        ok(test_close_error_code == 12345);
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
    quic_ctx.closed_by_remote = orig_closed_by_remote;
}

static void tiny_connection_window(void)
{
    uint64_t max_data_orig = quic_ctx.transport_params.max_data;
    quicly_stream_t *client_stream, *server_stream;
    test_streambuf_t *client_streambuf, *server_streambuf;
    size_t i;
    int ret;
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
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &dest, &src, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        ok(quicly_get_first_timeout(client) > quic_ctx.now->cb(quic_ctx.now));
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
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

void test_simple(void)
{
    subtest("handshake", test_handshake);
    subtest("simple-http", simple_http);
    subtest("reset-then-close", test_reset_then_close);
    subtest("send-then-close", test_send_then_close);
    subtest("reset-after-close", test_reset_after_close);
    subtest("tiny-stream-window", tiny_stream_window);
    subtest("reset-during-loss", test_reset_during_loss);
    subtest("close", test_close);
    subtest("tiny-connection-window", tiny_connection_window);
}
