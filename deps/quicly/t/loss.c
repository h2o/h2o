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
#include "picotls/openssl.h"
#include "test.h"

static quicly_conn_t *client, *server;

static int transmit_cond(quicly_conn_t *src, quicly_conn_t *dst, size_t *num_sent, size_t *num_received, int (*cond)(void),
                         int64_t latency)
{
    quicly_datagram_t *packets[32];
    int ret;

    *num_sent = sizeof(packets) / sizeof(packets[0]);
    if ((ret = quicly_send(src, packets, num_sent)) != 0) {
        fprintf(stderr, "%s: quicly_send: ret=%d\n", __FUNCTION__, ret);
        return ret;
    }
    quic_now += latency;

    *num_received = 0;

    if (*num_sent != 0) {
        size_t i;
        for (i = 0; i != *num_sent; ++i) {
            if (cond()) {
                quicly_decoded_packet_t decoded[4];
                size_t num_decoded = decode_packets(decoded, packets + i, 1), j;
                assert(num_decoded != 0);
                for (j = 0; j != num_decoded; ++j) {
                    ret = quicly_receive(dst, decoded + j);
                    if (!(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED)) {
                        fprintf(stderr, "%s: quicly_receive: i=%zu, j=%zu, ret=%d\n", __FUNCTION__, i, j, ret);
                        return ret;
                    }
                }
                ++*num_received;
            }
        }
        free_packets(packets, *num_sent);
    }
    quic_now += latency;

    return 0;
}

static int cond_true(void)
{
    return 1;
}

static int cond_even_up(void)
{
    static size_t cnt;
    return cnt++ % 2 == 0;
}

static int cond_even_down(void)
{
    static size_t cnt;
    return cnt++ % 2 == 0;
}

static void test_even(void)
{
    quicly_loss_conf_t lossconf = quicly_loss_default_conf;
    size_t num_sent, num_received;
    int ret;

    lossconf.max_tlps = 0;
    quic_ctx.loss = &lossconf;

    quic_now = 0;

    { /* transmit first flight */
        quicly_datagram_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, new_master_id(), NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, &decoded, ptls_iovec_init(NULL, 0), new_master_id(), NULL);
        ok(ret == 0);
        free_packets(&raw, 1);
        cond_even_up();
    }

    /* drop 2nd packet from server */
    ret = transmit_cond(server, client, &num_sent, &num_received, cond_even_down, 0);
    ok(ret == 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* client sends delayed-ack that gets dropped */
    ret = transmit_cond(client, server, &num_sent, &num_received, cond_even_up, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += 1000;

    /* server resends the contents of all the packets (in cleartext) */
    ret = transmit_cond(server, client, &num_sent, &num_received, cond_even_down, 0);
    ok(ret == 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* client sends delayed-ack that gets accepted */
    ret = transmit_cond(client, server, &num_sent, &num_received, cond_even_up, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    quic_now += 1000;

    /* server resends the contents of all the packets (in cleartext) */
    ret = transmit_cond(server, client, &num_sent, &num_received, cond_even_down, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));

    quic_ctx.loss = &quicly_loss_default_conf;
}

static unsigned rand_ratio;

static int cond_rand(void)
{
    static ptls_cipher_context_t *c;

    if (c == NULL)
        c = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, "0000000000000000");

    uint16_t v;
    ptls_cipher_encrypt(c, &v, "0000", 2);
    v &= 1023;

    return v < rand_ratio;
}

static void loss_core(int downstream_only)
{
    size_t num_sent_up, num_sent_down, num_received;
    int ret;

    quic_now = 0;

    { /* transmit first flight */
        quicly_datagram_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", (void *)"abc", 3, new_master_id(), NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        quic_now += 10;
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, (void *)"abc", 3, &decoded, ptls_iovec_init(NULL, 0), new_master_id(), NULL);
        ok(ret == 0);
        free_packets(&raw, 1);
        quic_now += 10;
    }

    quicly_stream_t *client_stream = NULL, *server_stream = NULL;
    test_streambuf_t *client_streambuf = NULL, *server_streambuf = NULL;
    const char *req = "GET / HTTP/1.0\r\n\r\n", *resp = "HTTP/1.0 200 OK\r\n\r\nhello world";
    size_t i, stall_count = 0;
    for (i = 0; i < 2000; ++i) {
        int64_t client_timeout = quicly_get_first_timeout(client), server_timeout = quicly_get_first_timeout(server),
                min_timeout = client_timeout < server_timeout ? client_timeout : server_timeout;
        assert(min_timeout != INT64_MAX);
        assert(min_timeout == 0 || quic_now < min_timeout + 40); /* we might have spent two RTTs in the loop below */
        if (quic_now < min_timeout)
            quic_now = min_timeout;
        if ((ret = transmit_cond(server, client, &num_sent_down, &num_received, cond_rand, 10)) != 0)
            goto Fail;
        server_timeout = quicly_get_first_timeout(server);
        assert(server_timeout > quic_now - 20);
        if (quicly_get_state(client) == QUICLY_STATE_CONNECTED && quicly_connection_is_ready(client)) {
            if (client_stream == NULL) {
                if ((ret = quicly_open_stream(client, &client_stream, 0)) != 0) {
                    fprintf(stderr, "%s: quicly_open_stream: ret=%d\n", __FUNCTION__, ret);
                    goto Fail;
                }
                client_streambuf = client_stream->data;
                quicly_streambuf_egress_write(client_stream, req, strlen(req));
                quicly_streambuf_egress_shutdown(client_stream);
            } else if (client_streambuf->is_detached) {
                ok(buffer_is(&client_streambuf->super.ingress, resp));
                ok(max_data_is_equal(client, server));
                return;
            }
        }
        if ((ret = transmit_cond(client, server, &num_sent_up, &num_received, downstream_only ? cond_true : cond_rand, 10)) != 0)
            goto Fail;
        client_timeout = quicly_get_first_timeout(client);
        assert(client_timeout > quic_now - 20);
        if (client_stream != NULL && (server_stream = quicly_get_stream(server, client_stream->stream_id)) != NULL) {
            if (server_streambuf == NULL && quicly_recvstate_transfer_complete(&server_stream->recvstate)) {
                server_streambuf = server_stream->data;
                ok(buffer_is(&server_streambuf->super.ingress, req));
                quicly_streambuf_egress_write(server_stream, resp, strlen(resp));
                quicly_streambuf_egress_shutdown(server_stream);
            }
        }
        if (num_sent_up + num_sent_down == 0) {
            ++stall_count;
            if (stall_count >= 10) {
                fprintf(stderr, "%s: stall_count exceeds max\n", __FUNCTION__);
                goto Fail;
            }
        } else {
            stall_count = 0;
        }
    }

Fail:
    fprintf(stderr, "%s: i=%zu\n", __FUNCTION__, i);
    ok(0);
}

static void test_downstream_core(void)
{
    loss_core(1);
}

static void test_downstream(void)
{
    size_t i;

    for (i = 0; i != 100; ++i) {
        rand_ratio = 256;
        subtest("75%", test_downstream_core);
        rand_ratio = 512;
        subtest("50%", test_downstream_core);
        rand_ratio = 768;
        subtest("25%", test_downstream_core);
        rand_ratio = 921;
        subtest("10%", test_downstream_core);
        rand_ratio = 973;
        subtest("5%", test_downstream_core);
        rand_ratio = 1014;
        subtest("1%", test_downstream_core);
    }
}

static void test_bidirectional_core(void)
{
    loss_core(0);
}

static void test_bidirectional(void)
{
    size_t i;

    for (i = 0; i != 100; ++i) {
        rand_ratio = 256;
        subtest("75%", test_bidirectional_core);
        rand_ratio = 512;
        subtest("50%", test_bidirectional_core);
        rand_ratio = 768;
        subtest("25%", test_bidirectional_core);
        rand_ratio = 921;
        subtest("10%", test_bidirectional_core);
        rand_ratio = 973;
        subtest("5%", test_bidirectional_core);
        rand_ratio = 1014;
        subtest("1%", test_bidirectional_core);
    }
}

void test_loss(void)
{
    subtest("even", test_even);
    subtest("downstream", test_downstream);
    subtest("bidirectional", test_bidirectional);
}
