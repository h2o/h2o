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
#include "quicly/defaults.h"
#include "test.h"

static quicly_conn_t *client, *server;

struct loss_cond_t {
    int (*cb)(struct loss_cond_t *cond);
    union {
        struct {
            size_t cnt;
        } even;
        struct {
            struct {
                unsigned nloss, ntotal;
            } ratio;
            uint64_t bits;
            size_t bits_avail;
        } rand_;
    } data;
};

static int cond_true_(struct loss_cond_t *cond)
{
    return 1;
}

static struct loss_cond_t cond_true = {cond_true_};

static int cond_even_(struct loss_cond_t *cond)
{
    return cond->data.even.cnt++ % 2 == 0;
}

static void init_cond_even(struct loss_cond_t *cond)
{
    *cond = (struct loss_cond_t){cond_even_};
}

static int cond_rand_(struct loss_cond_t *cond)
{
    static ptls_cipher_context_t *c;

    if (cond->data.rand_.bits_avail == 0) {
        if (c == NULL) {
            /* use different seed for each invocation */
            static uint64_t key[2];
            c = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, &key);
            ++key[0];
        }
        /* initialize next `ntotal` bits, of which `nloss` bits are set */
        cond->data.rand_.bits = 0;
        unsigned num_bits_set;
        for (num_bits_set = 0; num_bits_set != cond->data.rand_.ratio.nloss; ++num_bits_set) {
            /* choose a mask that sets a new bit */
            uint64_t mask;
            do {
                uint32_t v;
                ptls_cipher_encrypt(c, &v, "01234567", 4);
                mask = (uint64_t)1 << (v % cond->data.rand_.ratio.ntotal);
            } while ((cond->data.rand_.bits & mask) != 0);
            /* set the chosen bit */
            cond->data.rand_.bits |= mask;
        }
        cond->data.rand_.bits_avail = cond->data.rand_.ratio.ntotal;
    }

    /* return a bit, negating the value, as rand_.bits indicates the bits being lost, whereas we want to return if transmission
     * succeeds */
    return ((cond->data.rand_.bits >> --cond->data.rand_.bits_avail) & 1) == 0;
}

/**
 * loss_rate indicates as `nloss` packets out of every `ntotal` packets
 */
static void init_cond_rand(struct loss_cond_t *cond, unsigned nloss, unsigned ntotal)
{
    *cond = (struct loss_cond_t){cond_rand_};
    cond->data.rand_.ratio.nloss = nloss;
    cond->data.rand_.ratio.ntotal = ntotal;
}

static int transmit_cond(quicly_conn_t *src, quicly_conn_t *dst, size_t *num_sent, size_t *num_received, struct loss_cond_t *cond,
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
            if (cond->cb(cond)) {
                quicly_decoded_packet_t decoded[4];
                size_t num_decoded = decode_packets(decoded, packets + i, 1), j;
                assert(num_decoded != 0);
                for (j = 0; j != num_decoded; ++j) {
                    ret = quicly_receive(dst, NULL, &fake_address.sa, decoded + j);
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

static void test_even(void)
{
    quicly_loss_conf_t lossconf = QUICLY_LOSS_SPEC_CONF;
    struct loss_cond_t cond_down, cond_up;
    size_t num_sent, num_received;
    int ret;

    quic_ctx.loss = lossconf;
    init_cond_even(&cond_down);
    init_cond_even(&cond_up);

    quic_now = 0;

    { /* transmit first flight */
        quicly_datagram_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
        ok(ret == 0);
        free_packets(&raw, 1);
        cond_up.cb(&cond_up);
    }

    /* server sends 2 datagrams (Initial+Handshake,Handshake+1RTT), the latter gets dropped */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0);
    ok(ret == 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* client sends Handshake that gets dropped */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += 1000;

    /* server resends 2 datagrams, the latter gets dropped again */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0);
    ok(ret == 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* client sends Handshake again */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    quic_now += 1000;

    /* server retransmits the unacked (Handshake+1RTT) packet */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));

    /* client sends ClientFinished, gets lost */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    quic_now += 1000;

    /* server retransmits the unacked packet */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    quic_now += 1000;

    /* client resends ClientFinished */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(server));

    quic_ctx.loss = (quicly_loss_conf_t)QUICLY_LOSS_SPEC_CONF;
}

struct loss_cond_t loss_cond_down, loss_cond_up;

static void loss_core(void)
{
    size_t num_sent_up, num_sent_down, num_received;
    int ret;

#if 0 /* enable this to log the transaction of beginning from a specific subtest (in the case of the following, 9,3,37) */
    if (test_index[0] == 9 && test_index[1] == 2 && test_index[2] == 15) {
        quic_ctx.event_log.cb = quicly_new_default_event_logger(stdout);
        quic_ctx.event_log.mask = UINT64_MAX;
    }
#endif

    quic_now = 0;

    { /* transmit first flight */
        quicly_datagram_t *raw;
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &raw, &num_packets);
        ok(ret == 0);
        ok(num_packets == 1);
        quic_now += 10;
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
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
        if ((ret = transmit_cond(server, client, &num_sent_down, &num_received, &loss_cond_down, 10)) != 0)
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
        if ((ret = transmit_cond(client, server, &num_sent_up, &num_received, &loss_cond_up, 10)) != 0)
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

static void test_downstream(void)
{
    size_t i;

    loss_cond_up = cond_true;

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 3, 4);
        subtest("75%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 2);
        subtest("50%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 4);
        subtest("25%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 10);
        subtest("10%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 20);
        subtest("5%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 40);
        subtest("2.5%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 64);
        subtest("1.6%", loss_core);
    }
}

static void test_bidirectional(void)
{
    size_t i;

    for (i = 0; i != 100; ++i) {
#if 0 /* TODO enable this after adding code that retransmits ACK every 1 PTO even when a single packet is received */
        init_cond_rand(&loss_cond_down, 3, 4);
        init_cond_rand(&loss_cond_up, 3, 4);
        subtest("75%", loss_core);
#endif

        init_cond_rand(&loss_cond_down, 1, 2);
        init_cond_rand(&loss_cond_up, 1, 2);
        subtest("50%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 4);
        init_cond_rand(&loss_cond_up, 1, 4);
        subtest("25%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 10);
        init_cond_rand(&loss_cond_up, 1, 10);
        subtest("10%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 20);
        init_cond_rand(&loss_cond_up, 1, 20);
        subtest("5%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 40);
        init_cond_rand(&loss_cond_up, 1, 40);
        subtest("2.5%", loss_core);

        init_cond_rand(&loss_cond_down, 1, 64);
        init_cond_rand(&loss_cond_up, 1, 64);
        subtest("1.6%", loss_core);
    }
}

void test_loss(void)
{
    subtest("even", test_even);

    uint64_t idle_timeout_backup = quic_ctx.transport_params.max_idle_timeout;
    quic_ctx.transport_params.max_idle_timeout = (uint64_t)600 * 1000; /* 600 seconds */
    subtest("downstream", test_downstream);
    quic_ctx.transport_params.max_idle_timeout = (uint64_t)600 * 1000; /* 600 seconds */
    subtest("bidirectional", test_bidirectional);
    quic_ctx.transport_params.max_idle_timeout = idle_timeout_backup;
}
