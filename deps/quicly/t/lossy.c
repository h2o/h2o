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
                         int64_t latency, ptls_buffer_t *logger)
{
    quicly_address_t destaddr, srcaddr;
    struct iovec packets[32];
    uint8_t packetsbuf[PTLS_ELEMENTSOF(packets) * quicly_get_context(src)->transport_params.max_udp_payload_size];
    int ret;

    *num_sent = PTLS_ELEMENTSOF(packets);
    if ((ret = quicly_send(src, &destaddr, &srcaddr, packets, num_sent, packetsbuf, sizeof(packetsbuf))) != 0) {
        fprintf(stderr, "%s: quicly_send: ret=%d\n", __FUNCTION__, ret);
        return ret;
    }
    quic_now += latency;

    *num_received = 0;

    if (*num_sent != 0) {
        size_t i;
        for (i = 0; i != *num_sent; ++i) {
            int pass = cond->cb(cond);
            if (logger != NULL)
                ptls_buffer_pushv(logger, pass ? "    pass" : "    drop", 8);
            quicly_decoded_packet_t decoded[4];
            size_t num_decoded = decode_packets(decoded, packets + i, 1), j;
            assert(num_decoded != 0);
            for (j = 0; j != num_decoded; ++j) {
                if (logger != NULL) {
                    char buf[16];
                    sprintf(buf, "%c%02x:%zu", j == 0 ? ':' : ',', decoded[j].octets.base[0], decoded[j].octets.len);
                    ptls_buffer_pushv(logger, buf, strlen(buf));
                }
                if (pass) {
                    ret = quicly_receive(dst, NULL, &fake_address.sa, decoded + j);
                    if (!(ret == 0 || ret == QUICLY_ERROR_PACKET_IGNORED)) {
                        fprintf(stderr, "%s: quicly_receive: i=%zu, j=%zu, ret=%d\n", __FUNCTION__, i, j, ret);
                        return ret;
                    }
                }
            }
            if (logger != NULL)
                ptls_buffer_push(logger, '\n');
            if (pass)
                ++*num_received;
        }
    }
    quic_now += latency;

Exit:
    assert(ret == 0);
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

    quic_now = 1;

    { /* transmit first flight */
        quicly_address_t destaddr, srcaddr;
        struct iovec raw;
        uint8_t rawbuf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &destaddr, &srcaddr, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
        ok(ret == 0);
        cond_up.cb(&cond_up);
    }

    /* server sends 2 datagrams (Initial+Handshake,Handshake+1RTT), the latter gets dropped */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* client sends Handshake that gets dropped */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += 1000;

    /* server resends 2 datagrams, the latter gets dropped again */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 2);
    ok(num_received == 1);
    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(!quicly_connection_is_ready(client));

    quic_now += QUICLY_DELAYED_ACK_TIMEOUT;

    /* client sends Handshake again */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    quic_now += 1000;

    /* server retransmits the unacked (Handshake+1RTT) packet */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    ok(quicly_get_state(client) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(client));

    /* client sends ClientFinished, gets lost */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    quic_now += 1000;

    /* server retransmits the unacked packet */
    ret = transmit_cond(server, client, &num_sent, &num_received, &cond_down, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 0);

    quic_now += 1000;

    /* client resends ClientFinished */
    ret = transmit_cond(client, server, &num_sent, &num_received, &cond_up, 0, NULL);
    ok(ret == 0);
    ok(num_sent == 1);
    ok(num_received == 1);

    ok(quicly_get_state(server) == QUICLY_STATE_CONNECTED);
    ok(quicly_connection_is_ready(server));

    quic_ctx.loss = (quicly_loss_conf_t)QUICLY_LOSS_SPEC_CONF;
}

struct loss_cond_t loss_cond_down, loss_cond_up;
static unsigned num_failures_in_loss_core;

static void loss_core(void)
{
    size_t num_sent_up, num_sent_down, num_received;
    int ret;

    quic_now = 1;

    { /* transmit first flight */
        quicly_address_t destaddr, srcaddr;
        struct iovec raw;
        uint8_t rawbuf[quic_ctx.transport_params.max_udp_payload_size];
        size_t num_packets;
        quicly_decoded_packet_t decoded;

        ret = quicly_connect(&client, &quic_ctx, "example.com", &fake_address.sa, NULL, new_master_id(), ptls_iovec_init(NULL, 0),
                             NULL, NULL);
        ok(ret == 0);
        num_packets = 1;
        ret = quicly_send(client, &destaddr, &srcaddr, &raw, &num_packets, rawbuf, sizeof(rawbuf));
        ok(ret == 0);
        ok(num_packets == 1);
        quic_now += 10;
        decode_packets(&decoded, &raw, 1);
        ok(num_packets == 1);
        ret = quicly_accept(&server, &quic_ctx, NULL, &fake_address.sa, &decoded, NULL, new_master_id(), NULL);
        ok(ret == 0);
        quic_now += 10;
    }

    ptls_buffer_t transmit_log;
    ptls_buffer_init(&transmit_log, "", 0);

    {
        char buf[64];
        sprintf(buf, "odcid: ");
        const quicly_cid_t *odcid = quicly_get_original_dcid(server);
        ptls_hexdump(buf + strlen(buf), odcid->cid, odcid->len);
        strcat(buf, "\n");
        ptls_buffer_pushv(&transmit_log, buf, strlen(buf));
    }

    quicly_stream_t *client_stream = NULL, *server_stream = NULL;
    test_streambuf_t *client_streambuf = NULL, *server_streambuf = NULL;
    const char *req = "GET / HTTP/1.0\r\n\r\n", *resp = "HTTP/1.0 200 OK\r\n\r\nhello world";
    size_t i, stall_count = 0;
    for (i = 0; i < 100; ++i) {
        int64_t client_timeout = quicly_get_first_timeout(client), server_timeout = quicly_get_first_timeout(server),
                min_timeout = client_timeout < server_timeout ? client_timeout : server_timeout;
        assert(min_timeout != INT64_MAX);
        assert(min_timeout == 0 || quic_now < min_timeout + 40); /* we might have spent two RTTs in the loop below */
        if (quic_now < min_timeout)
            quic_now = min_timeout;
        char logbuf[32];
        sprintf(logbuf, "at:%" PRId64 "\n  down:\n", quic_now);
        ptls_buffer_pushv(&transmit_log, logbuf, strlen(logbuf));
        if ((ret = transmit_cond(server, client, &num_sent_down, &num_received, &loss_cond_down, 10, &transmit_log)) != 0)
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
            } else if (client_streambuf->is_detached || quicly_recvstate_transfer_complete(&client_stream->recvstate)) {
                ok(buffer_is(&client_streambuf->super.ingress, resp));
                ok(max_data_is_equal(client, server));
                ptls_buffer_dispose(&transmit_log);
                return;
            }
        }
        ptls_buffer_pushv(&transmit_log, "  up:\n", 6);
        if ((ret = transmit_cond(client, server, &num_sent_up, &num_received, &loss_cond_up, 10, &transmit_log)) != 0)
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
    fwrite(transmit_log.base, 1, transmit_log.off, stderr);
    ptls_buffer_dispose(&transmit_log);
    ++num_failures_in_loss_core;
    return;
Exit:
    fprintf(stderr, "no memory\n");
    abort();
}

static int cmp_int64(const void *_x, const void *_y)
{
    const int64_t *x = _x, *y = _y;
    if (*x < *y)
        return -1;
    if (*x > *y)
        return 1;
    return 0;
}

static void loss_check_stats(int64_t *time_spent, unsigned max_failures, double expected_time_mean, double expected_time_median,
                             double expected_time_90th)
{
    int64_t sum = 0;
    for (size_t i = 0; i < 100; ++i)
        sum += time_spent[i];

    double time_mean = sum / 100.;

    qsort(time_spent, 100, sizeof(time_spent[0]), cmp_int64);
    double time_median = (time_spent[49] + time_spent[50]) / 2.;
    double time_90th = (double)time_spent[89];

    printf("fail: %u, times: mean: %.1f, median: %.1f, 90th: %.1f\n", num_failures_in_loss_core, time_mean, time_median, time_90th);
    ok(num_failures_in_loss_core <= max_failures);
    ok(time_mean >= expected_time_mean * 0.6);
    ok(time_mean <= expected_time_mean * 1.2);
    ok(time_median >= expected_time_median * 0.8);
    ok(time_median <= expected_time_median * 1.2);
    // ok(time_90th >= expected_time_90th * 0.9); 90th is fragile to errors, we track this as an guarantee
    ok(time_90th <= expected_time_90th * 1.2);

    num_failures_in_loss_core = 0;
}

static void test_downstream(void)
{
    int64_t time_spent[100];
    size_t i;

    loss_cond_up = cond_true;

    num_failures_in_loss_core = 0;
    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 3, 4);
        subtest("75%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 3, 19927, 4188, 23030);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 2);
        subtest("50%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 1294.1, 710, 2988);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 4);
        subtest("25%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 225.6, 230, 408);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 10);
        subtest("10%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 134.6, 80, 298);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 20);
        subtest("5%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 102.8, 80, 230);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 40);
        subtest("2.5%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 88.2, 80, 80);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 64);
        subtest("1.6%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 91.3, 80, 80);
}

static void test_bidirectional(void)
{
    int64_t time_spent[100];
    size_t i;

    num_failures_in_loss_core = 0;
    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 3, 4);
        init_cond_rand(&loss_cond_up, 3, 4);
        subtest("75%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 27, 271754, 113887, 688726);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 2);
        init_cond_rand(&loss_cond_up, 1, 2);
        subtest("50%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 4913.4, 1815, 7106);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 4);
        init_cond_rand(&loss_cond_up, 1, 4);
        subtest("25%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 394, 264, 652);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 10);
        init_cond_rand(&loss_cond_up, 1, 10);
        subtest("10%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 150.1, 80, 298);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 20);
        init_cond_rand(&loss_cond_up, 1, 20);
        subtest("5%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 107.8, 80, 230);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 40);
        init_cond_rand(&loss_cond_up, 1, 40);
        subtest("2.5%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 90.9, 80, 170);

    for (i = 0; i != 100; ++i) {
        init_cond_rand(&loss_cond_down, 1, 64);
        init_cond_rand(&loss_cond_up, 1, 64);
        subtest("1.6%", loss_core);
        time_spent[i] = quic_now - 1;
    }
    loss_check_stats(time_spent, 0, 86.9, 80, 80);
}

void test_lossy(void)
{
    subtest("even", test_even);

    uint64_t idle_timeout_backup = quic_ctx.transport_params.max_idle_timeout;
    quic_ctx.transport_params.max_idle_timeout = (uint64_t)600 * 1000; /* 600 seconds */
    subtest("downstream", test_downstream);
    quic_ctx.transport_params.max_idle_timeout = (uint64_t)600 * 1000; /* 600 seconds */
    subtest("bidirectional", test_bidirectional);
    quic_ctx.transport_params.max_idle_timeout = idle_timeout_backup;
}
