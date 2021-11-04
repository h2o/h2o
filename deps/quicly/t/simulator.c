/*
 * Copyright (c) 2021 Fastly, Kazuho Oku
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
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/cc.h"
#include "quicly/defaults.h"

FILE *quicly_trace_fp;

static double now = 1000;

static quicly_address_t new_address(void)
{
    static uint32_t next_ipaddr = 1;
    quicly_address_t addr = {};
    addr.sin.sin_family = AF_INET;
    addr.sin.sin_addr.s_addr = htonl(next_ipaddr);
    addr.sin.sin_port = htons(54321);
    ++next_ipaddr;
    return addr;
}

struct net_endpoint;

/**
 * Packet
 */
struct net_packet {
    /**
     * used by nodes to maintain the linked-list of packets being queued
     */
    struct net_packet *next;
    /**
     * source
     */
    struct net_endpoint *src;
    /**
     * destination
     */
    quicly_address_t dest;
    /**
     * used by queues to retain when the packet entered that queue
     */
    double enter_at;
    /**
     * size of the packet
     */
    size_t size;
    /**
     * the packet
     */
    uint8_t bytes[1];
};

struct net_queue {
    struct net_packet *first, **append_at;
    size_t size;
};

struct net_node {
    void (*forward_)(struct net_node *node, struct net_packet *packet);
    double (*next_run_at)(struct net_node *node);
    void (*run)(struct net_node *node);
};

struct net_delay {
    struct net_node super;
    struct net_node *next_node;
    struct net_queue queue;
    double delay;
};

struct net_random_loss {
    struct net_node super;
    struct net_node *next_node;
    double loss_ratio;
};

struct net_bottleneck {
    struct net_node super;
    struct net_node *next_node;
    struct net_queue queue;
    double next_emit_at;
    double bytes_per_sec;
    size_t capacity;
};

struct net_endpoint {
    struct net_node super;
    quicly_address_t addr;
    double start_at;
    struct net_endpoint_conn {
        quicly_conn_t *quic;
        struct net_node *egress;
    } conns[10];
    quicly_context_t *accept_ctx;
};

static struct net_packet *net_packet_create(struct net_endpoint *src, quicly_address_t *dest, ptls_iovec_t vec)
{
    struct net_packet *p = malloc(offsetof(struct net_packet, bytes) + vec.len);

    p->next = NULL;
    p->src = src;
    p->dest = *dest;
    p->enter_at = now;
    p->size = vec.len;
    memcpy(p->bytes, vec.base, vec.len);

    return p;
}

static void net_packet_destroy(struct net_packet *packet)
{
    free(packet);
}

static void net_queue_enqueue(struct net_queue *self, struct net_packet *packet)
{
    packet->next = NULL;
    packet->enter_at = now;
    *self->append_at = packet;
    self->append_at = &packet->next;
    self->size += packet->size;
}

static struct net_packet *net_queue_dequeue(struct net_queue *self)
{
    struct net_packet *packet = self->first;
    assert(packet != NULL);
    if ((self->first = packet->next) == NULL)
        self->append_at = &self->first;
    self->size -= packet->size;
    return packet;
}

static void net_delay_forward(struct net_node *_self, struct net_packet *packet)
{
    struct net_delay *self = (struct net_delay *)_self;
    net_queue_enqueue(&self->queue, packet);
}

static double net_delay_next_run_at(struct net_node *_self)
{
    struct net_delay *self = (struct net_delay *)_self;
    return self->queue.first != NULL ? self->queue.first->enter_at + self->delay : INFINITY;
}

static void net_delay_run(struct net_node *_self)
{
    struct net_delay *self = (struct net_delay *)_self;

    while (self->queue.first != NULL && self->queue.first->enter_at + self->delay <= now) {
        struct net_packet *packet = net_queue_dequeue(&self->queue);
        self->next_node->forward_(self->next_node, packet);
    }
}

static void net_delay_init(struct net_delay *self, double delay)
{
    *self = (struct net_delay){
        .super = {net_delay_forward, net_delay_next_run_at, net_delay_run},
        .queue = {.append_at = &self->queue.first},
        .delay = delay,
    };
}

static void net_random_loss_forward(struct net_node *_self, struct net_packet *packet)
{
    struct net_random_loss *self = (struct net_random_loss *)_self;

    if (rand() % 65536 < self->loss_ratio * 65536) {
        printf("{\"random-loss\": \"drop\", \"at\": %f, \"packet-src\": %" PRIu32 "}\n", now,
               ntohl(packet->src->addr.sin.sin_addr.s_addr));
        net_packet_destroy(packet);
        return;
    }

    self->next_node->forward_(self->next_node, packet);
}

static double net_random_loss_next_run_at(struct net_node *self)
{
    return INFINITY;
}

static void net_random_loss_init(struct net_random_loss *self, double loss_ratio)
{
    *self = (struct net_random_loss){
        .super = {net_random_loss_forward, net_random_loss_next_run_at, NULL},
        .loss_ratio = loss_ratio,
    };
}

static void net_bottleneck_print_stats(struct net_bottleneck *self, const char *event, struct net_packet *packet)
{
    printf("{\"bottleneck\": \"%s\", \"at\": %f, \"queue-size\": %zu, \"packet-src\": %" PRIu32 ", \"packet-size\": %zu}\n", event,
           now, self->queue.size, ntohl(packet->src->addr.sin.sin_addr.s_addr), packet->size);
}

static void net_bottleneck_forward(struct net_node *_self, struct net_packet *packet)
{
    struct net_bottleneck *self = (struct net_bottleneck *)_self;

    /* drop the packet if the queue is full */
    if (self->queue.size + packet->size > self->capacity) {
        net_bottleneck_print_stats(self, "drop", packet);
        net_packet_destroy(packet);
        return;
    }

    net_bottleneck_print_stats(self, "enqueue", packet);
    net_queue_enqueue(&self->queue, packet);
}

static double net_bottleneck_next_run_at(struct net_node *_self)
{
    struct net_bottleneck *self = (struct net_bottleneck *)_self;

    if (self->queue.first == NULL)
        return INFINITY;

    double emit_at = self->queue.first->enter_at;
    if (emit_at < self->next_emit_at)
        emit_at = self->next_emit_at;

    return emit_at;
}

static void net_bottleneck_run(struct net_node *_self)
{
    struct net_bottleneck *self = (struct net_bottleneck *)_self;

    if (net_bottleneck_next_run_at(&self->super) > now)
        return;

    /* detach packet */
    struct net_packet *packet = net_queue_dequeue(&self->queue);
    net_bottleneck_print_stats(self, "dequeue", packet);

    /* update next emission timer */
    self->next_emit_at = now + (double)packet->size / self->bytes_per_sec;

    /* forward to the next node */
    self->next_node->forward_(self->next_node, packet);
}

static void net_bottleneck_init(struct net_bottleneck *self, double bytes_per_sec, double capacity_in_sec)
{
    *self = (struct net_bottleneck){
        .super = {net_bottleneck_forward, net_bottleneck_next_run_at, net_bottleneck_run},
        .queue = {.append_at = &self->queue.first},
        .bytes_per_sec = bytes_per_sec,
        .capacity = (size_t)(bytes_per_sec * capacity_in_sec),
    };
}

static quicly_cid_plaintext_t next_quic_cid;

static void net_endpoint_forward(struct net_node *_self, struct net_packet *packet)
{
    struct net_endpoint *self = (struct net_endpoint *)_self;

    size_t off = 0;
    while (off != packet->size) {
        /* decode packet */
        quicly_decoded_packet_t qp;
        if (quicly_decode_packet(self->conns[0].quic != NULL ? quicly_get_context(self->conns[0].quic) : self->accept_ctx, &qp,
                                 packet->bytes, packet->size, &off) == SIZE_MAX)
            break;
        /* find the matching connection, or where new state should be created */
        struct net_endpoint_conn *conn;
        for (conn = self->conns; conn->quic != NULL; ++conn)
            if (quicly_is_destination(conn->quic, &packet->dest.sa, &packet->src->addr.sa, &qp))
                break;
        /* let the existing connection handle the packet, or accept a new connection */
        if (conn->quic != NULL) {
            quicly_receive(conn->quic, &packet->dest.sa, &packet->src->addr.sa, &qp);
        } else {
            assert(self->accept_ctx != NULL && "a packet for which we do not have state must be a new connection request");
            if (quicly_accept(&conn->quic, self->accept_ctx, &packet->dest.sa, &packet->src->addr.sa, &qp, NULL, &next_quic_cid,
                              NULL) == 0) {
                assert(conn->quic != NULL);
                ++next_quic_cid.master_id;
                conn->egress = &packet->src->super;
            } else {
                assert(conn->quic == NULL);
            }
        }
    }

    net_packet_destroy(packet);
}

static double net_endpoint_next_run_at(struct net_node *_self)
{
    struct net_endpoint *self = (struct net_endpoint *)_self;

    if (now < self->start_at)
        return self->start_at;

    double at = INFINITY;
    for (struct net_endpoint_conn *conn = self->conns; conn->quic != NULL; ++conn) {
        /* value is incremented by 0.1ms to avoid the timer firing earlier than specified due to rounding error */
        double conn_at = quicly_get_first_timeout(conn->quic) / 1000. + 0.0001;
        if (conn_at < at)
            at = conn_at;
    }
    if (at < now)
        at = now;
    return at;
}

static void net_endpoint_run(struct net_node *_self)
{
    struct net_endpoint *self = (struct net_endpoint *)_self;

    if (now < self->start_at)
        return;

    for (struct net_endpoint_conn *conn = self->conns; conn->quic != NULL; ++conn) {
        quicly_address_t dest, src;
        struct iovec datagrams[10];
        size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
        uint8_t buf[PTLS_ELEMENTSOF(datagrams) * 1500];
        int ret;
        if ((ret = quicly_send(conn->quic, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf))) == 0) {
            for (size_t i = 0; i < num_datagrams; ++i) {
                struct net_packet *packet =
                    net_packet_create(self, &dest, ptls_iovec_init(datagrams[i].iov_base, datagrams[i].iov_len));
                conn->egress->forward_(conn->egress, packet);
            }
        } else {
            assert(ret != QUICLY_ERROR_FREE_CONNECTION);
        }
    }
}

static void net_endpoint_init(struct net_endpoint *endpoint)
{
    *endpoint = (struct net_endpoint){
        .super = {net_endpoint_forward, net_endpoint_next_run_at, net_endpoint_run},
        .addr = new_address(),
    };
}

static void run_nodes(struct net_node **nodes)
{
    double next_now = INFINITY;
    for (struct net_node **node = nodes; *node != NULL; ++node) {
        double at = (*node)->next_run_at(*node);
        assert(at >= now);
        if (next_now > at)
            next_now = at;
    }

    if (isinf(next_now))
        return;

    now = next_now;
    for (struct net_node **node = nodes; *node != NULL; ++node) {
        if ((*node)->next_run_at(*node) <= now)
            (*node)->run(*node);
    }
}

static uint64_t tls_now_cb(ptls_get_time_t *self)
{
    return (uint64_t)(now * 1000);
}

static int64_t quic_now_cb(quicly_now_t *self)
{
    return (int64_t)(now * 1000);
}

static void stream_destroy_cb(quicly_stream_t *stream, int err)
{
}

static void stream_egress_shift_cb(quicly_stream_t *stream, size_t delta)
{
}

static void stream_egress_emit_cb(quicly_stream_t *stream, size_t off, void *dst, size_t *len, int *wrote_all)
{
    assert(quicly_is_client(stream->conn));
    memset(dst, 'A', *len);
    *wrote_all = 0;
}

static void stream_on_stop_sending_cb(quicly_stream_t *stream, int err)
{
    assert(!"unexpected");
}

static void stream_on_receive_cb(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    assert(!quicly_is_client(stream->conn));
    assert(!quicly_recvstate_transfer_complete(&stream->recvstate));

    if (stream->recvstate.data_off < stream->recvstate.received.ranges[0].end)
        quicly_stream_sync_recvbuf(stream, stream->recvstate.received.ranges[0].end - stream->recvstate.data_off);
}

static void stream_on_receive_reset_cb(quicly_stream_t *stream, int err)
{
    assert(!"unexpected");
}

static int stream_open_cb(quicly_stream_open_t *self, quicly_stream_t *stream)
{
    static const quicly_stream_callbacks_t stream_callbacks = {stream_destroy_cb,     stream_egress_shift_cb,
                                                               stream_egress_emit_cb, stream_on_stop_sending_cb,
                                                               stream_on_receive_cb,  stream_on_receive_reset_cb};
    stream->callbacks = &stream_callbacks;
    return 0;
}

static void usage(const char *cmd)
{
    printf("Usage: %s ...\n"
           "\n"
           "Options:\n"
           "  -n <cc>             adds a sender using specified controller\n"
           "  -b <bytes_per_sec>  bottleneck bandwidth (default: 1000000, i.e., 1MB/s)\n"
           "  -l <seconds>        number of seconds to simulate (default: 100)\n"
           "  -d <delay>          delay to be introduced between the sender and the botteneck, in seconds (default: 0.1)\n"
           "  -q <seconds>        maximum depth of the bottleneck queue, in seconds (default: 0.1)\n"
           "  -r <rate>           introduce random loss at specified probability (default: 0)\n"
           "  -s <seconds>        delay until the sender is introduced to the simulation (default: 0)\n"
           "  -t                  emits trace as well\n"
           "  -h                  print this help\n"
           "\n",
           cmd);
}

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEpAIBAAKCAQEA7zZheZ4ph98JaedBNv9kqsVA9CSmhd69kBc9ZAfVFMA4VQwp\n"                                                           \
    "rOj3ZGrxf20HB3FkvqGvew9ZogUF6NjbPumeiUObGpP21Y5wcYlPL4aojlrwMB/e\n"                                                           \
    "OxOCpuRyQTRSSe1hDPvdJABQdmshDP5ZSEBLdUSgrNn4KWhIDjFj1AHXIMqeqTXe\n"                                                           \
    "tFuRgNzHdtbXQx+UWBis2B6qZJuqSArb2msVOC8D5gNznPPlQw7FbdPCaLNXSb6G\n"                                                           \
    "nI0E0uj6QmYlAw9s6nkgP/zxjfFldqPNUprGcEqTwmAb8VVtd7XbANYrzubZ4Nn6\n"                                                           \
    "/WXrCrVxWUmh/7Spgdwa/I4Nr1JHv9HHyL2z/wIDAQABAoIBAEVPf2zKrAPnVwXt\n"                                                           \
    "cJLr6xIj908GM43EXS6b3TjXoCDUFT5nOMgV9GCPMAwY3hmE/IjTtlG0v+bXB8BQ\n"                                                           \
    "3S3caQgio5VO3A1CqUfsXhpKLRqaNM/s2+pIG+oZdRV5gIJVGnK1o3yj7qxxG/F0\n"                                                           \
    "3Q+3OWXwDZIn0eTFh2M9YkxygA/KtkREZWv8Q8qZpdOpJSBYZyGE97Jqy/yGc+DQ\n"                                                           \
    "Vpoa9B8WwnIdUn47TkZfsbzqGIYZxatJQDC1j7Y+F8So7zBbUhpz7YqATQwf5Efm\n"                                                           \
    "K2xwvlwfdwykq6ffEr2M/Xna0220G2JZlGq3Cs2X9GT9Pt9OS86Bz+EL46ELo0tZ\n"                                                           \
    "yfHQe/kCgYEA+zh4k2be6fhQG+ChiG3Ue5K/kH2prqyGBus61wHnt8XZavqBevEy\n"                                                           \
    "4pdmvJ6Q1Ta9Z2YCIqqNmlTdjZ6B35lvAK8YFITGy0MVV6K5NFYVfhALWCQC2r3B\n"                                                           \
    "6uH39FQ0mDo3gS5ZjYlUzbu67LGFnyX+pyMr2oxlhI1fCY3VchXQAOsCgYEA88Nt\n"                                                           \
    "CwSOaZ1fWmyNAgXEAX1Jx4XLFYgjcA/YBXW9gfQ0AfufB346y53PsgjX1lB+Bbcg\n"                                                           \
    "cY/o5W7F0b3A0R4K5LShlPCq8iB2DC+VnpKwTgo8ylh+VZCPy2BmMK0jrrmyqWeg\n"                                                           \
    "PzwgP0lp+7l/qW8LDImeYi8nWoqd6f1ye4iJdD0CgYEAlIApJljk5EFYeWIrmk3y\n"                                                           \
    "EKoKewsNRqfNAkICoh4KL2PQxaAW8emqPq9ol47T5nVZOMnf8UYINnZ8EL7l3psA\n"                                                           \
    "NtNJ1Lc4G+cnsooKGJnaUo6BZjTDSzJocsPoopE0Fdgz/zS60yOe8Y5LTKcTaaQ4\n"                                                           \
    "B+yOe74KNHSs/STOS4YBUskCgYAIqaRBZPsOo8oUs5DbRostpl8t2QJblIf13opF\n"                                                           \
    "v2ZprN0ASQngwUqjm8sav5e0BQ5Fc7mSb5POO36KMp0ckV2/vO+VFGxuyFqJmlNN\n"                                                           \
    "3Fapn1GDu1tZ/RYvGxDmn/CJsA26WXVnaeKXfStoB7KSueCBpI5dXOGgJRbxjtE3\n"                                                           \
    "tKV13QKBgQCtmLtTJPJ0Z+9n85C8kBonk2MCnD9JTYWoDQzNMYGabthzSqJqcEek\n"                                                           \
    "dvhr82XkcHM+r6+cirjdQr4Qj7/2bfZesHl5XLvoJDB1YJIXnNJOELwbktrJrXLc\n"                                                           \
    "dJ+MMvPvBAMah/tqr2DqgTGfWLDt9PJiCJVsuN2kD9toWHV08pY0Og==\n"                                                                   \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIIDOjCCAiKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDEwtIMk8g\n"                                                           \
    "VGVzdCBDQTAeFw0xNDEyMTAxOTMzMDVaFw0yNDEyMDcxOTMzMDVaMBsxGTAXBgNV\n"                                                           \
    "BAMTEDEyNy4wLjAuMS54aXAuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"                                                           \
    "AoIBAQDvNmF5nimH3wlp50E2/2SqxUD0JKaF3r2QFz1kB9UUwDhVDCms6PdkavF/\n"                                                           \
    "bQcHcWS+oa97D1miBQXo2Ns+6Z6JQ5sak/bVjnBxiU8vhqiOWvAwH947E4Km5HJB\n"                                                           \
    "NFJJ7WEM+90kAFB2ayEM/llIQEt1RKCs2fgpaEgOMWPUAdcgyp6pNd60W5GA3Md2\n"                                                           \
    "1tdDH5RYGKzYHqpkm6pICtvaaxU4LwPmA3Oc8+VDDsVt08Jos1dJvoacjQTS6PpC\n"                                                           \
    "ZiUDD2zqeSA//PGN8WV2o81SmsZwSpPCYBvxVW13tdsA1ivO5tng2fr9ZesKtXFZ\n"                                                           \
    "SaH/tKmB3Br8jg2vUke/0cfIvbP/AgMBAAGjgY0wgYowCQYDVR0TBAIwADAsBglg\n"                                                           \
    "hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0O\n"                                                           \
    "BBYEFJXhddVQ68vtPvxoHWHsYkLnu3+4MDAGA1UdIwQpMCehGqQYMBYxFDASBgNV\n"                                                           \
    "BAMTC0gyTyBUZXN0IENBggkAmqS1V7DvzbYwDQYJKoZIhvcNAQELBQADggEBAJQ2\n"                                                           \
    "uvzL/lZnrsF4cvHhl/mg+s/RjHwvqFRrxOWUeWu2BQOGdd1Izqr8ZbF35pevPkXe\n"                                                           \
    "j3zQL4Nf8OxO/gx4w0165KL4dYxEW7EaxsDQUI2aXSW0JNSvK2UGugG4+E4aT+9y\n"                                                           \
    "cuBCtfWbL4/N6IMt2QW17B3DcigkreMoZavnnqRecQWkOx4nu0SmYg1g2QV4kRqT\n"                                                           \
    "nvLt29daSWjNhP3dkmLTxn19umx26/JH6rqcgokDfHHO8tlDbc9JfyxYH01ZP2Ps\n"                                                           \
    "esIiGa/LBXfKiPXxyHuNVQI+2cMmIWYf+Eu/1uNV3K55fA8806/FeklcQe/vvSCU\n"                                                           \
    "Vw6RN5S/14SQnMYWr7E=\n"                                                                                                       \
    "-----END CERTIFICATE-----\n"

int main(int argc, char **argv)
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();

    ptls_iovec_t cert = {};
    {
        BIO *bio = BIO_new_mem_buf(RSA_CERTIFICATE, strlen(RSA_CERTIFICATE));
        X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        assert(x509 != NULL || !!"failed to load certificate");
        BIO_free(bio);
        cert.len = i2d_X509(x509, &cert.base);
        X509_free(x509);
    }

    ptls_openssl_sign_certificate_t cert_signer;
    {
        BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, strlen(RSA_PRIVATE_KEY));
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        assert(pkey != NULL || !"failed to load private key");
        BIO_free(bio);
        ptls_openssl_init_sign_certificate(&cert_signer, pkey);
        EVP_PKEY_free(pkey);
    }
    ptls_get_time_t tls_now = {tls_now_cb};
    ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                             .get_time = &tls_now,
                             .key_exchanges = ptls_openssl_key_exchanges,
                             .cipher_suites = ptls_openssl_cipher_suites,
                             .certificates = {&cert, 1},
                             .sign_certificate = &cert_signer.super};
    quicly_amend_ptls_context(&tlsctx);

    quicly_stream_open_t stream_open = {stream_open_cb};
    quicly_now_t quic_now = {quic_now_cb};
    quicly_context_t quicctx = quicly_spec_context;
    quicctx.now = &quic_now;
    quicctx.tls = &tlsctx;
    quicctx.stream_open = &stream_open;
    quicctx.transport_params.max_streams_uni = 10;
    quicctx.transport_params.max_stream_data.uni = 128 * 1024 * 1024;
    quicctx.transport_params.max_data = 128 * 1024 * 1824;
    quicctx.transport_params.min_ack_delay_usec = UINT64_MAX; /* disable ack-delay extension */

    struct net_bottleneck bottleneck_node;
    struct net_random_loss random_loss_node;
    struct {
        struct net_endpoint node;
        quicly_context_t accept_ctx;
    } server_node;
    struct net_node *nodes[20] = {}, **node_insert_at = nodes;

    net_endpoint_init(&server_node.node);
    server_node.accept_ctx = quicctx;
    server_node.node.accept_ctx = &server_node.accept_ctx;
    *node_insert_at++ = &server_node.node.super;

    /* parse args */
    double delay = 0.1, bw = 1e6, depth = 0.1, start = 0, random_loss = 0;
    unsigned length = 100;
    int ch;
    while ((ch = getopt(argc, argv, "n:b:d:s:l:q:r:th")) != -1) {
        switch (ch) {
        case 'n': {
            quicly_cc_type_t **cc;
            for (cc = quicly_cc_all_types; *cc != NULL; ++cc)
                if (strcmp((*cc)->name, optarg) == 0)
                    break;
            if (*cc != NULL) {
                quicctx.init_cc = (*cc)->cc_init;
            } else {
                fprintf(stderr, "unknown congestion controller: %s\n", optarg);
                exit(1);
            }
            struct net_delay *delay_node = malloc(sizeof(*delay_node));
            net_delay_init(delay_node, delay);
            delay_node->next_node = &bottleneck_node.super;
            *node_insert_at++ = &delay_node->super;
            struct net_endpoint *client_node = malloc(sizeof(*client_node));
            net_endpoint_init(client_node);
            client_node->start_at = now + start;
            int ret = quicly_connect(&client_node->conns[0].quic, &quicctx, "hello.example.com", &server_node.node.addr.sa,
                                     &client_node->addr.sa, &next_quic_cid, ptls_iovec_init(NULL, 0), NULL, NULL);
            ++next_quic_cid.master_id;
            assert(ret == 0);
            quicly_stream_t *stream;
            ret = quicly_open_stream(client_node->conns[0].quic, &stream, 1);
            assert(ret == 0);
            ret = quicly_stream_sync_sendbuf(stream, 1);
            assert(ret == 0);
            client_node->conns[0].egress = &delay_node->super;
            *node_insert_at++ = &client_node->super;
        } break;
        case 'b':
            if (sscanf(optarg, "%lf", &bw) != 1) {
                fprintf(stderr, "invalid bandwidth: %s\n", optarg);
                exit(1);
            }
            break;
        case 'd':
            if (sscanf(optarg, "%lf", &delay) != 1) {
                fprintf(stderr, "invalid delay value: %s\n", optarg);
                exit(1);
            }
            break;
        case 's':
            if (sscanf(optarg, "%lf", &start) != 1) {
                fprintf(stderr, "invaild start: %s\n", optarg);
                exit(1);
            }
            break;
        case 'l':
            if (sscanf(optarg, "%u", &length) != 1) {
                fprintf(stderr, "invalid length: %s\n", optarg);
                exit(1);
            }
            break;
        case 'q':
            if (sscanf(optarg, "%lf", &depth) != 1) {
                fprintf(stderr, "invalid queue depth: %s\n", optarg);
                exit(1);
            }
            break;
        case 'r':
            if (sscanf(optarg, "%lf", &random_loss) != 1) {
                fprintf(stderr, "invalid random loss rate: %s\n", optarg);
                exit(1);
            }
            break;
        case 't':
            quicly_trace_fp = stdout;
            break;
        default:
            usage(argv[0]);
            exit(0);
        }
    }
    argc -= optind;
    argv += optind;

    /* setup bottleneck */
    net_bottleneck_init(&bottleneck_node, bw, depth);
    bottleneck_node.next_node = &server_node.node.super;
    *node_insert_at++ = &bottleneck_node.super;

    /* setup random loss */
    if (random_loss != 0) {
        net_random_loss_init(&random_loss_node, random_loss);
        random_loss_node.next_node = &server_node.node.super;
        bottleneck_node.next_node = &random_loss_node.super;
        *node_insert_at++ = &random_loss_node.super;
    }

    while (now < 1000 + length)
        run_nodes(nodes);

    return 0;
}
