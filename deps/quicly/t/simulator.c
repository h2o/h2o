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
static struct {
    uint64_t eligible_packets;
    uint64_t stalls;
    uint64_t queued_packets;
} ack_scheduler_stats;

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
     * ECN codepoint being carried by the IP header; the AQM of the bottleneck turns ECT(0) into CE when congestion is observed
     */
    uint8_t ecn;
    /**
     * size of the packet
     */
    size_t size;
    /**
     * the packet
     */
    uint8_t bytes[1];
};

/**
 * A lossy FIFO of packets. Every queue of the simulator is one of these; the discipline that determines when (and if) a packet
 * leaves is carried as part of it, rather than being a type of its own.
 */
struct net_queue {
    struct net_packet *first, **append_at;
    size_t size;
    /**
     * Number of bytes the queue is still allowed to send in the current round, and which of the two rounds it belongs to. Used
     * when the queue is one of several being served by deficit round robin; queues that have just become active are served
     * before the ones that have been, as fq_codel does.
     */
    int32_t deficit;
    enum { NET_QUEUE_INACTIVE, NET_QUEUE_NEW, NET_QUEUE_OLD } sched;
    /**
     * The discipline; the union carries whatever that discipline needs.
     */
    enum { NET_QUEUE_PLAIN, NET_QUEUE_DELAY, NET_QUEUE_STEP, NET_QUEUE_CODEL } type;
    union {
        /**
         * NET_QUEUE_DELAY: the duration for which each packet is withheld.
         */
        double delay;
        /**
         * NET_QUEUE_CODEL: the state of CoDel.
         */
        struct {
            /**
             * Time at which the sojourn time is going to have been above target for `interval`; zero if it is below target.
             */
            double above_target_since;
            /**
             * Time at which the next packet is to be marked (or dropped), while in the marking state.
             */
            double mark_next;
            /**
             * Number of packets marked since entering the marking state, and the value it had when the state was left the
             * previous time.
             */
            uint32_t count, last_count;
            /**
             * If being in the marking state.
             */
            int marking;
        } codel;
    };
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
};

struct net_random_loss {
    struct net_node super;
    struct net_node *next_node;
    double loss_ratio;
};

/**
 * The discipline the queues of the bottleneck run. It is orthogonal to whether the flows are isolated; fq_codel (RFC 8290) is
 * `NET_AQM_CODEL` combined with isolation.
 * `NET_AQM_STEP` marks every ECT packet whose sojourn time exceeds `target`. It is not a discipline that anybody deploys; being
 * deterministic, it tells exactly when a CE mark is supposed to be emitted.
 * `NET_AQM_CODEL` is CoDel (RFC 8289), following the ECN handling of the Linux implementation; the pseudocode of the RFC only
 * drops, whereas the packet that is marked is delivered.
 */
struct net_aqm {
    enum { NET_AQM_NONE, NET_AQM_STEP, NET_AQM_CODEL } type;
    double target;
    double interval;
};

/**
 * Maximum number of queues of the bottleneck. When the flows are isolated there is one for each of them, and as the endpoints are
 * given addresses sequentially, the address is used as the index.
 */
#define NET_BOTTLENECK_MAX_QUEUES 20
/**
 * Number of bytes a queue is allowed to send in one round of deficit round robin.
 */
#define NET_BOTTLENECK_QUANTUM 1514

struct net_bottleneck {
    struct net_node super;
    struct net_node *next_node;
    /**
     * The queues. `num_queues` is one unless the flows are isolated, in which case the packets are placed into the queue that
     * corresponds to their sender.
     */
    struct net_queue queues[NET_BOTTLENECK_MAX_QUEUES];
    size_t num_queues;
    /**
     * Total number of bytes being held, and the size of the buffer that holds them.
     */
    size_t size, capacity;
    /**
     * Packet size used for tail-drop admission, or zero to use the arriving packet's size. Setting this to the largest packet that
     * can enter the queue prevents smaller packets from consuming the residual space in which a larger packet would not fit.
     */
    size_t admission_mtu;
    double next_emit_at;
    double bytes_per_sec;
    /**
     * Parameters of the discipline the queues run; shared by all of them, unlike the state each queue keeps.
     */
    double target, interval;
};

struct net_endpoint {
    struct net_node super;
    quicly_address_t addr;
    double start_at;
    /**
     * Models a sender process being descheduled. An arriving packet selected by `probability` starts a blackout lasting `delay`;
     * it and every packet arriving during the blackout are processed together when `resume_at` is reached. Endpoint timers are
     * held as well, as they would be while the process is not running. During the data transfer, these incoming packets carry ACKs.
     */
    struct {
        struct net_queue queue;
        double probability;
        double delay;
        double resume_at;
    } ack_scheduler;
    struct net_endpoint_conn {
        quicly_conn_t *quic;
        struct net_node *egress;
    } conns[10];
    quicly_context_t *accept_ctx;
};

static struct net_packet *net_packet_create(struct net_endpoint *src, quicly_address_t *dest, ptls_iovec_t vec, uint8_t ecn)
{
    struct net_packet *p = malloc(offsetof(struct net_packet, bytes) + vec.len);

    p->next = NULL;
    p->src = src;
    p->dest = *dest;
    p->enter_at = now;
    p->ecn = ecn;
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
    return self->queue.first != NULL ? self->queue.first->enter_at + self->queue.delay : INFINITY;
}

static void net_delay_run(struct net_node *_self)
{
    struct net_delay *self = (struct net_delay *)_self;

    while (self->queue.first != NULL && self->queue.first->enter_at + self->queue.delay <= now) {
        struct net_packet *packet = net_queue_dequeue(&self->queue);
        self->next_node->forward_(self->next_node, packet);
    }
}

static void net_delay_init(struct net_delay *self, double delay)
{
    *self = (struct net_delay){
        .super = {net_delay_forward, net_delay_next_run_at, net_delay_run},
        .queue = {.append_at = &self->queue.first, .type = NET_QUEUE_DELAY, .delay = delay},
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
           now, self->size, ntohl(packet->src->addr.sin.sin_addr.s_addr), packet->size);
}

#define NET_ECN_NOT_ECT 0
#define NET_ECN_ECT1 1
#define NET_ECN_ECT0 2
#define NET_ECN_CE 3

/**
 * Turns ECT into CE, returning if the packet is ECN-capable. Packets that are not ECN-capable have to be dropped instead, as there
 * is no way of signalling congestion to their sender.
 */
static int net_bottleneck_mark(struct net_bottleneck *self, struct net_packet *packet)
{
    if (packet->ecn == NET_ECN_NOT_ECT)
        return 0;

    if (packet->ecn != NET_ECN_CE) {
        packet->ecn = NET_ECN_CE;
        net_bottleneck_print_stats(self, "mark", packet);
    }
    return 1;
}

static void net_bottleneck_drop(struct net_bottleneck *self, struct net_packet *packet)
{
    net_bottleneck_print_stats(self, "drop", packet);
    net_packet_destroy(packet);
}

/**
 * Returns the queue the packet belongs to; all of them share one when the flows are not isolated.
 */
static struct net_queue *net_bottleneck_classify(struct net_bottleneck *self, struct net_packet *packet)
{
    if (self->num_queues == 1)
        return &self->queues[0];

    uint32_t index = ntohl(packet->src->addr.sin.sin_addr.s_addr);
    assert(index < self->num_queues && "the endpoints are given addresses sequentially, starting from one");
    return &self->queues[index];
}

static struct net_queue *net_bottleneck_longest(struct net_bottleneck *self)
{
    struct net_queue *longest = &self->queues[0];

    for (size_t i = 1; i < self->num_queues; ++i)
        if (self->queues[i].size > longest->size)
            longest = &self->queues[i];

    return longest;
}

static void net_bottleneck_forward(struct net_node *_self, struct net_packet *packet)
{
    struct net_bottleneck *self = (struct net_bottleneck *)_self;
    struct net_queue *queue = net_bottleneck_classify(self, packet);

    /* a queue that has been idle becomes a new one, obtaining the right to send one quantum before the old ones do */
    if (queue->sched == NET_QUEUE_INACTIVE) {
        queue->deficit = NET_BOTTLENECK_QUANTUM;
        queue->sched = NET_QUEUE_NEW;
    }

    /* When the buffer is full, room is made by dropping from the head of the longest queue, so that a flow that does not slow
     * down cannot push the others out. Should the arrival belong to that queue itself there is nothing to be protected, hence it
     * is refused; that is what always happens when the flows are not isolated.
     * Section 4.2.1.2 of RFC 7141 identifies reserving the last buffer space usable by a large packet as the minimum necessary to
     * prevent large-packet lockout. `admission_mtu` therefore holds the largest configured packet size, unless `-B` is set. */
    size_t admission_size = self->admission_mtu != 0 ? self->admission_mtu : packet->size;
    while (self->size + admission_size > self->capacity) {
        struct net_queue *longest = net_bottleneck_longest(self);
        if (longest == queue || longest->first == NULL) {
            net_bottleneck_drop(self, packet);
            return;
        }
        struct net_packet *victim = net_queue_dequeue(longest);
        self->size -= victim->size;
        net_bottleneck_drop(self, victim);
    }

    net_bottleneck_print_stats(self, "enqueue", packet);
    net_queue_enqueue(queue, packet);
    self->size += packet->size;
}

static double net_codel_mark_next(struct net_bottleneck *self, double from, uint32_t count)
{
    return from + self->interval / sqrt((double)count);
}

/**
 * Takes the packet at the head of the queue, telling if CoDel considers the queue to have been standing for long enough that the
 * sender has to be told to slow down.
 */
static struct net_packet *net_codel_take(struct net_bottleneck *self, struct net_queue *queue, int *ok_to_mark)
{
    struct net_packet *packet;

    *ok_to_mark = 0;

    if (queue->first == NULL) {
        queue->codel.above_target_since = 0;
        return NULL;
    }
    packet = net_queue_dequeue(queue);
    self->size -= packet->size;

    /* the queue is not considered standing while it holds less than one packet worth of bytes; the quantum stands in for the MTU */
    if (now - packet->enter_at < self->target || queue->size <= NET_BOTTLENECK_QUANTUM) {
        queue->codel.above_target_since = 0;
    } else if (queue->codel.above_target_since == 0) {
        queue->codel.above_target_since = now + self->interval;
    } else if (now >= queue->codel.above_target_since) {
        *ok_to_mark = 1;
    }

    return packet;
}

/**
 * Dequeues one packet from the queue being given, running CoDel. Packets that are ECN-capable are marked and delivered; the ones
 * that are not are dropped, there being no other way of telling their sender to slow down.
 */
static struct net_packet *net_codel_dequeue(struct net_bottleneck *self, struct net_queue *queue)
{
    struct net_packet *packet;
    int ok_to_mark;

    if ((packet = net_codel_take(self, queue, &ok_to_mark)) == NULL) {
        queue->codel.marking = 0;
        return NULL;
    }

    if (queue->codel.marking) {
        if (!ok_to_mark) {
            queue->codel.marking = 0;
        } else {
            while (queue->codel.marking && now >= queue->codel.mark_next) {
                ++queue->codel.count;
                /* a packet that can be marked is delivered, the schedule being advanced all the same */
                if (net_bottleneck_mark(self, packet)) {
                    queue->codel.mark_next = net_codel_mark_next(self, queue->codel.mark_next, queue->codel.count);
                    break;
                }
                net_bottleneck_drop(self, packet);
                if ((packet = net_codel_take(self, queue, &ok_to_mark)) == NULL) {
                    queue->codel.marking = 0;
                    return NULL;
                }
                /* the schedule is advanced only while the queue is still standing; leaving the state must not push it back */
                if (!ok_to_mark) {
                    queue->codel.marking = 0;
                } else {
                    queue->codel.mark_next = net_codel_mark_next(self, queue->codel.mark_next, queue->codel.count);
                }
            }
        }
    } else if (ok_to_mark) {
        if (!net_bottleneck_mark(self, packet)) {
            net_bottleneck_drop(self, packet);
            if ((packet = net_codel_take(self, queue, &ok_to_mark)) == NULL)
                return NULL;
        }
        queue->codel.marking = 1;
        /* if the queue was left recently, resume from the rate that was being used back then */
        uint32_t delta = queue->codel.count - queue->codel.last_count;
        queue->codel.count = delta > 1 && now - queue->codel.mark_next < 16 * self->interval ? delta : 1;
        queue->codel.mark_next = net_codel_mark_next(self, now, queue->codel.count);
        queue->codel.last_count = queue->codel.count;
    }

    return packet;
}

/**
 * Dequeues one packet from the queue being given, applying whichever discipline it runs.
 */
static struct net_packet *net_bottleneck_dequeue_one(struct net_bottleneck *self, struct net_queue *queue)
{
    struct net_packet *packet;

    if (queue->type == NET_QUEUE_CODEL)
        return net_codel_dequeue(self, queue);

    if (queue->first == NULL)
        return NULL;
    packet = net_queue_dequeue(queue);
    self->size -= packet->size;

    /* mark-only; the packets that are not ECN-capable are left to the drop that happens when the buffer becomes full */
    if (queue->type == NET_QUEUE_STEP && now - packet->enter_at > self->target)
        net_bottleneck_mark(self, packet);

    return packet;
}

/**
 * Picks the queue to be served by deficit round robin, then dequeues one packet from it. The queues being few, they are scanned
 * rather than being kept in the lists that the real implementations of fq_codel maintain.
 */
static struct net_packet *net_bottleneck_dequeue(struct net_bottleneck *self)
{
    while (1) {
        struct net_queue *found = NULL;

        /* serve the queues that have just become active before the ones that have been */
        for (int sched = NET_QUEUE_NEW; sched <= NET_QUEUE_OLD && found == NULL; ++sched)
            for (size_t i = 0; i < self->num_queues; ++i)
                if (self->queues[i].sched == sched && self->queues[i].deficit > 0) {
                    found = &self->queues[i];
                    break;
                }

        if (found == NULL) {
            /* none of the active queues is allowed to send; start the next round, unless there is nothing to send at all */
            int any = 0;
            for (size_t i = 0; i < self->num_queues; ++i) {
                if (self->queues[i].sched != NET_QUEUE_INACTIVE) {
                    self->queues[i].deficit += NET_BOTTLENECK_QUANTUM;
                    any = 1;
                }
            }
            if (!any)
                return NULL;
            continue;
        }

        struct net_packet *packet;
        if ((packet = net_bottleneck_dequeue_one(self, found)) == NULL) {
            /* a new queue that has become empty becomes an old one rather than going idle, so that it does not obtain the
             * priority given to the new ones again as soon as it receives the next packet */
            found->sched = found->sched == NET_QUEUE_NEW ? NET_QUEUE_OLD : NET_QUEUE_INACTIVE;
            continue;
        }

        found->deficit -= (int32_t)packet->size;
        return packet;
    }
}

static double net_bottleneck_next_run_at(struct net_node *_self)
{
    struct net_bottleneck *self = (struct net_bottleneck *)_self;
    double emit_at = INFINITY;

    for (size_t i = 0; i < self->num_queues; ++i)
        if (self->queues[i].first != NULL && self->queues[i].first->enter_at < emit_at)
            emit_at = self->queues[i].first->enter_at;

    if (emit_at == INFINITY)
        return INFINITY;
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
    struct net_packet *packet;
    if ((packet = net_bottleneck_dequeue(self)) == NULL)
        return;
    net_bottleneck_print_stats(self, "dequeue", packet);

    /* update next emission timer */
    self->next_emit_at = now + (double)packet->size / self->bytes_per_sec;

    /* forward to the next node */
    self->next_node->forward_(self->next_node, packet);
}

static void net_bottleneck_init(struct net_bottleneck *self, double bytes_per_sec, double capacity_in_sec, struct net_aqm aqm,
                                int isolate_flows, size_t admission_mtu)
{
    *self = (struct net_bottleneck){
        .num_queues = isolate_flows ? NET_BOTTLENECK_MAX_QUEUES : 1,
        .capacity = (size_t)(bytes_per_sec * capacity_in_sec),
        .admission_mtu = admission_mtu,
        .bytes_per_sec = bytes_per_sec,
        .target = aqm.target,
        .interval = aqm.interval,
        .super = {net_bottleneck_forward, net_bottleneck_next_run_at, net_bottleneck_run},
    };

    int queue_type;
    switch (aqm.type) {
    case NET_AQM_STEP:
        queue_type = NET_QUEUE_STEP;
        break;
    case NET_AQM_CODEL:
        queue_type = NET_QUEUE_CODEL;
        break;
    default:
        queue_type = NET_QUEUE_PLAIN;
        break;
    }

    for (size_t i = 0; i < self->num_queues; ++i) {
        self->queues[i].append_at = &self->queues[i].first;
        self->queues[i].type = queue_type;
    }
}

static quicly_cid_plaintext_t next_quic_cid;

static void net_endpoint_receive(struct net_endpoint *self, struct net_packet *packet)
{
    size_t off = 0;
    while (off != packet->size) {
        /* decode packet */
        quicly_decoded_packet_t qp;
        if (quicly_decode_packet(self->conns[0].quic != NULL ? quicly_get_context(self->conns[0].quic) : self->accept_ctx, &qp,
                                 packet->bytes, packet->size, &off) == SIZE_MAX)
            break;
        qp.ecn = packet->ecn; /* the value is reset by `quicly_decode_packet`, as it is provided by the IP stack */
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
                              NULL, NULL) == 0) {
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

static void net_endpoint_forward(struct net_node *_self, struct net_packet *packet)
{
    struct net_endpoint *self = (struct net_endpoint *)_self;

    if (self->ack_scheduler.probability != 0) {
        if (self->ack_scheduler.resume_at != 0) {
            ++ack_scheduler_stats.queued_packets;
            net_queue_enqueue(&self->ack_scheduler.queue, packet);
            return;
        }
        ++ack_scheduler_stats.eligible_packets;
        if (rand() % 65536 < self->ack_scheduler.probability * 65536) {
            ++ack_scheduler_stats.stalls;
            ++ack_scheduler_stats.queued_packets;
            self->ack_scheduler.resume_at = now + self->ack_scheduler.delay;
            net_queue_enqueue(&self->ack_scheduler.queue, packet);
            return;
        }
    }

    net_endpoint_receive(self, packet);
}

static double net_endpoint_next_run_at(struct net_node *_self)
{
    struct net_endpoint *self = (struct net_endpoint *)_self;

    if (self->ack_scheduler.resume_at != 0)
        return self->ack_scheduler.resume_at;

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

    if (self->ack_scheduler.resume_at != 0) {
        assert(self->ack_scheduler.resume_at <= now);
        self->ack_scheduler.resume_at = 0;
        while (self->ack_scheduler.queue.first != NULL)
            net_endpoint_receive(self, net_queue_dequeue(&self->ack_scheduler.queue));
    }

    for (struct net_endpoint_conn *conn = self->conns; conn->quic != NULL; ++conn) {
        quicly_address_t dest, src;
        struct iovec datagrams[10];
        size_t num_datagrams = PTLS_ELEMENTSOF(datagrams);
        uint8_t buf[PTLS_ELEMENTSOF(datagrams) * 1500];
        int ret;
        if ((ret = quicly_send(conn->quic, &dest, &src, datagrams, &num_datagrams, buf, sizeof(buf))) == 0) {
            uint8_t ecn = quicly_send_get_ecn_bits(conn->quic);
            for (size_t i = 0; i < num_datagrams; ++i) {
                struct net_packet *packet =
                    net_packet_create(self, &dest, ptls_iovec_init(datagrams[i].iov_base, datagrams[i].iov_len), ecn);
                conn->egress->forward_(conn->egress, packet);
            }
        } else {
            assert(ret != QUICLY_ERROR_FREE_CONNECTION);
        }
    }
}

static void net_endpoint_init(struct net_endpoint *endpoint, double ack_scheduler_probability, double ack_scheduler_delay)
{
    *endpoint = (struct net_endpoint){
        .super = {net_endpoint_forward, net_endpoint_next_run_at, net_endpoint_run},
        .addr = new_address(),
        .ack_scheduler = {.queue = {.append_at = &endpoint->ack_scheduler.queue.first},
                          .probability = ack_scheduler_probability,
                          .delay = ack_scheduler_delay},
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

static void stream_destroy_cb(quicly_stream_t *stream, quicly_error_t err)
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

static void stream_on_stop_sending_cb(quicly_stream_t *stream, quicly_error_t err)
{
    assert(!"unexpected");
}

static void stream_on_receive_cb(quicly_stream_t *stream, size_t off, const void *src, size_t len)
{
    assert(!quicly_is_client(stream->conn));
    assert(!quicly_recvstate_transfer_complete(&stream->recvstate));

    if (stream->recvstate.data_off < stream->recvstate.received.ranges[0].end)
        quicly_stream_sync_recvbuf(stream, stream->recvstate.received.ranges[0].end - stream->recvstate.data_off);

    struct sockaddr *peer = quicly_get_peername(stream->conn);
    assert(peer->sa_family == AF_INET);
    uint32_t packet_src = ntohl(((struct sockaddr_in *)peer)->sin_addr.s_addr);

    printf("{\"bytes-available\": %" PRIu64 ", \"at\": %f, \"packet-src\": %" PRIu32 "}\n", stream->recvstate.data_off, now,
           packet_src);
}

static void stream_on_receive_reset_cb(quicly_stream_t *stream, quicly_error_t err)
{
    assert(!"unexpected");
}

static quicly_error_t stream_open_cb(quicly_stream_open_t *self, quicly_stream_t *stream)
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
           "  -a <prob[:secs]>   stalls ACK processing at given probability, batching arrivals\n"
           "                      until the stall ends (default duration: 0.001 seconds)\n"
           "  -c <cc>             sets congestion controller\n"
           "  -b <bytes_per_sec>  bottleneck bandwidth (default: 1000000, i.e., 1MB/s)\n"
           "  -B                  uses byte-fit rather than packet-size-neutral tail-drop admission\n"
           "  -d <delay_secs>     delay added between the sender and the botteneck\n"
           "                      (default: 0.1)\n"
           "  -i <packets>        sets initial CWND (default: %" PRIu32 ")\n"
           "  -E                  turns off ECN, which is otherwise used by every flow\n"
           "  -j <packets>        enables use of jumpstart using given window size\n"
           "  -l <seconds>        number of seconds to simulate (default: 100)\n"
           "  -m <bytes>          sets the maximum UDP payload size\n"
           "  -M                  disables packet-size normalization of congestion-control growth\n"
           "  -p                  turns on pacing\n"
           "  -q <seconds>        max depth of the bottleneck queue (default: 0.1)\n"
           "  -A <aqm>            queue discipline of the bottleneck: `none` (default),\n"
           "                      `step[:target]` marking CE on the packets whose sojourn\n"
           "                      time exceeds target seconds (default: 0.005), or\n"
           "                      `codel[:target[:interval]]` (defaults: 0.005, 0.1)\n"
           "  -F                  gives each flow a queue of its own; `-A codel -F` is\n"
           "                      fq_codel\n"
           "  -r <probability>    adds random loss at given probability (default: 0)\n"
           "  -R                  turns on rapid start\n"
           "  -s <seconds>        delay until the sender is added to the simulation\n"
           "                      (default: 0)\n"
           "  -t                  emits trace as well\n"
           "  -h                  print this help\n"
           "\n",
           cmd, quicly_spec_context.initcwnd_packets);
}

static void reset_getopt_state(void)
{
#if defined(__APPLE__)
    extern int optreset;
    optreset = 1;
#endif
    optind = 1;
}

static int find_next_separator(int argc, char **argv, int start)
{
    for (int i = start; i < argc; ++i)
        if (strcmp(argv[i], "--") == 0)
            return i;
    return argc;
}

/**
 * Parses the AQM spec, which is `none` or `step[:target_in_seconds]`.
 */
static int parse_aqm(const char *spec, struct net_aqm *aqm)
{
    if (strcmp(spec, "none") == 0) {
        *aqm = (struct net_aqm){.type = NET_AQM_NONE};
        return 1;
    }
    if (strncmp(spec, "step", 4) == 0 && (spec[4] == '\0' || spec[4] == ':')) {
        *aqm = (struct net_aqm){.type = NET_AQM_STEP, .target = 0.005};
        if (spec[4] == ':' && (sscanf(spec + 5, "%lf", &aqm->target) != 1 || aqm->target <= 0))
            return 0;
        return 1;
    }
    if (strncmp(spec, "codel", 5) == 0 && (spec[5] == '\0' || spec[5] == ':')) {
        *aqm = (struct net_aqm){.type = NET_AQM_CODEL, .target = 0.005, .interval = 0.1};
        if (spec[5] == ':') {
            if (sscanf(spec + 6, "%lf:%lf", &aqm->target, &aqm->interval) < 1)
                return 0;
            if (aqm->target <= 0 || aqm->interval <= 0)
                return 0;
        }
        return 1;
    }
    return 0;
}

static int parse_options(int argc, char **argv, quicly_context_t *quicctx, double *delay, double *start, double *bw, double *depth,
                         double *length, double *random_loss, struct net_aqm *aqm, int *isolate_flows, int *byte_fit_admission,
                         double *ack_scheduler_probability, double *ack_scheduler_delay, FILE **trace_fp)
{
    reset_getopt_state();
    int ch;
    while ((ch = getopt(argc, argv, "A:Ba:b:c:d:EFi:j:l:m:Mpq:r:Rs:th")) != -1) {

        switch (ch) {
        case 'a': {
            if (ack_scheduler_probability == NULL) {
                fprintf(stderr, "-%c is not available here\n", ch);
                return 0;
            }
            double probability, delay = 0.001;
            int consumed = 0;
            if (sscanf(optarg, "%lf:%lf%n", &probability, &delay, &consumed) != 2 || optarg[consumed] != '\0') {
                consumed = 0;
                delay = 0.001;
                if (sscanf(optarg, "%lf%n", &probability, &consumed) != 1 || optarg[consumed] != '\0') {
                    fprintf(stderr, "invalid ACK scheduler specification: %s\n", optarg);
                    return 0;
                }
            }
            if (!(0 <= probability && probability <= 1) || !(delay > 0)) {
                fprintf(stderr, "invalid ACK scheduler specification: %s\n", optarg);
                return 0;
            }
            *ack_scheduler_probability = probability;
            *ack_scheduler_delay = delay;
        } break;
        case 'c': {
            quicly_cc_type_t **cc;
            for (cc = quicly_cc_all_types; *cc != NULL; ++cc)
                if (strcmp((*cc)->name, optarg) == 0)
                    break;
            if (*cc == NULL) {
                fprintf(stderr, "unknown congestion controller: %s\n", optarg);
                return 0;
            }
            quicctx->init_cc = (*cc)->cc_init;
        } break;
        case 'A':
            if (aqm == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            if (!parse_aqm(optarg, aqm)) {
                fprintf(stderr, "invalid AQM: %s\n", optarg);
                return 0;
            }
            break;
        case 'B':
            if (byte_fit_admission == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            *byte_fit_admission = 1;
            break;
        case 'b':
            if (bw == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            if (sscanf(optarg, "%lf", bw) != 1) {
                fprintf(stderr, "invalid bandwidth: %s\n", optarg);
                return 0;
            }
            break;
        case 'd':
            if (sscanf(optarg, "%lf", delay) != 1) {
                fprintf(stderr, "invalid delay value: %s\n", optarg);
                return 0;
            }
            break;
        case 'i':
            if (sscanf(optarg, "%" PRIu32, &quicctx->initcwnd_packets) != 1) {
                fprintf(stderr, "invalid INITCWND size: %s\n", optarg);
                return 0;
            }
            break;
        case 'j':
            if (sscanf(optarg, "%" PRIu32, &quicctx->default_jumpstart_cwnd_packets) != 1) {
                fprintf(stderr, "invalid jumpstart window size: %s\n", optarg);
                return 0;
            }
            break;
        case 'l':
            if (length == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            if (sscanf(optarg, "%lf", length) != 1) {
                fprintf(stderr, "invalid length: %s\n", optarg);
                return 0;
            }
            break;
        case 'm': {
            uint16_t max_udp_payload_size;
            if (sscanf(optarg, "%" SCNu16, &max_udp_payload_size) != 1 || max_udp_payload_size < QUICLY_MIN_CLIENT_INITIAL_SIZE ||
                max_udp_payload_size > quicctx->transport_params.max_udp_payload_size) {
                fprintf(stderr, "invalid maximum UDP payload size: %s\n", optarg);
                return 0;
            }
            quicctx->initial_egress_max_udp_payload_size = max_udp_payload_size;
            quicctx->transport_params.max_udp_payload_size = max_udp_payload_size;
        } break;
        case 'M':
            quicctx->normalize_cc_mtu = 0;
            break;
        case 'p':
            quicctx->enable_ratio.pacing = 255;
            break;
        case 'q':
            if (depth == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            if (sscanf(optarg, "%lf", depth) != 1) {
                fprintf(stderr, "invalid queue depth: %s\n", optarg);
                return 0;
            }
            break;
        case 'r':
            if (random_loss == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            if (sscanf(optarg, "%lf", random_loss) != 1) {
                fprintf(stderr, "invalid random loss rate: %s\n", optarg);
                return 0;
            }
            break;
        case 'F':
            if (isolate_flows == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            *isolate_flows = 1;
            break;
        case 'E':
            quicctx->enable_ratio.ecn = 0;
            break;
        case 'R':
            quicctx->enable_ratio.rapid_start = 255;
            break;
        case 's':
            if (sscanf(optarg, "%lf", start) != 1) {
                fprintf(stderr, "invaild start: %s\n", optarg);
                return 0;
            }
            break;
        case 't':
            if (trace_fp == NULL) {
                fprintf(stderr, "-%c is a global option and cannot be used inside a flow block\n", ch);
                return 0;
            }
            *trace_fp = stdout;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(0);
        }
    }
    if (optind != argc) {
        fprintf(stderr, "unexpected token in args: %s\n", argv[optind]);
        return 0;
    }
    return 1;
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
    ERR_load_crypto_strings();
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

    net_endpoint_init(&server_node.node, 0, 0);
    server_node.accept_ctx = quicctx;
    server_node.node.accept_ctx = &server_node.accept_ctx;
    *node_insert_at++ = &server_node.node.super;

    /* parse args */
    struct net_aqm aqm = {.type = NET_AQM_NONE};
    int isolate_flows = 0, byte_fit_admission = 0;
    uint16_t queue_mtu = 0;
    double delay = 0.1, bw = 1e6, depth = 0.1, start = 0, random_loss = 0;
    double ack_scheduler_probability = 0, ack_scheduler_delay = 0.001;
    double length = 100;
    int first_sep = find_next_separator(argc, argv, 1);

    if (first_sep == argc) {
        fprintf(stderr, "missing flow separator `--`\n");
        usage(argv[0]);
        exit(1);
    }

    argv[first_sep] = NULL;
    if (!parse_options(first_sep, argv, &quicctx, &delay, &start, &bw, &depth, &length, &random_loss, &aqm, &isolate_flows,
                       &byte_fit_admission, &ack_scheduler_probability, &ack_scheduler_delay, &quicly_trace_fp))
        exit(1);
    argv[first_sep] = "--";

    int sender_count = 0;
    for (int seg_start = first_sep + 1; seg_start < argc;) {
        int seg_end = find_next_separator(argc, argv, seg_start);
        if (seg_end > seg_start) {
            /* the context is retained by the connection being created below, therefore it has to be allocated on heap */
            quicly_context_t *flow_ctx = malloc(sizeof(*flow_ctx));
            *flow_ctx = quicctx;
            double flow_delay = delay, flow_start = start;
            double flow_ack_scheduler_probability = ack_scheduler_probability, flow_ack_scheduler_delay = ack_scheduler_delay;

            int flow_argc = seg_end - seg_start + 1;
            char **flow_argv = &argv[seg_start - 1];
            char *saved_argv0 = flow_argv[0];
            char *saved = seg_end < argc ? argv[seg_end] : NULL;
            flow_argv[0] = argv[0];
            if (seg_end < argc)
                argv[seg_end] = NULL;

            if (!parse_options(flow_argc, flow_argv, flow_ctx, &flow_delay, &flow_start, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                               &flow_ack_scheduler_probability, &flow_ack_scheduler_delay, NULL))
                exit(1);
            flow_argv[0] = saved_argv0;
            if (seg_end < argc)
                argv[seg_end] = saved;

            if (queue_mtu < flow_ctx->initial_egress_max_udp_payload_size)
                queue_mtu = flow_ctx->initial_egress_max_udp_payload_size;

            struct net_delay *delay_node = malloc(sizeof(*delay_node));
            net_delay_init(delay_node, flow_delay);
            delay_node->next_node = &bottleneck_node.super;
            *node_insert_at++ = &delay_node->super;

            struct net_endpoint *client_node = malloc(sizeof(*client_node));
            net_endpoint_init(client_node, flow_ack_scheduler_probability, flow_ack_scheduler_delay);
            client_node->start_at = now + flow_start;
            int ret = quicly_connect(&client_node->conns[0].quic, flow_ctx, "hello.example.com", &server_node.node.addr.sa,
                                     &client_node->addr.sa, &next_quic_cid, ptls_iovec_init(NULL, 0), NULL, NULL, NULL);
            ++next_quic_cid.master_id;
            assert(ret == 0);
            quicly_stream_t *stream;
            ret = quicly_open_stream(client_node->conns[0].quic, &stream, 1);
            assert(ret == 0);
            ret = quicly_stream_sync_sendbuf(stream, 1);
            assert(ret == 0);
            client_node->conns[0].egress = &delay_node->super;
            *node_insert_at++ = &client_node->super;
            ++sender_count;
        }
        seg_start = seg_end + 1;
    }
    if (sender_count == 0) {
        fprintf(stderr, "no flow blocks found after --\n");
        exit(1);
    }

    /* setup bottleneck */
    net_bottleneck_init(&bottleneck_node, bw, depth, aqm, isolate_flows, byte_fit_admission ? 0 : queue_mtu);
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

    if (ack_scheduler_stats.eligible_packets != 0)
        printf("{\"ack-scheduler\": \"summary\", \"eligible-packets\": %" PRIu64 ", \"stalls\": %" PRIu64
               ", \"queued-packets\": %" PRIu64 "}\n",
               ack_scheduler_stats.eligible_packets, ack_scheduler_stats.stalls, ack_scheduler_stats.queued_packets);

    return 0;
}
