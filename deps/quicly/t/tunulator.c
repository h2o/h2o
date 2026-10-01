/*
 * Implementation notes (see usage() for the interface):
 *
 * Packet handling:
 *   Attach to the configured Linux TUN using TUNSETIFF with IFF_TUN | IFF_NO_PI.
 *   Discard packets whose source and destination ports are both server ports, because their direction is ambiguous.
 *   Discard IPv4 fragments (MF set or nonzero fragment offset); noninitial fragments lack transport ports.
 *   To emulate one router hop, discard TTL <= 1; otherwise decrement TTL and update the IPv4 header checksum. The kernel's
 *   local-delivery path does not decrement TTL. The address swap preserves the IP and TCP/UDP pseudo-header sums, so
 *   transport checksums need no adjustment. With no link smaller than the fixed TUN MTU, no PMTUD handling is needed.
 *
 * Scheduling:
 *   Each direction has a propagation-delay stage followed by a shared FIFO bottleneck. Delay storage is separate from
 *   bottleneck capacity. Tail-drop arrivals when free buffer space is below one TUN MTU, regardless of packet size.
 *   At a fixed rate, an idle bottleneck emits immediately; emitting L IP bytes at
 *   rate w prevents another emission for L/w seconds. Do not accumulate transmission credit while idle. Use complete IP
 *   lengths for bandwidth and buffer accounting. Require nonnegative delay, positive rate, and buffers at least the TUN MTU.
 *   Optional CoDel marks ECN-capable packets or drops at the bottleneck before consuming bandwidth. Measure sojourn time excluding
 *   propagation delay and host scheduling jitter. With traces, inspect each packet only before its first transmission slot.
 *
 * Event loop:
 *   Use one thread, nonblocking TUN I/O, CLOCK_MONOTONIC, and select() with a timeout to the earliest absolute deadline.
 *   Continue reading even when the bottleneck is full, dropping in userspace to avoid an unmodelled kernel queue. Process
 *   due events between bounded read batches so continuous arrivals cannot starve timers. Retry interrupted I/O. Use
 *   nonblocking TUN writes and drop on EAGAIN, without queueing for retry or monitoring write readiness.
 *
 * Statistics:
 *   Use the current monotonic time when reading or writing each packet.
 *   In the select() loop, emit an object for each completed millisecond, including empty milliseconds after a late wakeup.
 *   Wake once per second to flush statistics when there is no I/O.
 *   Port reuse shares a series; tunulator does not track TCP connection lifetimes or QUIC connections multiplexed on one socket.
 */
/*
 * Copyright (c) 2026 Kazuho Oku
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
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/if_tun.h>
#include <math.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include "picotls.h"
#include "picotls/openssl.h"

#define NS_PER_MS UINT64_C(1000000)
#define NS_PER_SEC UINT64_C(1000000000)
#define NUM_FLOWS (2 * 65536)
#define READ_BATCH 32
#define EVENT_BATCH 64
#define TRACE_BYTES 1500

struct packet {
    struct packet *next;
    uint64_t at;
    unsigned flow;
    size_t len;
    uint8_t bytes[];
};

struct queue {
    struct packet *head, **tail;
    size_t bytes;
};

struct codel {
    uint64_t target, interval;
    int ecn;
    uint64_t first_above_time, drop_next;
    uint32_t count, lastcount;
    int dropping;
};

static const struct codel codel_defaults = {.target = 5 * NS_PER_MS, .interval = 100 * NS_PER_MS, .ecn = 1};

struct direction {
    struct queue delay, bottleneck;
    uint64_t delay_ns, rate, next_send;
    size_t capacity;
    double loss_probability;
    int use_codel;
    struct codel codel;
    struct {
        uint64_t *at, period, epoch;
        size_t count, index, remaining;
    } trace;
};

struct statistics {
    uint64_t bytes[NUM_FLOWS][4];
    unsigned active[NUM_FLOWS], num_active;
    uint64_t next_at;
    FILE *out;
};

struct tunulator {
    int fd;
    size_t mtu;
    struct in_addr peer;
    uint8_t server_ports[65536];
    struct direction dirs[2];
    struct statistics stats;
};

static void fail(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

static uint64_t get_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        fail("clock_gettime: %s", strerror(errno));
    return (uint64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static void random_bytes(void *dst, size_t len)
{
    static struct {
        ptls_cipher_context_t *cipher;
        size_t offset;
        uint8_t bytes[1024];
    } prng;

    if (prng.cipher == NULL) {
        struct {
            uint8_t key[PTLS_AES128_KEY_SIZE];
            uint8_t iv[PTLS_AES_IV_SIZE];
        } seed;

        ptls_openssl_random_bytes(&seed, sizeof(seed));
        prng.cipher = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, seed.key);
        assert(prng.cipher != NULL);
        ptls_cipher_init(prng.cipher, seed.iv);
        prng.offset = sizeof(prng.bytes);
        ptls_clear_memory(&seed, sizeof(seed));
    }
    assert(len <= sizeof(prng.bytes));

    if (sizeof(prng.bytes) - prng.offset < len) {
        ptls_cipher_encrypt(prng.cipher, prng.bytes, prng.bytes, sizeof(prng.bytes));
        prng.offset = 0;
    }
    memcpy(dst, prng.bytes + prng.offset, len);
    prng.offset += len;
}

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t)p[0] << 8 | p[1];
}

static void write16(uint8_t *p, uint16_t value)
{
    p[0] = value >> 8;
    p[1] = value;
}

static void init_queue(struct queue *q)
{
    q->head = NULL;
    q->tail = &q->head;
    q->bytes = 0;
}

static void enqueue(struct queue *q, struct packet *p)
{
    p->next = NULL;
    *q->tail = p;
    q->tail = &p->next;
    q->bytes += p->len;
}

static struct packet *dequeue(struct queue *q)
{
    struct packet *p = q->head;
    if ((q->head = p->next) == NULL)
        q->tail = &q->head;
    q->bytes -= p->len;
    return p;
}

static int codel_should_drop(struct codel *c, struct queue *q, size_t mtu, uint64_t now)
{
    /* Exclude the candidate packet from the backlog, as in RFC 8289, Section 5.6. p->at is its bottleneck arrival time. */
    struct packet *p = q->head;
    if (p == NULL || now - p->at < c->target || q->bytes - p->len <= mtu) {
        c->first_above_time = 0;
        return 0;
    }
    if (c->first_above_time == 0) {
        c->first_above_time = now + c->interval;
        return 0;
    }
    return now >= c->first_above_time;
}

static uint64_t codel_control_law(struct codel *c, uint64_t at)
{
    return at + (uint64_t)(c->interval / sqrt(c->count));
}

static int mark_ce(struct packet *p)
{
    if ((p->bytes[1] & 3) == 0)
        return 0;
    if ((p->bytes[1] & 3) != 3) {
        /* RFC 1624 incremental checksum update; preserve DSCP and the rest of the IPv4 header. */
        uint32_t sum = (uint16_t)~read16(p->bytes + 10) + (uint16_t)~read16(p->bytes);
        p->bytes[1] |= 3;
        sum += read16(p->bytes);
        sum = (sum & 65535) + (sum >> 16);
        sum = (sum & 65535) + (sum >> 16);
        write16(p->bytes + 10, ~sum);
    }
    return 1;
}

/* Apply RFC 8289 CoDel, leaving the selected packet at the head. Keeping it queued preserves buffer accounting while a trace
 * transmits it across multiple slots. Drops consume no bandwidth; the MTU guard ensures that a nonempty queue stays nonempty. */
static void codel_prepare(struct codel *c, struct queue *q, size_t mtu, uint64_t now)
{
    int should_drop = codel_should_drop(c, q, mtu, now);
    if (c->dropping) {
        if (!should_drop) {
            c->dropping = 0;
            return;
        }
        while (c->dropping && now >= c->drop_next) {
            if (c->count != UINT32_MAX)
                ++c->count;
            if (c->ecn && mark_ce(q->head)) {
                c->drop_next = codel_control_law(c, c->drop_next);
                return;
            }
            free(dequeue(q));
            if (!codel_should_drop(c, q, mtu, now))
                c->dropping = 0;
            else
                c->drop_next = codel_control_law(c, c->drop_next);
        }
    } else if (should_drop) {
        if (!c->ecn || !mark_ce(q->head)) {
            free(dequeue(q));
            codel_should_drop(c, q, mtu, now);
        }
        c->dropping = 1;
        uint32_t delta = c->count - c->lastcount;
        /* drop_next may still be in the future when reentering; avoid unsigned subtraction in that case. */
        c->count = delta > 1 && (now < c->drop_next || now - c->drop_next < 16 * c->interval) ? delta : 1;
        c->lastcount = c->count;
        c->drop_next = codel_control_law(c, now);
    }
}

static void emit_statistics(struct statistics *s)
{
    fputc('{', s->out);
    for (unsigned i = 0; i < s->num_active; ++i) {
        unsigned flow = s->active[i];
        uint64_t *b = s->bytes[flow];
        fprintf(s->out, "%s\"%c%u\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]", i == 0 ? "" : ",", flow >> 16 ? 't' : 'u',
                flow & 65535, b[0], b[1], b[2], b[3]);
        memset(b, 0, sizeof(s->bytes[flow]));
    }
    fputs("}\n", s->out);
    s->num_active = 0;
}

static void advance_statistics(struct statistics *s, uint64_t now)
{
    if (now < s->next_at)
        return;
    while (now >= s->next_at) {
        emit_statistics(s);
        s->next_at += NS_PER_MS;
    }
    if (fflush(s->out) != 0 || ferror(s->out))
        fail("writing statistics: %s", strerror(errno));
}

static void count_bytes(struct statistics *s, uint64_t now, unsigned flow, unsigned counter, size_t len)
{
    advance_statistics(s, now);
    uint64_t *b = s->bytes[flow];
    if ((b[0] | b[1] | b[2] | b[3]) == 0)
        s->active[s->num_active++] = flow;
    b[counter] += len;
}

static void receive_packet(struct tunulator *t, uint8_t *bytes, size_t len, uint64_t now)
{
    if (len < 20 || bytes[0] >> 4 != 4 || len > t->mtu || read16(bytes + 2) != len)
        return;
    size_t iplen = (bytes[0] & 15) * 4;
    if (iplen < 20 || iplen > len || (read16(bytes + 6) & 0x3fff) != 0)
        return;
    static const uint8_t loopback[] = {127, 0, 0, 1};
    if (memcmp(bytes + 12, loopback, 4) != 0 || memcmp(bytes + 16, &t->peer.s_addr, 4) != 0)
        return;
    unsigned proto = bytes[9];
    if (proto == IPPROTO_UDP) {
        if (len - iplen < 8 || read16(bytes + iplen + 4) != len - iplen)
            return;
    } else if (proto == IPPROTO_TCP) {
        if (len - iplen < 20)
            return;
        size_t tcplen = (bytes[iplen + 12] >> 4) * 4;
        if (tcplen < 20 || tcplen > len - iplen)
            return;
    } else {
        return;
    }

    uint16_t src = read16(bytes + iplen), dst = read16(bytes + iplen + 2);
    unsigned dir, port;
    if (t->server_ports[dst] && !t->server_ports[src]) {
        dir = 0;
        port = src;
    } else if (t->server_ports[src] && !t->server_ports[dst]) {
        dir = 1;
        port = dst;
    } else {
        return;
    }
    unsigned flow = (proto == IPPROTO_TCP ? 65536 : 0) | port;
    count_bytes(&t->stats, now, flow, dir * 2, len);
    if (bytes[8] <= 1)
        return;

    /* RFC 1624 incremental checksum update for the TTL/protocol word. */
    uint32_t sum = (uint16_t)~read16(bytes + 10) + (uint16_t)~read16(bytes + 8);
    --bytes[8];
    sum += read16(bytes + 8);
    sum = (sum & 65535) + (sum >> 16);
    sum = (sum & 65535) + (sum >> 16);
    write16(bytes + 10, ~sum);
    uint8_t addr[4];
    memcpy(addr, bytes + 12, 4);
    memcpy(bytes + 12, bytes + 16, 4);
    memcpy(bytes + 16, addr, 4);

    struct direction *d = &t->dirs[dir];
    if (d->delay_ns > UINT64_MAX - now)
        fail("propagation delay exceeds clock range");
    struct packet *p = malloc(sizeof(*p) + len);
    if (p == NULL)
        fail("allocating packet: %s", strerror(errno));
    p->at = now + d->delay_ns;
    p->flow = flow;
    p->len = len;
    memcpy(p->bytes, bytes, len);
    enqueue(&d->delay, p);
}

static uint64_t send_at(struct direction *d)
{
    if (d->bottleneck.head == NULL)
        return UINT64_MAX;
    if (d->trace.at != NULL) {
        uint64_t earliest = d->bottleneck.head->at;
        if (earliest >= d->trace.epoch + d->trace.period) {
            d->trace.epoch += (earliest - d->trace.epoch) / d->trace.period * d->trace.period;
            d->trace.index = 0;
        }
        while (d->trace.epoch + d->trace.at[d->trace.index] < earliest) {
            if (++d->trace.index == d->trace.count) {
                d->trace.index = 0;
                d->trace.epoch += d->trace.period;
            }
        }
        return d->trace.epoch + d->trace.at[d->trace.index];
    }
    return d->next_send > d->bottleneck.head->at ? d->next_send : d->bottleneck.head->at;
}

static uint64_t next_event(struct direction *d)
{
    uint64_t at = send_at(d);
    if (d->delay.head != NULL && d->delay.head->at < at)
        at = d->delay.head->at;
    return at;
}

static void send_packet(struct tunulator *t, unsigned dir, struct packet *p)
{
    struct direction *d = &t->dirs[dir];
    if (d->loss_probability != 0) {
        uint32_t value;
        random_bytes(&value, sizeof(value));
        if ((double)value / ((double)UINT32_MAX + 1) < d->loss_probability) {
            free(p);
            return;
        }
    }
    ssize_t ret;
    do {
        ret = write(t->fd, p->bytes, p->len);
    } while (ret < 0 && errno == EINTR);
    if (ret == (ssize_t)p->len) {
        count_bytes(&t->stats, get_now(), p->flow, dir * 2 + 1, p->len);
    } else if (ret >= 0) {
        fail("short TUN write: %zd of %zu bytes", ret, p->len);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fail("writing TUN: %s", strerror(errno));
    }
    free(p);
}

static void run_event(struct tunulator *t, unsigned dir, uint64_t at)
{
    struct direction *d = &t->dirs[dir];
    if (d->delay.head != NULL && d->delay.head->at <= at) {
        struct packet *p = dequeue(&d->delay);
        if (d->capacity - d->bottleneck.bytes < t->mtu)
            free(p);
        else
            enqueue(&d->bottleneck, p);
        return;
    }

    if (d->trace.at != NULL) {
        size_t budget = TRACE_BYTES;
        while (budget != 0 && d->bottleneck.head != NULL) {
            if (d->trace.remaining == 0) {
                if (d->use_codel)
                    codel_prepare(&d->codel, &d->bottleneck, t->mtu, at);
                d->trace.remaining = d->bottleneck.head->len;
            }
            size_t bytes = d->trace.remaining < budget ? d->trace.remaining : budget;
            d->trace.remaining -= bytes;
            budget -= bytes;
            if (d->trace.remaining == 0)
                send_packet(t, dir, dequeue(&d->bottleneck));
        }
        if (++d->trace.index == d->trace.count) {
            d->trace.index = 0;
            d->trace.epoch += d->trace.period;
        }
    } else {
        if (d->use_codel)
            codel_prepare(&d->codel, &d->bottleneck, t->mtu, at);
        struct packet *p = dequeue(&d->bottleneck);
        uint64_t duration = p->len * NS_PER_SEC;
        d->next_send = at + duration / d->rate + (duration % d->rate != 0);
        send_packet(t, dir, p);
    }
}

static void run_events(struct tunulator *t, uint64_t now)
{
    for (unsigned i = 0; i < EVENT_BATCH; ++i) {
        uint64_t up = next_event(&t->dirs[0]), down = next_event(&t->dirs[1]);
        unsigned dir = down < up;
        uint64_t at = dir ? down : up;
        if (at > now)
            break;
        run_event(t, dir, at);
    }
}

static void run_loop(struct tunulator *t)
{
    uint8_t bytes[65536];
    while (1) {
        run_events(t, get_now());
        for (unsigned i = 0; i < READ_BATCH; ++i) {
            ssize_t len = read(t->fd, bytes, sizeof(bytes));
            if (len > 0) {
                receive_packet(t, bytes, len, get_now());
            } else if (len == 0) {
                fail("TUN device closed");
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            } else if (errno != EINTR) {
                fail("reading TUN: %s", strerror(errno));
            }
        }
        uint64_t now = get_now();
        advance_statistics(&t->stats, now);
        uint64_t at = t->stats.next_at + NS_PER_SEC - NS_PER_MS;
        for (unsigned i = 0; i < 2; ++i) {
            uint64_t event = next_event(&t->dirs[i]);
            if (event < at)
                at = event;
        }
        now = get_now();
        uint64_t wait_ns = at > now ? at - now : 0;
        uint64_t wait_us = wait_ns / 1000 + (wait_ns % 1000 != 0);
        struct timeval timeout = {.tv_sec = wait_us / 1000000, .tv_usec = wait_us % 1000000};
        fd_set reads;
        FD_ZERO(&reads);
        FD_SET(t->fd, &reads);
        if (select(t->fd + 1, &reads, NULL, NULL, &timeout) < 0 && errno != EINTR)
            fail("select: %s", strerror(errno));
    }
}

static uint64_t parse_number(const char *value, uint64_t min, uint64_t max, const char *what)
{
    uint64_t n;
    if (sscanf(value, "%" SCNu64, &n) != 1 || n < min || n > max)
        fail("invalid %s: %s", what, value);
    return n;
}

static int parse_queue_discipline(struct direction *d, const char *value)
{
    struct codel c = codel_defaults;
    int use_codel = strcmp(value, "fifo") != 0;
    if (use_codel) {
        if (strncmp(value, "codel", 5) != 0)
            return 0;
        const char *p = value + 5;
        if (strncmp(p, "/noecn", 6) == 0) {
            c.ecn = 0;
            p += 6;
        }
        if (*p == ':') {
            uint64_t *fields[] = {&c.target, &c.interval};
            for (unsigned i = 0; i < 2; ++i) {
                if (*p != ':' || p[1] < '0' || p[1] > '9')
                    return 0;
                char *end;
                errno = 0;
                unsigned long long ms = strtoull(p + 1, &end, 10);
                if (errno != 0 || ms == 0 || ms > UINT32_MAX)
                    return 0;
                *fields[i] = ms * NS_PER_MS;
                p = end;
            }
            if (c.target >= c.interval)
                return 0;
        }
        if (*p != '\0')
            return 0;
    }
    d->use_codel = use_codel;
    d->codel = c;
    return 1;
}

static void load_trace(struct direction *d, const char *path, uint64_t start_ms)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        fail("opening trace %s: %s", path, strerror(errno));
    uint64_t *entries = NULL, ms;
    size_t count = 0, capacity = 0;
    int ret;
    while ((ret = fscanf(fp, "%" SCNu64, &ms)) == 1) {
        if (ms >= UINT64_MAX / NS_PER_MS || (count != 0 && ms < entries[count - 1]))
            fail("invalid timestamp in trace %s", path);
        if (count == capacity) {
            capacity = capacity == 0 ? 1024 : capacity * 2;
            if ((entries = realloc(entries, capacity * sizeof(*entries))) == NULL)
                fail("allocating trace: %s", strerror(errno));
        }
        entries[count++] = ms;
    }
    if (ret != EOF || ferror(fp) || count == 0)
        fail("invalid or empty trace: %s", path);
    fclose(fp);
    uint64_t period_ms = entries[count - 1] + 1;
    if (start_ms >= period_ms)
        fail("trace start offset must be below %" PRIu64 " ms", period_ms);

    free(d->trace.at);
    if ((d->trace.at = malloc(count * sizeof(*d->trace.at))) == NULL)
        fail("allocating trace: %s", strerror(errno));
    size_t first = 0;
    while (entries[first] < start_ms)
        ++first;
    for (size_t i = 0; i < count; ++i) {
        size_t source = (first + i) % count;
        uint64_t relative_ms = source >= first ? entries[source] - start_ms : period_ms - start_ms + entries[source];
        d->trace.at[i] = relative_ms * NS_PER_MS;
    }
    d->trace.count = count;
    d->trace.period = period_ms * NS_PER_MS;
    free(entries);
}

static int open_tun(const char *path, const char *name, size_t *mtu)
{
    if (strlen(name) >= IFNAMSIZ)
        fail("TUN interface name is too long: %s", name);
    int control = socket(AF_INET, SOCK_DGRAM, 0);
    if (control < 0)
        fail("opening interface control socket: %s", strerror(errno));
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, name);
    if (ioctl(control, SIOCGIFMTU, &ifr) != 0)
        fail("getting MTU of %s (configure the interface first): %s", name, strerror(errno));
    if (ifr.ifr_mtu < 68 || ifr.ifr_mtu > 65535)
        fail("invalid IPv4 MTU on %s: %d", name, ifr.ifr_mtu);
    *mtu = ifr.ifr_mtu;
    close(control);

    int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        fail("opening %s: %s", path, strerror(errno));
    if (fd >= FD_SETSIZE)
        fail("TUN descriptor exceeds select limit");
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) != 0)
        fail("attaching to %s: %s", name, strerror(errno));
    if (ioctl(fd, TUNSETOFFLOAD, 0) != 0)
        fail("disabling TUN offload: %s", strerror(errno));
    return fd;
}

static void usage(const char *cmd)
{
    printf("Usage: %s -t tun-file [options] peer-ip server-port [server-port ...]\n"
           "       %s -h\n"
           "\n"
           "Emulate a network between local TCP/UDP endpoints through a single TUN.\n"
           "Swap IPv4 addresses between peer-ip and 127.0.0.1, preserving ports.\n"
           "\n"
           "Options:\n"
           "  -t <tun-file>       TUN device path (required; Linux: /dev/net/tun)\n"
           "  -n <interface>      preconfigured Linux TUN interface (default: tun0)\n"
           "  -b <bytes>          upstream FIFO capacity (default: 100000)\n"
           "  -B <bytes>          downstream FIFO capacity (default: 100000)\n"
           "  -q <discipline>     upstream queue discipline (default: fifo)\n"
           "  -Q <discipline>     downstream queue discipline (default: fifo)\n"
           "  -w <bytes_per_sec>  upstream throughput (default: 4294967295, UINT32_MAX)\n"
           "  -W <bytes_per_sec>  downstream throughput (default: 4294967295, UINT32_MAX)\n"
           "  -F <file> <ms>      downstream bandwidth trace, starting at offset ms; replaces -W\n"
           "  -p <microseconds>   upstream propagation delay (default: 0)\n"
           "  -P <microseconds>   downstream propagation delay (default: 0)\n"
           "  -r <probability>    upstream random packet loss (0..1; default: 0)\n"
           "  -R <probability>    downstream random packet loss (0..1; default: 0)\n"
           "  -h                  print this help and exit\n"
           "\n"
           "peer-ip is the virtual IPv4 peer, followed by one or more local TCP/UDP server ports.\n"
           "Upstream means client-to-server; downstream means server-to-client.\n"
           "Directions have independent queues/rates; added base RTT is -p plus -P.\n"
           "All server ports share the same queue and rate in each direction.\n"
           "Disciplines: fifo, codel[:target_ms:interval_ms], or codel/noecn[:target_ms:interval_ms].\n"
           "CoDel defaults to a 5 ms target and 100 ms interval; times are positive integer milliseconds\n"
           "(up to 4294967295), with target below interval. Example: -Q codel:10:200.\n"
           "CoDel marks ECN-capable packets CE, otherwise drops; codel/noecn always drops.\n"
           "Marked packets consume bandwidth; dropped packets do not. Full buffers tail-drop.\n"
           "Its queue delay excludes propagation delay; buffer capacity still limits arrivals.\n"
           "Random losses occur after the bottleneck, consuming bandwidth.\n"
           "Trace files list millisecond timestamps, one per line, each allowing 1500 IP bytes.\n"
           "Repeated timestamps add capacity; unused capacity expires at that timestamp.\n"
           "Packets spanning entries are sent when their full length has been accounted for.\n"
           "Playback starts with forwarding and repeats after the last timestamp plus 1 ms.\n"
           "\n"
           "Statistics: emit a JSON object containing only active flows each millisecond\n"
           "on stdout, followed by a newline:\n"
           "  {\"u12345\":[2400,1200,80,80],\"t12347\":[1200,1200,0,0]}\n"
           "Keys are u (UDP) or t (TCP) followed by the client port. Arrays contain\n"
           "[up_received, up_sent, down_received, down_sent]\n"
           "IP bytes for that millisecond. Received is before drops; sent is a\n"
           "successful TUN write.\n"
           "\n"
           "Setup: route peer-ip through TUN with source 127.0.0.1, enable Linux\n"
           "route_localnet, and configure a fixed MTU. Do not assign peer-ip locally.\n"
           "Disable TUN checksum/segmentation offload. Only unfragmented IPv4 TCP/UDP\n"
           "is supported; routing and interface setup are external.\n"
           "\n"
           "Example (DSL profile, with IP-byte accounting):\n"
           "  %s -t /dev/net/tun -n tun0 -p 30000 -w 3750000 -b 187500 192.0.2.1 4433\n",
           cmd, cmd, cmd);
}

int main(int argc, char **argv)
{
    struct tunulator *t = calloc(1, sizeof(*t));
    if (t == NULL)
        fail("allocating state: %s", strerror(errno));
    for (unsigned i = 0; i < 2; ++i) {
        init_queue(&t->dirs[i].delay);
        init_queue(&t->dirs[i].bottleneck);
        t->dirs[i].rate = UINT32_MAX;
        t->dirs[i].capacity = 100000;
    }
    const char *path = NULL, *name = "tun0";
    int ch;
    while ((ch = getopt(argc, argv, "t:n:b:B:q:Q:w:W:F:p:P:r:R:h")) != -1) {
        switch (ch) {
        case 't':
            path = optarg;
            break;
        case 'n':
            name = optarg;
            break;
        case 'b':
        case 'B':
            t->dirs[ch == 'B'].capacity = parse_number(optarg, 1, SIZE_MAX, "buffer capacity");
            break;
        case 'w':
        case 'W':
            t->dirs[ch == 'W'].rate = parse_number(optarg, 1, UINT64_MAX, "throughput");
            break;
        case 'q':
        case 'Q':
            if (!parse_queue_discipline(&t->dirs[ch == 'Q'], optarg))
                fail("invalid queue discipline: %s (expected fifo or codel[/noecn][:target_ms:interval_ms]; "
                     "0 < target < interval <= 4294967295)",
                     optarg);
            break;
        case 'F':
            if (optind == argc)
                fail("missing trace start offset");
            load_trace(&t->dirs[1], optarg, parse_number(argv[optind++], 0, UINT64_MAX, "trace start offset"));
            break;
        case 'p':
        case 'P':
            t->dirs[ch == 'P'].delay_ns = parse_number(optarg, 0, UINT64_MAX / 1000, "propagation delay") * 1000;
            break;
        case 'r':
        case 'R': {
            double probability;
            if (sscanf(optarg, "%lf", &probability) != 1 || !(probability >= 0 && probability <= 1))
                fail("invalid random loss probability: %s", optarg);
            t->dirs[ch == 'R'].loss_probability = probability;
        } break;
        case 'h':
            usage(argv[0]);
            free(t);
            return EXIT_SUCCESS;
        default:
            free(t);
            return EXIT_FAILURE;
        }
    }
    if (path == NULL)
        fail("missing -t tun-file; use -h for help");
    if (argc - optind < 2)
        fail("expected peer-ip and at least one server-port; use -h for help");
    if (inet_pton(AF_INET, argv[optind], &t->peer) != 1)
        fail("invalid IPv4 peer: %s", argv[optind]);
    for (int i = optind + 1; i < argc; ++i)
        t->server_ports[parse_number(argv[i], 1, 65535, "server port")] = 1;
    t->fd = open_tun(path, name, &t->mtu);
    for (unsigned i = 0; i < 2; ++i)
        if (t->dirs[i].capacity < t->mtu)
            fail("%s buffer must hold at least one MTU (%zu bytes)", i == 0 ? "upstream" : "downstream", t->mtu);

    t->stats.out = stdout;
    uint64_t now = get_now();
    t->stats.next_at = now + NS_PER_MS;
    t->dirs[1].trace.epoch = now;
    run_loop(t);
    return EXIT_SUCCESS;
}
