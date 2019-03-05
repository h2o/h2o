/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAXDROPS 64

struct connection_t {
    struct connection_t *prev, *next;
    size_t cid;
    int up_fd;
    struct {
        struct sockaddr_storage ss;
        socklen_t len;
    } down_addr;
    uint64_t packet_num_up;
    uint64_t packet_num_down;
};

struct queue_t {
    struct {
        size_t depth;
        size_t head;
        size_t tail;
        struct {
            struct connection_t *conn;
            uint8_t data[2048];
            size_t len;
            int64_t arrival;
        } * elements;
    } ring;
    int64_t delay_usec; /* propagation delay */
    int64_t interval_usec;  /* serialization delay */
    int64_t congested_until; /* in usec */
    uint64_t num_forwarded;
    uint64_t num_dropped;
    uint16_t num_drops;
    uint16_t drops[MAXDROPS];
} up = {{16}, 0, 10, 0, 0, 0, 0}, down = {{16}, 0, 10, 0, 0, 0, 0};

static int listen_fd = -1;
static struct addrinfo *server_addr = NULL;
static struct connection_t connections = {&connections, &connections};

static void usage(const char *cmd, int exit_status)
{
    printf("Usage: %s [options] <upstream-host> <upstream-port>\n"
           "\n"
           "Options:\n"
           "  -b <buffersize> size of the buffer for packets upstream (default: 16)\n"
           "  -B <buffersize> size of the buffer for packets downstream (default: 16)\n"
           "  -i <interval>   delay (in microseconds) to insert after sending one packet\n"
           "                  upstream (default: 10)\n"
           "  -I <interval>   delay (in microseconds) to insert after sending one packet\n"
           "                  downstream (default: 10)\n"
           "  -p <interval>   propagation delay (in microseconds) upstream (default: 0)\n"
           "  -P <interval>   propagation delay (in microseconds) downstream (default: 0)\n"
           "  -l <port>       port number to which the command binds\n"
           "  -d <packetnum>  packet number in connection to drop upstream\n"
           "  -D <packetnum>  packet number in connection to drop downstream\n"
           "  -h              prints this help\n"
           "\n",
           cmd);
    exit(exit_status);
}

static int64_t gettime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static int new_socket(int sin_family)
{
    int s = socket(sin_family, SOCK_DGRAM, IPPROTO_UDP);
    assert(s != -1);
    int flags = fcntl(s, F_GETFL, 0);
    assert(flags != -1);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    return s;
}

static struct connection_t *find_or_create_connection(struct sockaddr *sa, socklen_t salen)
{
    struct connection_t *c;
    static size_t cid;

    for (c = connections.next; c != &connections; c = c->next) {
        if (c->down_addr.ss.ss_family != sa->sa_family)
            continue;
        switch (c->down_addr.ss.ss_family) {
        case AF_INET: {
            struct sockaddr_in *x = (void *)&c->down_addr, *y = (void *)sa;
            if (!(memcmp(&x->sin_addr, &y->sin_addr, sizeof(x->sin_addr)) == 0 && x->sin_port == y->sin_port))
                continue;
        } break;
        case AF_INET6: {
            struct sockaddr_in6 *x = (void *)&c->down_addr, *y = (void *)sa;
            if (!(memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0 && x->sin6_port == y->sin6_port))
                continue;
        } break;
        default:
            assert(!"FIXME");
            break;
        }
        return c;
    }

    /* not found */
    c = malloc(sizeof(*c));
    assert(c != NULL);
    c->cid = cid++;
    c->up_fd = new_socket(server_addr->ai_family);
    if (connect(c->up_fd, server_addr->ai_addr, server_addr->ai_addrlen) != 0) {
        fprintf(stderr, "failed to connect to server:%s\n", strerror(errno));
        exit(1);
    }
    memcpy(&c->down_addr.ss, sa, salen);
    c->down_addr.len = salen;
    c->prev = connections.prev;
    c->next = &connections;
    connections.prev = c;
    c->prev->next = c;
    c->packet_num_up = 0;
    c->packet_num_down = 0;
    return c;
}

static void init_queue(struct queue_t *q)
{
    assert(q->ring.depth != 0);
    q->ring.head = 0;
    q->ring.tail = 0;
    q->ring.elements = malloc(sizeof(q->ring.elements[0]) * q->ring.depth);
    assert(q->ring.elements != NULL);
}

static void dequeue(struct queue_t *q, int up, int64_t now)
{
    if (q->ring.head == q->ring.tail)
        return;
    if (now < q->congested_until)
        return;
    if (up) {
        send(q->ring.elements[q->ring.head].conn->up_fd, q->ring.elements[q->ring.head].data, q->ring.elements[q->ring.head].len,
             0);
    } else {
        sendto(listen_fd, q->ring.elements[q->ring.head].data, q->ring.elements[q->ring.head].len, 0,
               (void *)&q->ring.elements[q->ring.head].conn->down_addr.ss, q->ring.elements[q->ring.head].conn->down_addr.len);
    }
    fprintf(stderr, "%" PRId64 ":%zu:%c:forward\n", now, q->ring.elements[q->ring.head].conn->cid, up ? 'u' : 'd');
    q->ring.head = (q->ring.head + 1) % q->ring.depth;
    if (q->ring.head == q->ring.tail)  // empty queue
        return;
    q->congested_until = now + q->interval_usec;  // next packet serialization delay
    if (q->ring.elements[q->ring.head].arrival + q->delay_usec > now)
        q->congested_until += q->ring.elements[q->ring.head].arrival + q->delay_usec - now;  // remainder of propagation delay
}

static int enqueue(struct queue_t *q, struct connection_t *conn, int64_t now)
{
    ssize_t readlen;
    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    int downstream = (conn != NULL);

    if ((readlen = recvfrom(downstream ? conn->up_fd : listen_fd, q->ring.elements[q->ring.tail].data,
                            sizeof(q->ring.elements[q->ring.tail].data), 0, downstream ? NULL : (void *)&ss,
                            downstream ? NULL : &sslen)) <= 0)
        return 0;
    
    if (!downstream) {
        conn = find_or_create_connection((void *)&ss, sslen);
    }

    assert(conn != NULL);
    uint64_t packet_num = downstream ? ++(conn->packet_num_down) : ++(conn->packet_num_up);
    /* check if packet should be dropped */
    if (q->num_drops > 0 && packet_num >= q->drops[0] && packet_num <= q->drops[q->num_drops - 1]) {
        int i = 0;
        while (i < q->num_drops) {
            if (packet_num == q->drops[i]) {
                fprintf(stderr, "%" PRId64 ":%zu:%c:droplist\n", now, conn->cid, downstream ? 'd' : 'u');
                return 1;
            }
            i++;
        }
    }

    q->ring.elements[q->ring.tail].len = readlen;
    q->ring.elements[q->ring.tail].conn = conn;
    q->ring.elements[q->ring.tail].arrival = now;
    
    size_t next_tail = (q->ring.tail + 1) % q->ring.depth;
    fprintf(stderr, "%" PRId64 ":%zu:%c:", now, q->ring.elements[q->ring.tail].conn->cid, downstream ? 'd' : 'u');

    if (next_tail == q->ring.head) {
        ++q->num_dropped;
        fprintf(stderr, "drop\n");
        return 1;
    }

    /* if head queued, dequeue after full propagation and serialization delay */
    if (q->ring.head == q->ring.tail)
        q->congested_until = now + q->delay_usec + q->interval_usec;
    q->ring.tail = next_tail;
    ++q->num_forwarded;
    fprintf(stderr, "queue\n");
    return 1;
}

static void on_signal(int signo)
{
    fprintf(stderr,
            "up:\n"
            "  forwarded: %" PRIu64 "\n"
            "  dropped: %" PRIu64 "\n"
            "down:\n"
            "  forwarded: %" PRIu64 "\n"
            "  dropped: %" PRIu64 "\n",
            up.num_forwarded, up.num_dropped, down.num_forwarded, down.num_dropped);
    if (signo == SIGINT)
        _exit(0);
}

int main(int argc, char **argv)
{
    int ch;

    signal(SIGINT, on_signal);
    signal(SIGHUP, on_signal);

    while ((ch = getopt(argc, argv, "b:B:i:I:p:P:l:d:D:h")) != -1) {
        switch (ch) {
        case 'b': /* size of the upstream buffer */
            if (sscanf(optarg, "%zu", &up.ring.depth) != 1 || up.ring.depth == 0) {
                fprintf(stderr, "argument to `-b` must be a positive number\n");
                exit(1);
            }
            break;
        case 'B': /* size of the downstream buffer */
            if (sscanf(optarg, "%zu", &down.ring.depth) != 1 || down.ring.depth == 0) {
                fprintf(stderr, "argument to `-D` must be a positive number\n");
                exit(1);
            }
            break;
        case 'i': /* interval (microseconds) between every packet being forwarded */
            if (sscanf(optarg, "%" PRId64, &up.interval_usec) != 1) {
                fprintf(stderr, "argument to `-i` must be an unsigned number\n");
                exit(1);
            }
            break;
        case 'I': /* interval (microseconds) between every packet being forwarded */
            if (sscanf(optarg, "%" PRId64, &down.interval_usec) != 1) {
                fprintf(stderr, "argument to `-i` must be an unsigned number\n");
                exit(1);
            }
            break;
        case 'p': /* propagation delay (microseconds) */
            if (sscanf(optarg, "%" PRId64, &up.delay_usec) != 1) {
                fprintf(stderr, "argument to `-p` must be an unsigned number\n");
                exit(1);
            }
            break;
        case 'P': /* propagation delay (microseconds) */
            if (sscanf(optarg, "%" PRId64, &down.delay_usec) != 1) {
                fprintf(stderr, "argument to `-P` must be an unsigned number\n");
                exit(1);
            }
            break;
        case 'l': { /* listen port */
            struct sockaddr_in sin;
            uint16_t port;
            if (sscanf(optarg, "%" SCNu16, &port) != 1) {
                fprintf(stderr, "argument to `-l` must be a port number\n");
                exit(1);
            }
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            listen_fd = new_socket(sin.sin_family);
            if (bind(listen_fd, (void *)&sin, sizeof(sin)) != 0) {
                fprintf(stderr, "failed to bind to 0.0.0.0:%" PRIu16 ": %s\n", port, strerror(errno));
                exit(1);
            }
        } break;
        case 'd': { /* packet to drop upstream*/
            uint16_t pnum;
            if (up.num_drops >= MAXDROPS)
                break;
            if (sscanf(optarg, "%" SCNu16, &pnum) != 1) {
                fprintf(stderr, "argument to `-d` must be an unsigned number\n");
                exit(1);
            }
            up.drops[up.num_drops++] = pnum;
        } break;
        case 'D': { /* packet to drop downstream */
            uint16_t pnum;
            if (down.num_drops >= MAXDROPS)
                break;
            if (sscanf(optarg, "%" SCNu16, &pnum) != 1) {
                fprintf(stderr, "argument to `-D` must be an unsigned number\n");
                exit(1);
            }
            down.drops[down.num_drops++] = pnum;
        } break;
        case 'h':
            usage(argv[0], 0);
            break;
        default:
            usage(argv[0], 1);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    if (listen_fd == -1) {
        fprintf(stderr, "mandatory option `-l` is missing\n");
        exit(1);
    }
    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        exit(1);
    }
    {
        struct addrinfo hints;
        int err;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
        if ((err = getaddrinfo(argv[0], argv[1], &hints, &server_addr)) != 0 || server_addr == NULL) {
            fprintf(stderr, "failed to resolve server address:%s:%s:%s\n", argv[0], argv[1], err != 0 ? gai_strerror(err) : "null");
            exit(1);
        }
    }

    init_queue(&up);
    init_queue(&down);

    while (1) {
        struct connection_t *c;
        /* select */
        fd_set fds;
        struct timeval timeout;
        FD_ZERO(&fds);
        FD_SET(listen_fd, &fds);
        int nfds = listen_fd + 1;
        for (c = connections.next; c != &connections; c = c->next) {
            FD_SET(c->up_fd, &fds);
            if (c->up_fd >= nfds)
                nfds = c->up_fd + 1;
        }
        int64_t now = gettime(), timeout_at = now + 1000000000;
        if (up.ring.head != up.ring.tail && up.congested_until < timeout_at)
            timeout_at = up.congested_until;
        if (down.ring.head != down.ring.tail && down.congested_until < timeout_at)
            timeout_at = down.congested_until;
        if (timeout_at <= now) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            int64_t d = timeout_at - now;
            timeout.tv_sec = d / 1000000;
            timeout.tv_usec = d % 1000000;
        }
        if (select(nfds, &fds, NULL, NULL, &timeout) <= 0)
            FD_ZERO(&fds);
        now = gettime();
        /* write */
        dequeue(&up, 1, now);
        dequeue(&down, 0, now);
        /* read from sockets */
        if (FD_ISSET(listen_fd, &fds)) {
            while (enqueue(&up, NULL, now))
                ;
        }
        for (c = connections.next; c != &connections; c = c->next) {
            if (FD_ISSET(c->up_fd, &fds)) {
                while (enqueue(&down, c, now))
                    ;
            } else {
                /* close idle connections */
            }
        }
    }

    return 0;
}
