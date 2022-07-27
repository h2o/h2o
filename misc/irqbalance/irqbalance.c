#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bpf/bpf.h"
#include "irqbalance.h"
#include "irqbalance.skel.h"

/* taken from sysexits.h */
#ifndef EX_OSERR
#define EX_OSERR 71
#endif
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

#define DEBUG_LOG(...)                                                                                                             \
    do {                                                                                                                           \
        if (verbose)                                                                                                               \
            fprintf(stderr, __VA_ARGS__);                                                                                          \
    } while (0)

struct sock_s {
    int fd;
    struct sockaddr_storage addr;
};

static int verbose = 0;

static int get_num(void)
{
    int n = 0, foundchar = 0, ch;

    while (1) {
        if ((ch = fgetc(stdin)) == EOF)
            break;
        if (!('0' <= ch && ch <= '9')) {
            ungetc(ch, stdin);
            break;
        }
        n = n * 10 + ch - '0';
        foundchar = 1;
    }

    return foundchar ? n : -1;
}

static int get_num_list(int *list)
{
    int count = 0, n, ch;

    while (1) {
        if ((n = get_num()) != -1)
            list[count++] = n;
        if ((ch = fgetc(stdin)) == EOF)
            break;
        if (ch != ':') {
            ungetc(ch, stdin);
            break;
        }
    }

    return count;
}

static int get_rank_of_sock(const struct sockaddr_storage *ss)
{
    switch (ss->ss_family) {
    case AF_INET:
        return ((struct sockaddr_in *)ss)->sin_addr.s_addr == INADDR_ANY ? 2 : 0;
        break;
    case AF_INET6:
        return memcmp(&((struct sockaddr_in6 *)ss)->sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0 ? 3 : 1;
    default:
        abort();
    }
}

static int compare_socks(const void *_x, const void *_y)
{
    const struct sock_s *x = _x, *y = _y;
    int x_rank = get_rank_of_sock(&x->addr), y_rank = get_rank_of_sock(&y->addr);

    /* 1. Non-global addresses are preferred above global addresses, because that's how the OS works without eBPF.
     * 2. V4 socket are preferred above v6, because when there is both v4 and v4-mapped v6, we want to route v4 connections to v4
     *    socket.
     * 3. Otherwise, use stable sort (i.e., preserve the order of the original array). */
    if (x_rank != y_rank) {
        return x_rank - y_rank;
    } else if (x < y) {
        return -1;
    } else {
        return 1;
    }
}

static int register_socks(uint32_t cpuid, struct bpf_map *map, struct sock_s *socks, int num)
{
    for (int i = 0; i < num; ++i) {
        DEBUG_LOG("registering fd %d\n", socks[i].fd);

        uint32_t key = cpuid * IRQBALANCE_MAX_SOCKS_PER_CPU + i;
        uint64_t value = socks[i].fd;
        if (bpf_map_update_elem(bpf_map__fd(map), &key, &value, 0) != 0) {
            fprintf(stderr, "failed to add fd %d to bpf map:%s:%d\n", socks[i].fd, strerror(errno), errno);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct irqbalance_bpf *obj;
    int netfd, ret;
    struct bpf_link *link;
    struct bpf_map *tcpmap, *udpmap;

    verbose = getenv("IRQBALANCE_VERBOSE") != NULL;

    DEBUG_LOG("irqbalance starting\n");

    if ((obj = irqbalance_bpf__open_and_load()) == NULL) {
        fprintf(stderr, "failed to load BPF object:%s:%d\n", strerror(errno), errno);
        return EX_OSERR;
    }

    if ((netfd = open("/proc/self/ns/net", O_RDONLY)) == -1) {
        fprintf(stderr, "failed to open /proc/self/ns/net:%s:%d\n", strerror(errno), errno);
        return EX_OSERR;
    }
    if ((link = bpf_program__attach_netns(obj->progs.irqbalance, netfd)) == NULL) {
        fprintf(stderr, "failed to attach BPF program:%s:%d\n", strerror(errno), errno);
        return EX_OSERR;
    }

    if ((tcpmap = bpf_object__find_map_by_name(obj->obj, "cpuid_tcp_sockmap")) == NULL) {
        fprintf(stderr, "failed to get map:%s:%d\n", strerror(errno), errno);
        return EX_OSERR;
    }
    if ((udpmap = bpf_object__find_map_by_name(obj->obj, "cpuid_udp_sockmap")) == NULL) {
        fprintf(stderr, "failed to get map:%s:%d\n", strerror(errno), errno);
        return EX_OSERR;
    }

    for (uint32_t cpuid = 0;; ++cpuid) {

        /* get file descriptors for current cpuid */
        int allfds[1024], num_allfds = get_num_list(allfds);

        { /* next character must be LF */
            int ch;
            if ((ch = fgetc(stdin)) == EOF)
                break;
            if (ch != '\n') {
                fprintf(stderr, "unexpected char:%c\n", ch);
                return 1;
            }
        }

        /* build per-protocol list */
        struct {
            struct sock_s socks[IRQBALANCE_MAX_SOCKS_PER_CPU];
            int num;
        } tcpsocks = {}, udpsocks = {};
        for (int i = 0; i < num_allfds; ++i) {
            DEBUG_LOG("working on fd %d\n", allfds[i]);
            /* determine type of the socket and where to add */
            struct sock_s *sock;
            int socktype;
            socklen_t socktypelen = sizeof(socktype);
            if (getsockopt(allfds[i], SOL_SOCKET, SO_TYPE, &socktype, &socktypelen) != 0) {
                fprintf(stderr, "failed to obtain socket type for fd %d:%s:%d\n", allfds[i], strerror(errno), errno);
                return EX_CONFIG;
            }
            switch (socktype) {
            case SOCK_STREAM:
                if (tcpsocks.num >= sizeof(tcpsocks.socks) / sizeof(tcpsocks.socks[0])) {
                    fprintf(stderr, "too many TCP sockets, ignoring fd %d\n", allfds[i]);
                    continue;
                }
                sock = &tcpsocks.socks[tcpsocks.num++];
                break;
            case SOCK_DGRAM:
                if (udpsocks.num >= sizeof(udpsocks.socks) / sizeof(udpsocks.socks[0])) {
                    fprintf(stderr, "too many UDP sockets, ignoring fd %d\n", allfds[i]);
                    continue;
                }
                sock = &udpsocks.socks[udpsocks.num++];
                break;
            default:
                fprintf(stderr, "fd %d has unknown socket type %d\n", allfds[i], socktype);
                return EX_CONFIG;
            }
            sock->fd = allfds[i];
            /* get address */
            socklen_t salen = sizeof(sock->addr);
            if (getsockname(sock->fd, (struct sockaddr *)&sock->addr, &salen) != 0) {
                fprintf(stderr, "failed to obtain local address of fd %d:%s:%d\n", sock->fd, strerror(errno), errno);
                return EX_OSERR;
            }
            switch (sock->addr.ss_family) {
            case AF_INET:
            case AF_INET6:
                break;
            default:
                fprintf(stderr, "fd %d has unexpected address family %d\n", sock->fd, (int)sock->addr.ss_family);
                break;
            }
        }

        qsort(tcpsocks.socks, tcpsocks.num, sizeof(tcpsocks.socks[0]), compare_socks);
        qsort(udpsocks.socks, udpsocks.num, sizeof(udpsocks.socks[0]), compare_socks);

        DEBUG_LOG("registering TCP sockets for cpuid %" PRIu32 "\n", cpuid);
        if (register_socks(cpuid, tcpmap, tcpsocks.socks, tcpsocks.num) != 0)
            return EX_OSERR;

        DEBUG_LOG("registering UDP sockets for cpuid %" PRIu32 "\n", cpuid);
        if (register_socks(cpuid, udpmap, udpsocks.socks, udpsocks.num) != 0)
            return EX_OSERR;
    }

    return 0;
}
