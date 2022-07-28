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

static int get_num(int *n)
{
    int sign = 1, foundchar = 0, ch;

    *n = 0;

    while (1) {
        if ((ch = fgetc(stdin)) == EOF)
            break;
        if (!foundchar && ch == '-') {
            sign = -1;
            foundchar = 1;
        } else if ('0' <= ch && ch <= '9') {
            *n = *n * 10 + ch - '0';
            foundchar = 1;
        } else {
            ungetc(ch, stdin);
            break;
        }
    }

    *n *= sign;

    return foundchar ? 0 : -1;
}

static int get_num_list(int *list)
{
    int count = 0, n, ch;

    while (1) {
        if (get_num(&list[count]) == 0)
            ++count;
        if ((ch = fgetc(stdin)) == EOF)
            break;
        if (ch != ',') {
            ungetc(ch, stdin);
            break;
        }
    }

    return count;
}

int main(int argc, char **argv)
{
    verbose = getenv("IRQBALANCE_VERBOSE") != NULL;

    DEBUG_LOG("irqbalance starting\n");

    while (1) {
        struct irqbalance_bpf *obj;
        struct bpf_map *sockarray;

        /* get file descriptors for a socket group sharing one tuple */
        int allfds[1024], num_allfds = get_num_list(allfds);

        { /* next character must be LF */
            int ch;
            if ((ch = fgetc(stdin)) == EOF)
                break;
            if (ch != '\n') {
                fprintf(stderr, "unexpected char:%c\n", ch);
                return EX_CONFIG;
            }
        }

        DEBUG_LOG("read a socket group of %d sockets\n", num_allfds);

        if (num_allfds > IRQBALANCE_MAX_CPUS)
            fprintf(stderr, "too many file descriptors being supplied, ignoring some\n");

        /* load bpf */
        if ((obj = irqbalance_bpf__open_and_load()) == NULL) {
            fprintf(stderr, "failed to load BPF object:%s:%d\n", strerror(errno), errno);
            return EX_OSERR;
        }

        /* fill in the eBPF map */
        if ((sockarray = bpf_object__find_map_by_name(obj->obj, "sockarray")) == NULL) {
            fprintf(stderr, "failed to get map:%s:%d\n", strerror(errno), errno);
            return EX_OSERR;
        }
        int firstsockfd = -1;
        for (int i = 0; i < num_allfds; ++i) {
            if (allfds[i] != -1) {
                if (firstsockfd == -1)
                    firstsockfd = allfds[i];
                uint32_t key = i;
                uint64_t value = allfds[i];
                DEBUG_LOG("attaching fd %d to cpuid %d\n", allfds[i], i);
                if (bpf_map_update_elem(bpf_map__fd(sockarray), &key, &value, 0) != 0) {
                    fprintf(stderr, "failed to add fd %d to bpf map:%s:%d\n", allfds[i], strerror(errno), errno);
                    return EX_CONFIG;
                }
            }
        }
        if (firstsockfd == -1) {
            fprintf(stderr, "no valid fd for given socket group\n");
            return EX_CONFIG;
        }

        /* attach the program to the socket group */
        DEBUG_LOG("attaching the program to socket %d\n", firstsockfd);
        int progfd = bpf_program__fd(obj->progs.irqbalance);
        if (setsockopt(firstsockfd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &progfd, sizeof(progfd)) != 0) {
            fprintf(stderr, "failed to attach ebpf program to socket group:%s:%d\n", strerror(errno), errno);
            return EX_OSERR;
        }

        /* program loadded is left open - it is closed upon process exit */
    }

    return 0;
}
