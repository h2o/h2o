#include "h2o.h"
#include "h2o/busypoll.h"

#include <errno.h>
#include <error.h>

#if defined(__linux__) && defined(SO_REUSEPORT) && defined(H2O_HAS_YNL_H)
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <ynl/ynl.h>
#include <ynl/netdev-user.h>

static __thread int cpu_claimed = 0;
static __thread const char *nic_claimed = NULL;
static __thread unsigned int napi_id_claimed = 0;

static void setup_queue(uint32_t cfg_ifindex, uint32_t cfg_defer_hard_irqs, uint64_t cfg_gro_flush_timeout,
                        uint64_t cfg_irq_suspend_timeout)
{
    struct netdev_napi_get_list *napi_list = NULL;
    struct netdev_napi_get_req_dump *req = NULL;
    struct netdev_napi_set_req *set_req = NULL;
    struct ynl_sock *ys;
    struct ynl_error yerr;
    uint32_t napi_id = 0;

    ys = ynl_sock_create(&ynl_netdev_family, &yerr);
    if (!ys)
        error(1, 0, "YNL: %s", yerr.msg);

    req = netdev_napi_get_req_dump_alloc();
    netdev_napi_get_req_dump_set_ifindex(req, cfg_ifindex);
    napi_list = netdev_napi_get_dump(ys, req);

    /* assume there is 1 NAPI configured and take the first */
    if (napi_list->obj._present.id)
        napi_id = napi_list->obj.id;
    else
        error(1, 0, "napi ID not present?");

    set_req = netdev_napi_set_req_alloc();
    netdev_napi_set_req_set_id(set_req, napi_id);
    netdev_napi_set_req_set_defer_hard_irqs(set_req, cfg_defer_hard_irqs);
    netdev_napi_set_req_set_gro_flush_timeout(set_req, cfg_gro_flush_timeout);
    netdev_napi_set_req_set_irq_suspend_timeout(set_req, cfg_irq_suspend_timeout);

    if (netdev_napi_set(ys, set_req))
        error(1, 0, "can't set NAPI params: %s\n", yerr.msg);

    netdev_napi_get_list_free(napi_list);
    netdev_napi_get_req_dump_free(req);
    netdev_napi_set_req_free(set_req);
    ynl_sock_destroy(ys);
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

void attach_cbpf(int fd, uint16_t cpus, const char *iface)
{
    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    uint16_t n = cpus;
    int ret = 0;

    ret = getsockname(fd, (struct sockaddr *)&ss, &sslen);
    if (ret != 0) {
        fprintf(stderr, "getsockname failed on listener: %s\n", strerror(errno));
    }
    if (ss.ss_family == AF_UNIX) {
        fprintf(stderr, "dont add reuseport filter to AF_UNIX socket listener\n");
        return;
    } else if (ss.ss_family == AF_INET) {
        fprintf(stderr, "will add filter to AF_INET socket\n");
    } else if (ss.ss_family == AF_INET6) {
        fprintf(stderr, "will add filter to AF_INET6 socket\n");
    } else {
        fprintf(stderr, "unknown family: %lu, adding\n", (unsigned long)ss.ss_family);
    }

    struct sock_filter code[] = {
        /* A = skb->queue_mapping */
        {BPF_LD | BPF_W | BPF_ABS, 0, 0, SKF_AD_OFF + SKF_AD_QUEUE},
        /* A = A % n */
        {BPF_ALU | BPF_MOD, 0, 0, n},
        /* return A */
        {BPF_RET | BPF_A, 0, 0, 0},
    };

    struct sock_fprog p = {
        .len = ARRAY_SIZE(code),
        .filter = code,
    };

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &p, sizeof(p))) {
        char buf[128];
        h2o_fatal("failed to set SO_ATTACH_REUSEPORT_CBPF: %d:%s", errno, h2o_strerror_r(errno, buf, sizeof(buf)));
    } else {
        fprintf(stderr, "bpf prog attached to fd:%d, queues: %u\n", fd, cpus);
    }

    return;
}

void bind_interface(int fd, const char *iface)
{
    /* setting SO_BINDTODEVICE causes listen sockets with the same
     * attributes (address, port, nic index) to be part of the same
     * reuseport group.
     *
     * this is critical because if the nic index is not set with
     * BINDTODEVICE, the reuseport group will receive incoming connections
     * from any NIC and the cBPF program which does a modulo on the
     * queue_mapping will fail (since multiple NICs each can have the same
     * queue mapping)
     */
    if (iface && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) == -1) {
        h2o_perror("failed to SO_BINDTODEVICE");
        abort();
    }

    if (iface) {
        fprintf(stderr, "bound %d to iface: %s\n", fd, iface);
    }
}

static unsigned int get_napi_id(int fd)
{
#if !defined(SIOCGIFNAME_BY_NAPI_ID)
#define SIOCGIFNAME_BY_NAPI_ID (0x894D)
#endif
    unsigned int napi_id = 0;
    socklen_t napi_id_len = sizeof(napi_id);

    if (getsockopt(fd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &napi_id_len) != 0) {
        h2o_perror("so_napi_incoming_id failed");
    }

    return napi_id;
}

static int get_nic_name_by_napi(int fd, unsigned int napi_id, struct ifreq *ifr)
{
    ifr->ifr_ifru.ifru_ivalue = napi_id;

    return ioctl(fd, SIOCGIFNAME_BY_NAPI_ID, ifr);
}

/*
 * -2  error
 * -1  unix socket
 *  0  non-local INET (or INET6) connection
 *  1  local INET (or INET6) connection
 */
static int is_local_conn(int fd)
{
    int is_local = -2;
    int domain = AF_UNSPEC;
    socklen_t domain_size = sizeof(domain);
    int r = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_size);
    if (r < 0) {
        h2o_perror("getsockopt SO_DOMAIN failed");
        return -2;
    }
    if (domain_size != sizeof(domain)) {
        h2o_perror("getsockopt SO_DOMAIN length mismatch");
        return -2;
    }

    /* unix sockets are not the sockets we are looking for */
    if (domain == AF_UNIX || domain == AF_LOCAL) {
        return -1;
    }

    return is_local;
}

static int assign_nic_map_cpu(h2o_loop_t *loop, const char *iface, size_t thread_index, int napi_id, int listener_fd, int is_lo,
                              struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count)
{
    int found = 0;
    for (int i = 0; i < nic_count; i++) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);

        if (strcmp(nic_to_cpu_map[i].iface.base, iface) == 0) {
            fprintf(stderr, "found matching iface in conf map: %s\n", iface);
            pthread_mutex_lock(&nic_to_cpu_map[i].mutex);
            for (int j = 0; j < get_nprocs_conf(); j++) {

                if (CPU_ISSET(j, &nic_to_cpu_map[i].cpu_map)) {
                    /* take the first CPU that is set, and clear it so other threads can't have it */
                    CPU_CLR(j, &nic_to_cpu_map[i].cpu_map);

                    /* set the CPU in this threads temporary set so the thread can pin itself */
                    CPU_SET(j, &cpuset);
                    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

                    /* if using neverbleed, the neverbleed threads inherit
                     * their CPU set from the default h2o mask (which
                     * excludes busy poll CPUs).
                     *
                     * all that is left to do is ensure that yield (sleep)
                     * on read is disabled.
                     */

                    /* FIXME:
                    if (neverbleed != NULL) {
                        set_yield_on_read(neverbleed, 0);
                    }
                    */

                    fprintf(stderr, "thread idx %zd, has taken cpu: %d, for NIC: %s, via napi: %d via listener %d\n", thread_index,
                            j, nic_to_cpu_map[i].iface.base, napi_id, listener_fd);

                    /* we can print which listener the accept arrived on to
                     * help debug / figure out why this thread took this
                     * CPU.
                     *
                     * some ifaces, like lo, pass listener_fd = 0, so there
                     * would be nothing to print.
                     */
                    if (listener_fd > 0) {
                        int ret;
                        struct sockaddr_storage ss;
                        socklen_t len = sizeof(ss);
                        ret = getsockname(listener_fd, (struct sockaddr *)&ss, &len);
                        if (ret != 0) {
                            fprintf(stderr, "getsockname failed on listener: %s\n", strerror(errno));
                        }
                    }

                    struct busypoll_nic_t *nic = &nic_to_cpu_map[i];
                    if (nic && nic->mode == BP_MODE_SUSPEND) {
                        h2o_loop_set_bp_prefer(loop, 1);
                    }
                    nic_claimed = nic->iface.base;
                    napi_id_claimed = napi_id;
                    found = 1;
                    cpu_claimed = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&nic_to_cpu_map[i].mutex);
            if (found)
                break;
        }
    }

    return found;
}

static void handle_nic_map_accept(h2o_socket_t *sock, h2o_socket_t *listener, size_t thread_index,
                                  struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count)
{
    /* this would probably be set per-listener or something as sndbuf and rcvbuf are below ? */
    int sockfd = h2o_socket_get_fd(sock);
    unsigned int napi_id = 0;
    int prio = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) != 0) {
        h2o_perror("so_priority failed");
    }

    napi_id = get_napi_id(sockfd);

    /* if this thread has claimed a CPU, check the incoming connection to make sure it is correct */
    if (cpu_claimed) {
        /* start by getting a verdict on the incoming connection */
        int verdict = is_local_conn(sockfd);
        if (verdict == -2) {
            /* some sort of error, is_local printed something but there's nothing for us to do. */
            return;
        } else if (verdict == -1) {
            /* socket is a unix socket, which we can ignore */
            return;
        }

        /* at this point the verdict is either 0 (not local) or 1 (is local) */

        /* the cases to check are:
         *
         * - this thread claimed a NAPI ID > 0 and the connection matches.
         *   in this case, there is nothing to do because a non-zero NAPI ID
         *   must have come from an RX queue on a real NIC.
         *
         * - this thread claimed a NAPI ID > 0 and the connection MISmatches.
         *   in this case, if the connection is from a unix socket, it is OK.
         *   but any other case (including if it is from loopback) is a bug.
         *
         * - this thread claimed NAPI ID of 0 and the connection matches.
         *   in this case, we need to make sure that the connection is really
         *   a local connection (via is_local)
         *
         * - this thread claimed NAPI ID of 0 and the connection mismatches.
         *   in this case, this is a bug.
         */

        /* this thread claimed a NAPI ID for a "real" NIC... */
        if (napi_id_claimed > 0) {
            /* handle the easiest case first, the IDs match and are non-zero.
             *
             * it *should be impossible* for is_local to return true.
             */
            if (napi_id_claimed == napi_id) {
                if (verdict == 1) {
                    /* this is extremely unexpected. */
                    fprintf(stderr, "thread: %lu claimed NIC %s [%d]. NAPI IDs match but connection is local?\n", thread_index,
                            nic_claimed, napi_id_claimed);
                }
                return;
            }

            /* next case, the IDs mismatch */
            if (napi_id_claimed != napi_id) {
                /* this is a bug no matter what -- but let's check is_local to help debug */
                struct ifreq ifr = {};
                const char *mismatch_nic_name = NULL;

                if (get_nic_name_by_napi(sockfd, napi_id, &ifr) == -1) {
                    fprintf(stderr, "SIOCGIFNAME_BY_NAPI_ID failed ? %d\n", napi_id);
                    h2o_perror("SIOCGIFNAME_BY_NAPI_ID failed");
                }

                mismatch_nic_name = "unknown";
                if (strlen(ifr.ifr_name) > 0)
                    mismatch_nic_name = ifr.ifr_name;

                struct sockaddr_in localaddr;
                socklen_t localaddrlen = sizeof(localaddr);

                int ret = getsockname(sockfd, (struct sockaddr *)&localaddr, &localaddrlen);
                if (ret == -1) {
                    h2o_perror("getpeername failed");
                }

                /* INET6_ADDRSTRLEN should be long enough to hold both v4
                 * and v6 addresses, so we'll use INET6_ADDRSTRLEN even if
                 * it isn't strictly necessary if the family is AF_INET.
                 */
                char laddr[INET6_ADDRSTRLEN] = {0};
                if (inet_ntop(localaddr.sin_family, &localaddr.sin_addr, laddr, INET6_ADDRSTRLEN) == NULL) {
                    h2o_perror("inet_ntop couldn't convert addr");
                }

                fprintf(stderr,
                        "thread: %lu claimed NIC %s [%d]. NAPI IDs MISmatch [%d from %s], is_local: %d, laddr: %s, lport: %d, "
                        "family: %d\n",
                        thread_index, nic_claimed, napi_id_claimed, napi_id, mismatch_nic_name, verdict, laddr,
                        ntohs(localaddr.sin_port), localaddr.sin_family);
                return;
            }
        } else {
            /* if this thread claimed the loopback device, let's make sure the incoming
             * connection is actually a loopback connection with napi id of 0
             */
            if (napi_id == 0) {
                if (verdict == 1) {
                    /* is_local returned 1, as expected, so this socket is fine */
                    return;
                }

                if (verdict == 0) {
                    /* is_local returned 0, so this NAPI ID matches and is correct but is not a local connection */
                    fprintf(stderr, "thread: %lu claimed loopback, got a loopback connection, but conn is NOT local\n",
                            thread_index);
                }
            } else {
                /* in this case the the connection has a mismatched NAPI ID. Let's check if its local to help debug */
                fprintf(stderr, "thread: %lu claimed loopback [%d] but received non-zero NAPI ID [%d] is local: %d\n", thread_index,
                        napi_id_claimed, napi_id, verdict);
                return;
            }
        }
    } else {
        /* a CPU has not been claimed yet, so claim one */
        int listener_fd = h2o_socket_get_fd(listener);
        struct ifreq ifr = {};

        if (get_nic_name_by_napi(sockfd, napi_id, &ifr) == -1) {
            fprintf(stderr, "SIOCGIFNAME_BY_NAPI_ID failed ? %d\n", napi_id);
            h2o_perror("SIOCGIFNAME_BY_NAPI_ID failed");
        }

        fprintf(stderr, "thread %zd NAPI id: %u, iface: %s, listener fd: %d\n", thread_index, napi_id, ifr.ifr_name, listener_fd);

        int found = assign_nic_map_cpu(h2o_socket_get_loop(sock), ifr.ifr_name, thread_index, napi_id, listener_fd, 0, nic_to_cpu_map, nic_count);

        if (!found) {
            fprintf(stderr, "no CPU found for thread with NAPI from NIC: %s:%d\n", ifr.ifr_name, napi_id);
            fprintf(stderr, "busy-poll-cpu-map configuration or queue setup is buggy -- exiting h2o now.\n");
            exit(-1);
        }
    }

    return;
}

void h2o_busypoll_bind_interface(int fd, const char *iface)
{
    bind_interface(fd, iface);
}

void h2o_busypoll_set_opts(uint32_t ifindex, uint32_t defer_hard_irqs, uint64_t gro_flush_timeout, uint64_t irq_suspend_timeout)
{
    setup_queue(ifindex, defer_hard_irqs, gro_flush_timeout, irq_suspend_timeout);
}

void h2o_busypoll_attach_cbpf(int fd, uint16_t cpus, const char *iface)
{
    attach_cbpf(fd, cpus, iface);
}

void h2o_busypoll_handle_nic_map_accept(h2o_socket_t *sock, h2o_socket_t *listener, size_t thread_index,
                                        struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count)
{
    handle_nic_map_accept(sock, listener, thread_index, nic_to_cpu_map, nic_count);
}

#else

void h2o_busypoll_bind_interface(int fd, const char *iface)
{
    /* noop */
}

void h2o_busypoll_set_opts(uint32_t ifindex, uint32_t defer_hard_irqs, uint64_t gro_flush_timeout, uint64_t irq_suspend_timeout)
{
    /* noop */
}

void h2o_busypoll_attach_cbpf(int fd, uint16_t cpus, const char *iface)
{
    /* noop */
}

void h2o_busypoll_handle_nic_map_accept(h2o_socket_t *sock, h2o_socket_t *listener, size_t thread_index,
                                        struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count)
{
    /* noop */
}

#endif

