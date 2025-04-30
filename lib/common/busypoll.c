#include "h2o.h"

#include "h2o/busypoll.h"
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
                        uint64_t cfg_irq_suspend_timeout, uint32_t *napi_ids, size_t napi_ids_size)
{
    struct netdev_queue_get_req *get_req = NULL;
    struct netdev_napi_set_req *set_req = NULL;
    struct ynl_sock *ys;
    struct ynl_error yerr;

    ys = ynl_sock_create(&ynl_netdev_family, &yerr);
    if (!ys)
        h2o_fatal("ynl, failed to create socket: %s\n", yerr.msg);

    /* fetch napi ids for first available queues on the provided interface */
    for (int i = 0; i < napi_ids_size; i++) {
        get_req = netdev_queue_get_req_alloc();
        netdev_queue_get_req_set_ifindex(get_req, cfg_ifindex);
        netdev_queue_get_req_set_type(get_req, NETDEV_QUEUE_TYPE_RX);
        netdev_queue_get_req_set_id(get_req, i);
        struct netdev_queue_get_rsp *rsp = netdev_queue_get(ys, get_req);
        if (rsp == NULL) {
            char buf[128];
            h2o_fatal("ynl, queue_get: [%d] %s\n", errno, h2o_strerror_r(errno, buf, sizeof(buf)));
        }
        if (!rsp->_present.napi_id || rsp->napi_id == 0) {
            h2o_fatal("ynl, napi id not present or invalid for queue %d\n", i);
        }
        napi_ids[i] = rsp->napi_id;
        netdev_queue_get_rsp_free(rsp);
        netdev_queue_get_req_free(get_req);

        fprintf(stderr, "ynl setup_queue(%d) -> napi_id[%u]\n", i, napi_ids[i]);

        /* and configure the napi id with the settings provided */
        set_req = netdev_napi_set_req_alloc();
        netdev_napi_set_req_set_id(set_req, napi_ids[i]);
        netdev_napi_set_req_set_defer_hard_irqs(set_req, cfg_defer_hard_irqs);
        netdev_napi_set_req_set_gro_flush_timeout(set_req, cfg_gro_flush_timeout);
        netdev_napi_set_req_set_irq_suspend_timeout(set_req, cfg_irq_suspend_timeout);
        int ret = netdev_napi_set(ys, set_req);
        if (ret != 0) {
            char buf[128];
            h2o_fatal("ynl, napi_set: [%d] %s\n", errno, h2o_strerror_r(errno, buf, sizeof(buf)));
        }
        netdev_napi_set_req_free(set_req);
    }

    ynl_sock_destroy(ys);
}

void attach_cbpf(int fd, uint16_t cpus)
{
    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    uint16_t n = cpus;
    int ret = 0;

    ret = getsockname(fd, (struct sockaddr *)&ss, &sslen);
    if (ret != 0) {
        char buf[128];
        fprintf(stderr, "getsockname failed on listener: %s\n", h2o_strerror_r(errno, buf, sizeof(buf)));
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
        .len = sizeof(code) / sizeof(code[0]),
        .filter = code,
    };

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &p, sizeof(p)) != 0) {
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
        fprintf(stderr, "bound fd %d to iface: %s\n", fd, iface);
    }
}

static unsigned int get_napi_id(int fd)
{
    unsigned int napi_id = 0;
    socklen_t napi_id_len = sizeof(napi_id);

    if (getsockopt(fd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &napi_id_len) != 0) {
        h2o_perror("so_napi_incoming_id failed");
    }

    return napi_id;
}

static const char *get_nic_name_by_napi(unsigned int napi_id, struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count)
{
    for (int i = 0; i < nic_count; i++) {
        for (int j = 0; j < nic_to_cpu_map[i].napi_ids.size; j++) {
            if (nic_to_cpu_map[i].napi_ids.entries[j] == napi_id)
                return nic_to_cpu_map[i].iface.base;
        }
    }
    return NULL;
}

/*
 * -2  error
 * -1  unix socket
 *  0  non-local INET (or INET6) connection
 *  1  local INET (or INET6) connection
 */
static int is_local_conn(int fd, int napi_id)
{
    int is_local = napi_id == 0;
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

        if (iface && strcmp(nic_to_cpu_map[i].iface.base, iface) == 0) {
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
                            char buf[128];
                            fprintf(stderr, "getsockname failed on listener: %s\n", h2o_strerror_r(errno, buf, sizeof(buf)));
                        }
                    }

                    struct busypoll_nic_t *nic = &nic_to_cpu_map[i];
                    if (nic) {
                        h2o_evloop_update_busypoll_params(loop, nic->epoll_params.usecs, nic->epoll_params.budget,
                                                          nic->epoll_params.prefer, nic->epoll_params.nonblock, nic->mode);
                    }
                    nic_claimed = nic->iface.base;
                    napi_id_claimed = napi_id;
                    found = 1;
                    cpu_claimed = j;
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
    if (cpu_claimed > 0) {
        /* start by getting a verdict on the incoming connection */
        int verdict = is_local_conn(sockfd, napi_id);
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
                const char *iface, *mismatch_nic_name = "unknown";

                if ((iface = get_nic_name_by_napi(napi_id, nic_to_cpu_map, nic_count)) == NULL) {
                    h2o_fatal("failed to find interface name for napi id: %d\n", napi_id);
                }

                if (strlen(iface) > 0)
                    mismatch_nic_name = iface;

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
        const char *iface;
        if ((iface = get_nic_name_by_napi(napi_id, nic_to_cpu_map, nic_count)) == NULL) {
            h2o_fatal("failed to find interface name for napi id: %d\n", napi_id);
        }

        fprintf(stderr, "thread %zd NAPI id: %u, iface: %s, listener fd: %d\n", thread_index, napi_id, iface, listener_fd);

        int found =
            assign_nic_map_cpu(h2o_socket_get_loop(sock), iface, thread_index, napi_id, listener_fd, 0, nic_to_cpu_map, nic_count);

        if (!found) {
            fprintf(stderr, "no CPU found for thread with NAPI from NIC: %s:%d\n", iface, napi_id);
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

void h2o_busypoll_set_opts(struct busypoll_nic_t *nic)
{
    if (h2o_memis(nic->iface.base, nic->iface.len, H2O_STRLIT("lo")))
        return;
    setup_queue(nic->ifindex, nic->options.defer_hard_irqs, nic->options.gro_flush_timeout, nic->options.suspend_timeout,
                nic->napi_ids.entries, nic->napi_ids.size);
}

void h2o_busypoll_clear_opts(struct busypoll_nic_t *nic)
{
    if (h2o_memis(nic->iface.base, nic->iface.len, H2O_STRLIT("lo")))
        return;
    setup_queue(nic->ifindex, 0, 0, 0, nic->napi_ids.entries, nic->napi_ids.size);
}

void h2o_busypoll_attach_cbpf(int fd, uint16_t cpus)
{
    attach_cbpf(fd, cpus);
}

void h2o_busypoll_handle_nic_map_accept(h2o_socket_t *sock, h2o_socket_t *listener, size_t thread_index,
                                        struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count)
{
    handle_nic_map_accept(sock, listener, thread_index, nic_to_cpu_map, nic_count);
}

const char *h2o_busypoll_get_iface(void)
{
    return nic_claimed;
}

uint32_t h2o_busypoll_get_napi_id(void)
{
    return napi_id_claimed;
}

uint16_t h2o_busypoll_get_cpu_idx(void)
{
    return cpu_claimed;
}

