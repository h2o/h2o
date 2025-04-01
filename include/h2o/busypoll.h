#ifndef h2o__busypoll_h
#define h2o__busypoll_h

#include <stdint.h>

enum busypoll_mode_t {
    BP_MODE_OFF = 0,
    BP_MODE_SUSPEND,
    BP_MODE_BUSYPOLL,
};

struct busypoll_nic_t {
    h2o_iovec_t iface;
    size_t ifindex;
    size_t cpu_count;
    enum busypoll_mode_t mode;
    cpu_set_t cpu_map;
    H2O_VECTOR(uint32_t) napi_ids;
    pthread_mutex_t mutex;
    struct {
        size_t gro_flush_timeout;
        size_t defer_hard_irqs;
        size_t suspend_timeout;
    } options;
};

typedef H2O_VECTOR(struct busypoll_nic_t) h2o_busypoll_nic_vector_t;

void h2o_busypoll_bind_interface(int fd, const char *iface);
void h2o_busypoll_attach_cbpf(int fd, uint16_t cpus);
void h2o_busypoll_set_opts(struct busypoll_nic_t *nic);
void h2o_busypoll_handle_nic_map_accept(h2o_socket_t *sock, h2o_socket_t *listener, size_t thread_index,
                                        struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count);

const char *h2o_busypoll_get_iface(void);
uint32_t h2o_busypoll_get_napi_id(void);
uint16_t h2o_busypoll_get_cpu_idx(void);

#endif
