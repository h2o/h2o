#ifndef h2o__busypoll_h
#define h2o__busypoll_h

#if !H2O_USE_EPOLL_BUSYPOLL
#error "this file may be included only on linux and when ynl support is available"
#endif

#include <stdint.h>

enum en_h2o_bp_mode_t { BP_MODE_OFF, BP_MODE_SUSPEND, BP_MODE_BUSYPOLL, BP_MODE_NUM };

struct busypoll_epoll_params {
    uint32_t usecs;
    uint16_t budget;
    uint8_t prefer : 1;
    uint8_t nonblock : 1;
};

struct busypoll_nic_t {
    h2o_iovec_t iface;
    size_t ifindex;
    size_t cpu_count;
    enum en_h2o_bp_mode_t mode;
    cpu_set_t cpu_map;
    H2O_VECTOR(uint32_t) napi_ids;
    pthread_mutex_t mutex;
    struct {
        size_t gro_flush_timeout;
        size_t defer_hard_irqs;
        size_t suspend_timeout;
    } options;
    struct busypoll_epoll_params epoll_params;
};

typedef H2O_VECTOR(struct busypoll_nic_t) h2o_busypoll_nic_vector_t;

void h2o_busypoll_bind_interface(int fd, const char *iface);
void h2o_busypoll_attach_cbpf(int fd, uint16_t cpus);
void h2o_busypoll_set_opts(struct busypoll_nic_t *nic);
void h2o_busypoll_clear_opts(struct busypoll_nic_t *nic);
void h2o_busypoll_handle_nic_map_accept(h2o_socket_t *sock, h2o_socket_t *listener, size_t thread_index,
                                        struct busypoll_nic_t *nic_to_cpu_map, size_t nic_count);

const char *h2o_busypoll_get_iface(void);
uint32_t h2o_busypoll_get_napi_id(void);
int h2o_busypoll_get_cpu_idx(void);

#endif
