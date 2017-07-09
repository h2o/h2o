#include "h2o/socketpool.h"

struct round_robin_t {
    size_t next_pos;
    pthread_mutex_t mutex;
};

void h2o_balancer_rr_init(h2o_socketpool_target_vector_t *targets, void **data)
{
    struct round_robin_t *self = h2o_mem_alloc(sizeof(*self));
    self->next_pos = 0;
    pthread_mutex_init(&self->mutex, NULL);
    *data = self;
}

size_t h2o_balancer_rr_selector(h2o_socketpool_target_vector_t *targets, h2o_socketpool_target_status_vector_t *status,
                                void *_data, int *tried)
{
    size_t i;
    size_t result;
    struct round_robin_t *self = _data;
    
    pthread_mutex_lock(&self->mutex);
    
    for (i = 0; i < targets->size; i++) {
        if (!tried[self->next_pos]) {
            result = self->next_pos;
            break;
        }
        self->next_pos++;
        self->next_pos %= targets->size;
    }
    
    assert(i < targets->size);
    self->next_pos++;
    self->next_pos %= targets->size;
    pthread_mutex_unlock(&self->mutex);
    return result;
}

void h2o_balancer_rr_dispose(void *data)
{
    struct round_robin_t *self = data;
    pthread_mutex_destroy(&self->mutex);
    free(data);
}
