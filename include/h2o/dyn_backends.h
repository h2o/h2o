#ifndef DYN_BACKENDS_H_
#define DYN_BACKENDS_H_

#include "h2o/url.h"
#include "h2o/socketpool.h"

typedef struct st_h2o_dyn_backend_config_t {
    h2o_url_t upstream;
} h2o_dyn_backend_config_t;
const char *h2o_dyn_backend_add(const char *id, h2o_dyn_backend_config_t *config);
int h2o_dyn_backend_get_upstream(h2o_handler_t *h, h2o_req_t *req, h2o_url_t **upstream, h2o_socketpool_t **pool, void *ctx);

#endif /* DYN_BACKENDS_H_ */
