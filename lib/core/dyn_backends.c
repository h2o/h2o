#include "h2o.h"
#include "h2o/dyn_backends.h"

#include "khash.h"


KHASH_MAP_INIT_STR(backends, h2o_socketpool_t *);

struct st_backend_t {
    char id[64];
    int timeout_set;
    struct sockaddr_storage ss;
    socklen_t sslen;
    h2o_url_t upstream;
    h2o_socketpool_t sockpool;
};
static khash_t(backends) *backends;

const char *h2o_dyn_backend_add(const char *id, h2o_dyn_backend_config_t *config)
{
    khint_t k;
    struct st_backend_t *backend = h2o_mem_alloc(sizeof(*backend));
    struct sockaddr_in sin;
    struct sockaddr_un sa;
    const char *to_sa_err;
    int is_ssl;

    if (!backends) {
        backends = kh_init(backends);
    }
    memset(&sin, 0, sizeof(sin));
    memset(backend, 0, sizeof(*backend));

    is_ssl = config->upstream.scheme == &H2O_URL_SCHEME_HTTPS;
    to_sa_err = h2o_url_host_to_sun(config->upstream.host, &sa);
    if (to_sa_err == h2o_url_host_to_sun_err_is_not_unix_socket) {
        h2o_socketpool_init_by_hostport(&backend->sockpool, config->upstream.host, h2o_url_get_port(&config->upstream), is_ssl,
                SIZE_MAX /* FIXME */);
    } else {
        assert(to_sa_err == NULL);
        h2o_socketpool_init_by_address(&backend->sockpool, (void *)&sa, sizeof(sa), is_ssl, SIZE_MAX /* FIXME */);
    }

    if (strlen(id) + 1 > sizeof(backend->id)) {
        goto err;
    }

    memcpy(backend->id, id, strlen(id));
    k = kh_get(backends, backends, backend->id);
    if (k != kh_end(backends)) {
        goto err;
    }

    h2o_url_copy(NULL, &backend->upstream, &config->upstream);
    int ret;
    k = kh_put(backends, backends, backend->id, &ret);
    kh_val(backends, k) = &backend->sockpool;
    return backend->id;

err:
    h2o_socketpool_dispose(&backend->sockpool);
    free(backend);
    return NULL;
}

int h2o_dyn_backend_get_upstream(h2o_handler_t *h, h2o_req_t *req, h2o_url_t **upstream, h2o_socketpool_t **pool, void *ctx)
{
    khint_t k;
    struct st_backend_t *backend;
    h2o_iovec_t *bid_header = ctx;
    h2o_iovec_t id = {};
    char *p;
    ssize_t bid;

    if (!bid_header->base)
        return -1;

    if ((bid = h2o_find_header_by_str(&req->headers, bid_header->base, bid_header->len, -1)) != -1) {
        if (req->headers.entries[bid].value.base)
            id = h2o_strdup(&req->pool, req->headers.entries[bid].value.base, req->headers.entries[bid].value.len);
    }
    if (!id.base)
        return -1;

    p = memchr(id.base, '\r', id.len);
    if (p)
        *p = '\0';

    k = kh_get(backends, backends, id.base);
    if (k == kh_end(backends))
        return -1;

    backend = H2O_STRUCT_FROM_MEMBER(struct st_backend_t, sockpool, kh_val(backends, k));
    *upstream = &backend->upstream;
    *pool = &backend->sockpool;

    if (backend->sockpool._interval_cb.loop == NULL)
        h2o_socketpool_set_timeout(&backend->sockpool, req->conn->ctx->loop, 5000);

    return 0;
}
