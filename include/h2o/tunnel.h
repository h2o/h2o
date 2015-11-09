#ifndef h2o__tunnel_h
#define h2o__tunnel_h

#ifdef __cplusplus
//extern "C" {
#endif

struct st_h2o_tunnel_t;

typedef struct st_h2o_tunnel_t h2o_tunnel_t;

h2o_tunnel_t *h2o_tunnel_establish(h2o_socket_t *sock1, h2o_socket_t *sock2);
void h2o_tunnel_break(h2o_tunnel_t *tunnel);

#ifdef __cplusplus
//}
#endif

#endif
