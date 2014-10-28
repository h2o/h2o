#ifndef h2o__t__test_h
#define h2o__t__test_h

#include "picotest.h"
#include "h2o.h"

typedef struct st_h2o_loopback_conn_t {
    h2o_conn_t super;
    /**
     * the response
     */
    h2o_input_buffer_t *body;
    /* internal structure */
    h2o_ostream_t _ostr_final;
    int _is_complete;
    /**
     * the HTTP request / response (intentionally placed at the last, since it is a large structure and has it's own ctor)
     */
    h2o_req_t req;
} h2o_loopback_conn_t;

h2o_loopback_conn_t *h2o_loopback_create(h2o_context_t *ctx);
void h2o_loopback_destroy(h2o_loopback_conn_t *conn);
void h2o_loopback_run_loop(h2o_loopback_conn_t *conn);

extern h2o_loop_t *test_loop;

void test_lib__string_c(void);
void test_lib__util_c(void);
void test_lib__http2__hpack(void);
void test_lib__file_c(void);

#endif
