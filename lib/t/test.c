#include "./test.h"

static void loopback_on_send(h2o_ostream_t *self, h2o_req_t *req, h2o_buf_t *inbufs, size_t inbufcnt, int is_final)
{
    h2o_loopback_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_loopback_conn_t, _ostr_final, self);
    size_t i;

    for (i = 0; i != inbufcnt; ++i) {
        h2o_reserve_input_buffer(&conn->body, inbufs->len);
        memcpy(conn->body->bytes + conn->body->size, inbufs->base, inbufs->len);
        conn->body->size += inbufs->len;
    }

    if (is_final)
        conn->_is_complete = 1;
    else
        h2o_proceed_response(&conn->req);
}

h2o_loopback_conn_t *h2o_loopback_create(h2o_context_t *ctx)
{
    h2o_loopback_conn_t *conn = h2o_malloc(sizeof(*conn));

    memset(conn, 0, offsetof(struct st_h2o_loopback_conn_t, req));
    conn->super.ctx = ctx;
    h2o_init_request(&conn->req, &conn->super, NULL);
    h2o_init_input_buffer(&conn->body);
    conn->req._ostr_top = &conn->_ostr_final;
    conn->_ostr_final.do_send = loopback_on_send;

    return conn;
}

void h2o_loopback_destroy(h2o_loopback_conn_t *conn)
{
    h2o_dispose_input_buffer(&conn->body);
    h2o_dispose_request(&conn->req);
    free(conn);
}

void h2o_loopback_run_loop(h2o_loopback_conn_t *conn)
{
    h2o_process_request(&conn->req);

    while (! conn->_is_complete) {
#if H2O_USE_LIBUV
        uv_run(conn->super.ctx->loop, UV_RUN_ONCE);
#else
        h2o_evloop_run(conn->super.ctx->loop);
#endif
    }
}

h2o_loop_t *test_loop;

static void test_loopback(void)
{
    h2o_globalconf_t conf;
    h2o_context_t ctx;
    h2o_loopback_conn_t *conn;

    h2o_config_init(&conf);
    h2o_config_register_host(&conf, "default");
    h2o_context_init(&ctx, test_loop, &conf);

    conn = h2o_loopback_create(&ctx);
    conn->req.method = h2o_buf_init(H2O_STRLIT("GET"));
    conn->req.path = h2o_buf_init(H2O_STRLIT("/"));
    conn->req.version = 0x100;
    h2o_loopback_run_loop(conn);

    ok(conn->req.res.status == 404);

    h2o_context_dispose(&ctx);
    h2o_config_dispose(&conf);
}

int main(int argc, char **argv)
{
    { /* library tests */
        subtest("lib/string.c", test_lib__string_c);
        subtest("lib/util.c", test_lib__util_c);
        subtest("lib/http2/hpack.c", test_lib__http2__hpack);
    }

    { /* tests that use the run loop */
#if H2O_USE_LIBUV
        test_loop = h2o_malloc(sizeof(*test_loop));
        uv_loop_init(test_loop);
#else
        test_loop = h2o_evloop_create();
#endif

        subtest("lib/t/test.c/loopback", test_loopback);
        subtest("lib/file.c", test_lib__file_c);

#if H2O_USE_LIBUV
        uv_loop_close(test_loop);
        free(test_loop);
#else
        //h2o_evloop_destroy(loop);
#endif
    }

    return done_testing();
}
