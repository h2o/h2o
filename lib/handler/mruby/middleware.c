/*
 * Copyright (c) 2017 Ichito Nagata, Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include "h2o/mruby_.h"
#include "embedded.c.h"

struct st_mruby_subreq_conn_t {
    h2o_conn_t super;
    struct {
        h2o_iovec_t host;
        h2o_iovec_t port;
        struct sockaddr_storage addr;
        socklen_t len;
    } server;
    struct {
        h2o_iovec_t host;
        h2o_iovec_t port;
        struct sockaddr_storage addr;
        socklen_t len;
    } remote;
};

struct st_mruby_subreq_t {
    h2o_req_t super;
    struct st_mruby_subreq_conn_t conn;
    h2o_mruby_context_t *ctx;
    h2o_buffer_t *buf;
    mrb_value receiver;
    struct {
        mrb_value request;
        mrb_value input_stream;
    } refs;
    mrb_value error_stream;
    struct {
        h2o_mruby_generator_t *response;
        h2o_mruby_generator_t *body;
    } shortcut;
    enum {
        INITIAL,
        RECEIVED,
        FINAL_RECEIVED
    } state;
    unsigned char chain_proceed : 1;
};

struct st_h2o_mruby_middleware_sender_t {
    h2o_mruby_sender_t super;
    h2o_doublebuffer_t sending;
    struct st_mruby_subreq_t *subreq;
    struct {
        h2o_iovec_t *bufs;
        size_t bufcnt;
    } blocking;
};

static void dispose_subreq(struct st_mruby_subreq_t *subreq)
{
    /* subreq must be alive until generator gets disposed if shortcut is used */
    assert(subreq->shortcut.response == NULL);
    assert(subreq->shortcut.body == NULL);

    if (!mrb_nil_p(subreq->error_stream)) {
        mrb_gc_unregister(subreq->ctx->shared->mrb, subreq->error_stream);
        subreq->error_stream = mrb_nil_value();
    }

    if (subreq->buf != NULL)
        h2o_buffer_dispose(&subreq->buf);

    if (!mrb_nil_p(subreq->refs.request))
        DATA_PTR(subreq->refs.request) = NULL;
    if (!mrb_nil_p(subreq->refs.input_stream))
        DATA_PTR(subreq->refs.input_stream) = NULL;

    h2o_dispose_request(&subreq->super);
    free(subreq);
}

static void on_gc_dispose_app_request(mrb_state *mrb, void *_subreq)
{
    struct st_mruby_subreq_t *subreq = _subreq;
    if (subreq == NULL) return;
    subreq->refs.request = mrb_nil_value();
    if (mrb_nil_p(subreq->refs.input_stream))
        dispose_subreq(subreq);
}

static void on_gc_dispose_app_input_stream(mrb_state *mrb, void *_subreq)
{
    struct st_mruby_subreq_t *subreq = _subreq;
    if (subreq == NULL) return;
    subreq->refs.input_stream = mrb_nil_value();
    if (mrb_nil_p(subreq->refs.request))
        dispose_subreq(subreq);
}

const static struct mrb_data_type app_request_type = {"app_request_type", on_gc_dispose_app_request};
const static struct mrb_data_type app_input_stream_type = {"app_input_stream", on_gc_dispose_app_input_stream};

static h2o_iovec_t convert_env_to_header_name(h2o_mem_pool_t *pool, const char *name, size_t len)
{
#define KEY_PREFIX "HTTP_"
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1)
    if (len < KEY_PREFIX_LEN || ! h2o_memis(name, KEY_PREFIX_LEN, KEY_PREFIX, KEY_PREFIX_LEN)) {
        return h2o_iovec_init(NULL, 0);
    }

    h2o_iovec_t ret;

    ret.len = len - KEY_PREFIX_LEN;
    ret.base = h2o_mem_alloc_pool(pool, char, ret.len);

    name += KEY_PREFIX_LEN;
    char *d = ret.base;
    for (; len != 0; ++name, --len)
        *d++ = *name == '_' ? '-' : h2o_tolower(*name);

    return ret;
#undef KEY_PREFIX
#undef KEY_PREFIX_LEN
}

static int iterate_headers_callback(h2o_mruby_shared_context_t *shared_ctx, h2o_mem_pool_t *pool, h2o_iovec_t *name, h2o_iovec_t value, void *cb_data)
{
    mrb_value result_hash = mrb_obj_value(cb_data);
    mrb_value n;
    if (h2o_iovec_is_token(name)) {
        const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, name);
        n = h2o_mruby_token_string(shared_ctx, token);
    } else {
        n = h2o_mruby_new_str(shared_ctx->mrb, name->base, name->len);
    }
    mrb_value v = h2o_mruby_new_str(shared_ctx->mrb, value.base, value.len);
    mrb_hash_set(shared_ctx->mrb, result_hash, n, v);
    return 0;
}

static mrb_value build_app_response(struct st_mruby_subreq_t *subreq)
{
    h2o_req_t *req = &subreq->super;
    h2o_mruby_context_t *ctx = subreq->ctx;
    mrb_state *mrb = ctx->shared->mrb;

    /* build response array */
    mrb_value resp = mrb_ary_new_capa(mrb, 3);

    /* status */
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(req->res.status));

    /* headers */
    {
        mrb_value headers_hash = mrb_hash_new_capa(mrb, (int)req->res.headers.size);
        h2o_mruby_iterate_headers(ctx->shared, &req->pool, &req->res.headers, iterate_headers_callback, mrb_obj_ptr(headers_hash));
        if (req->res.content_length != SIZE_MAX) {
            h2o_token_t *token = H2O_TOKEN_CONTENT_LENGTH;
            mrb_value n = h2o_mruby_new_str(mrb, token->buf.base, token->buf.len);
            mrb_value v = h2o_mruby_to_str(mrb, mrb_fixnum_value(req->res.content_length));
            mrb_hash_set(mrb, headers_hash, n, v);
        }
        mrb_ary_set(mrb, resp, 1, headers_hash);
    }

    /* body */
    {
        mrb_value body = h2o_mruby_create_data_instance(mrb, mrb_ary_entry(ctx->shared->constants, H2O_MRUBY_APP_INPUT_STREAM_CLASS), subreq, &app_input_stream_type);
        mrb_funcall(mrb, body, "initialize", 0);
        mrb_ary_set(mrb, resp, 2, body);
    }
    
    return resp;
}

static void append_bufs(struct st_mruby_subreq_t *subreq, h2o_iovec_t *inbufs, size_t inbufcnt)
{
    int i;
    for (i = 0; i != inbufcnt; ++i) {
        h2o_buffer_append(&subreq->buf, inbufs[i].base, inbufs[i].len);
    }
}

static mrb_value detach_receiver(struct st_mruby_subreq_t *subreq)
{
    mrb_value receiver = subreq->receiver;
    assert(!mrb_nil_p(receiver));
    subreq->receiver = mrb_nil_value();
    mrb_gc_unregister(subreq->ctx->shared->mrb, receiver);
    mrb_gc_protect(subreq->ctx->shared->mrb, receiver);
    return receiver;
}

static void send_response_shortcutted(struct st_mruby_subreq_t *subreq);
static void subreq_ostream_send(h2o_ostream_t *_self, h2o_req_t *_subreq, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    struct st_mruby_subreq_t *subreq = (void *)_subreq;
    mrb_state *mrb = subreq->ctx->shared->mrb;

    /* body shortcut */
    if (subreq->shortcut.body != NULL) {
        if (subreq->shortcut.body->sender->final_sent)
            return; /* TODO: close subreq ASAP */

        subreq->chain_proceed = 1;
        if (subreq->buf == NULL) {
            /* flushing chunks has been finished, so send directly */
            h2o_mruby_sender_do_send(subreq->shortcut.body, inbufs, inbufcnt, state);
        } else {
            /* flushing, buffer chunks again */
            append_bufs(subreq, inbufs, inbufcnt);
        }

        return;
    }

    int is_first = subreq->state == INITIAL;
    if (h2o_send_state_is_in_progress(state)) {
        h2o_proceed_response_deferred(&subreq->super);
        subreq->state = RECEIVED;
    } else {
        subreq->state = FINAL_RECEIVED;
    }

    append_bufs(subreq, inbufs, inbufcnt);

    /* response shortcut */
    if (subreq->shortcut.response != NULL) {
        send_response_shortcutted(subreq);
        return;
    }

    if (mrb_nil_p(subreq->receiver))
        return;

    int gc_arena = mrb_gc_arena_save(mrb);

    if (is_first) {
        /* the fiber is waiting due to calling req.join */
        h2o_mruby_run_fiber(subreq->ctx, detach_receiver(subreq), mrb_nil_value(), NULL);
    } else if (subreq->buf->size != 0) {
        /* resume callback sender fiber */
        mrb_value chunk = h2o_mruby_new_str(mrb, subreq->buf->bytes, subreq->buf->size);
        h2o_buffer_consume(&subreq->buf, subreq->buf->size);
        h2o_mruby_run_fiber(subreq->ctx, detach_receiver(subreq), chunk, NULL);
    } else if (subreq->state == FINAL_RECEIVED) {
        h2o_mruby_run_fiber(subreq->ctx, detach_receiver(subreq), mrb_nil_value(), NULL);
    }

    mrb_gc_arena_restore(mrb, gc_arena);
}

static void prepare_subreq_entity(h2o_req_t *subreq, h2o_mruby_context_t *ctx, mrb_value rack_input)
{
    mrb_state *mrb = ctx->shared->mrb;

    if (mrb_nil_p(rack_input)) {
        subreq->entity = h2o_iovec_init(NULL, 0);
        subreq->content_length = 0;
        return;
    }

    // TODO: fastpath?
    if (! mrb_respond_to(mrb, rack_input, mrb_intern_lit(mrb, "read"))) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "'rack.input' must respond to 'read'"));
        return;
    }
    mrb_value body = mrb_funcall(mrb, rack_input, "read", 0);
    if (mrb->exc != NULL)
        return;
    if (!mrb_string_p(body)) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "return value of `read` must be a string"));
        return;
    }
    subreq->entity = h2o_strdup(&subreq->pool, RSTRING_PTR(body), RSTRING_LEN(body));

    if (subreq->content_length == SIZE_MAX) {
        subreq->content_length = subreq->entity.len;
    } else {
        if (subreq->content_length > subreq->entity.len)
            subreq->content_length = subreq->entity.len;
        else if (subreq->content_length < subreq->entity.len)
            subreq->entity.len = subreq->content_length;
    }
}

static socklen_t parse_hostport(h2o_mem_pool_t *pool, h2o_iovec_t host, h2o_iovec_t port, struct sockaddr_storage *ss)
{
    /* fast path for IPv4 addresses */
    {
        unsigned int d1, d2, d3, d4, _port;
        int parsed_len;
        if (sscanf(host.base, "%" SCNd32 "%*[.]%" SCNd32 "%*[.]%" SCNd32 "%*[.]%" SCNd32 "%n", &d1, &d2, &d3, &d4, &parsed_len) == 4 && parsed_len == host.len &&
            d1 <= UCHAR_MAX && d2 <= UCHAR_MAX && d3 <= UCHAR_MAX && d4 <= UCHAR_MAX) {
            if (sscanf(port.base, "%" SCNd32 "%n", &_port, &parsed_len) == 1 && parsed_len == port.len && _port <= USHRT_MAX) {
                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_port = htons(_port);
                sin.sin_addr.s_addr = ntohl((d1 << 24) + (d2 << 16) + (d3 << 8) + d4);
                *ss = *((struct sockaddr_storage *)&sin);
                return sizeof(sin);
            }
        }
    }

    /* call getaddrinfo */
    struct addrinfo hints, *res = NULL;

    char *hostname = h2o_mem_alloc_pool(pool, char, host.len + 1);
    memcpy(hostname, host.base, host.len);
    hostname[host.len] = '\0';
    char *servname = h2o_mem_alloc_pool(pool, char, port.len + 1);
    memcpy(servname, port.base, port.len);
    hostname[port.len] = '\0';

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    if (getaddrinfo(hostname, servname, &hints, &res) != 0) {
        goto Error;
    }

    switch(res->ai_family) {
        case AF_INET:
        case AF_INET6:
            memcpy(ss, res->ai_addr, res->ai_addrlen);
            break;
        default:
            goto Error;
    }

    socklen_t len =  res->ai_addrlen;
    freeaddrinfo(res);
    return len;

Error:
    if (res != NULL)
        freeaddrinfo(res);
    return 0;
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_mruby_subreq_conn_t *conn = (void *)_conn;
    if (conn->server.host.base != NULL) {
        struct st_mruby_subreq_t *subreq = H2O_STRUCT_FROM_MEMBER(struct st_mruby_subreq_t, conn, conn);
        conn->server.len = parse_hostport(&subreq->super.pool, conn->server.host, conn->server.port, &conn->server.addr);
        conn->server.host.base = NULL;
    }
    memcpy(sa, &conn->server.addr, conn->server.len);
    return conn->server.len;
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_mruby_subreq_conn_t *conn = (void *)_conn;
    if (conn->remote.host.base != NULL) {
        struct st_mruby_subreq_t *subreq = H2O_STRUCT_FROM_MEMBER(struct st_mruby_subreq_t, conn, conn);
        conn->remote.len = parse_hostport(&subreq->super.pool, conn->remote.host, conn->remote.port, &conn->remote.addr);
        conn->remote.host.base = NULL;
    }
    memcpy(sa, &conn->remote.addr, conn->remote.len);
    return conn->remote.len;
}

static h2o_socket_t *get_socket(h2o_conn_t *conn)
{
    return NULL;
}

static int handle_header_env_key(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t *env_key, h2o_iovec_t value, void *_req)
{
    h2o_req_t *req = _req;
    const h2o_token_t *token;

    /* convert env key to header name (lower case) */
    h2o_iovec_t name = convert_env_to_header_name(&req->pool, env_key->base, env_key->len);
    if (name.base == NULL)
        return 0;

    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        if (token == H2O_TOKEN_CONTENT_LENGTH) {
            /* skip. use CONTENT_LENGTH instead of HTTP_CONTENT_LENGTH */
        } else {
            value = h2o_strdup(&req->pool, value.base, value.len);
            h2o_add_header(&req->pool, &req->headers, token, NULL, value.base, value.len);
        }
    } else {
        value = h2o_strdup(&req->pool, value.base, value.len);
        h2o_add_header_by_str(&req->pool, &req->headers, name.base, name.len, 0, NULL, value.base, value.len);
    }

    return 0;
}

static void on_subreq_error_callback(void *data, h2o_iovec_t prefix, h2o_iovec_t msg)
{
    struct st_mruby_subreq_t *subreq = (void *)data;
    mrb_state *mrb = subreq->ctx->shared->mrb;

    assert(!mrb_nil_p(subreq->error_stream));

    h2o_iovec_t concat = h2o_concat(&subreq->super.pool, prefix, msg);
    mrb_value msgstr = h2o_mruby_new_str(mrb, concat.base, concat.len);
    mrb_funcall(mrb, subreq->error_stream, "write", 1, msgstr);
    if (mrb->exc != NULL) {
        fprintf(stderr, "%s\n", RSTRING_PTR(mrb_inspect(mrb, mrb_obj_value(mrb->exc))));
        mrb->exc = NULL;
    }
}

static struct st_mruby_subreq_t *create_subreq(h2o_mruby_context_t *ctx, mrb_value env, int is_reprocess)
{
    static const h2o_conn_callbacks_t callbacks = {
        get_sockname,    /* stringify address */
        get_peername,    /* ditto */
        NULL,            /* push (no push in subrequest) */
        get_socket,      /* get underlying socket */
        NULL,            /* get debug state */
        {{{NULL}}}};

    mrb_state *mrb = ctx->shared->mrb;
    int gc_arena = mrb_gc_arena_save(mrb);
    mrb_gc_protect(mrb, env);

    /* create subreq */
    struct st_mruby_subreq_t *subreq = h2o_mem_alloc(sizeof(*subreq));
    memset(&subreq->conn, 0, sizeof(subreq->conn));
    subreq->ctx = ctx;
    subreq->receiver = mrb_nil_value();
    subreq->refs.request = mrb_nil_value();
    subreq->refs.input_stream = mrb_nil_value();
    h2o_buffer_init(&subreq->buf, &h2o_socket_buffer_prototype);
    subreq->shortcut.response = NULL;
    subreq->shortcut.body = NULL;
    subreq->state = INITIAL;
    subreq->chain_proceed = 0;

    /* initialize super and conn */
    subreq->conn.super.ctx = ctx->shared->ctx;
    h2o_init_request(&subreq->super, &subreq->conn.super, NULL);
    subreq->super.is_subrequest = 1;
    h2o_ostream_t *ostream = h2o_add_ostream(&subreq->super, H2O_ALIGNOF(*ostream), sizeof(*ostream), &subreq->super._ostr_top);
    ostream->do_send = subreq_ostream_send;
    subreq->conn.super.hosts = ctx->handler->pathconf->global->hosts;
    subreq->conn.super.connected_at = (struct timeval){0}; /* no need because subreq won't logged */
    subreq->conn.super.id = 0; /* currently conn->id is used only for logging, so set zero as a meaningless value */
    subreq->conn.super.callbacks = &callbacks;


    /* retrieve env variables */
    mrb_value scheme = mrb_nil_value();
    mrb_value method = mrb_nil_value();
    mrb_value script_name = mrb_nil_value();
    mrb_value path_info = mrb_nil_value();
    mrb_value query_string = mrb_nil_value();
    mrb_value rack_input = mrb_nil_value();
    mrb_value http_host = mrb_nil_value();
    mrb_value server_name = mrb_nil_value();
    mrb_value server_port = mrb_nil_value();
    mrb_value server_addr = mrb_nil_value();
    mrb_value remote_addr = mrb_nil_value();
    mrb_value remote_port = mrb_nil_value();
    mrb_value server_protocol = mrb_nil_value();
    mrb_value remaining_delegations = mrb_nil_value();
    mrb_value remaining_reprocesses = mrb_nil_value();
    mrb_value rack_errors = mrb_nil_value();

#define RETRIEVE_ENV(val, stringify, numify) do { \
    val = value; \
    if (!mrb_nil_p(val)) { \
        if (stringify) \
            val = h2o_mruby_to_str(mrb, val); \
        if (numify) \
            val = h2o_mruby_to_int(mrb, val); \
        if (mrb->exc != NULL) \
            goto Failed; \
    } \
} while (0)
#define RETRIEVE_ENV_OBJ(val) RETRIEVE_ENV(val, 0, 0);
#define RETRIEVE_ENV_STR(val) RETRIEVE_ENV(val, 1, 0);
#define RETRIEVE_ENV_NUM(val) RETRIEVE_ENV(val, 0, 1);

#define COND0(str, lit, pos) (sizeof(lit) - 1 <= (pos) || (str)[pos] == (lit)[pos])
#define COND1(str, lit, pos) (COND0(str, lit, pos) && COND0(str, lit, pos + 1) && COND0(str, lit, pos + 2))
#define COND2(str, lit, pos) (COND1(str, lit, pos) && COND1(str, lit, pos + 3) && COND1(str, lit, pos + 6))
#define COND(str, lit)       (COND2(str, lit, 0)   && COND2(str, lit, 9)       && COND2(str, lit, 18))
#define CHECK_KEY(lit) ((sizeof(lit) - 1) == keystr_len && COND(keystr, lit))

    khiter_t k;
    khash_t(ht) *h = mrb_hash_tbl(mrb, env);
    for (k = kh_begin(h); k != kh_end(h); ++k) {
        if (!kh_exist(h, k))
            continue;
        mrb_value key = h2o_mruby_to_str(mrb, kh_key(h, k));
        if (mrb->exc != NULL)
            goto Failed;
        mrb_value value = kh_value(h, k).v;

        const char *keystr = RSTRING_PTR(key);
        const mrb_int keystr_len = RSTRING_LEN(key);

        if (CHECK_KEY("CONTENT_LENGTH")) {
            mrb_value content_length = mrb_nil_value();
            RETRIEVE_ENV_NUM(content_length);
            if (!mrb_nil_p(content_length))
                subreq->super.content_length = mrb_fixnum(content_length);
        } else if (CHECK_KEY("HTTP_HOST")) {
            RETRIEVE_ENV_STR(http_host);
        } else if (CHECK_KEY("PATH_INFO")) {
            RETRIEVE_ENV_STR(path_info);
        } else if (CHECK_KEY("QUERY_STRING")) {
            RETRIEVE_ENV_STR(query_string);
        } else if (CHECK_KEY("REMOTE_ADDR")) {
            RETRIEVE_ENV_STR(remote_addr);
        } else if (CHECK_KEY("REMOTE_PORT")) {
            RETRIEVE_ENV_STR(remote_port);
        } else if (CHECK_KEY("REQUEST_METHOD")) {
            RETRIEVE_ENV_STR(method);
        } else if (CHECK_KEY("SCRIPT_NAME")) {
            RETRIEVE_ENV_STR(script_name);
        } else if (CHECK_KEY("SERVER_ADDR")) {
            RETRIEVE_ENV_STR(server_addr);
        } else if (CHECK_KEY("SERVER_NAME")) {
            RETRIEVE_ENV_STR(server_name);
        } else if (CHECK_KEY("SERVER_PORT")) {
            RETRIEVE_ENV_STR(server_port);
        } else if (CHECK_KEY("SERVER_PROTOCOL")) {
            RETRIEVE_ENV_STR(server_protocol);
        } else if (CHECK_KEY("SERVER_SOFTWARE")) {
        } else if (CHECK_KEY("h2o.remaining_delegations")) {
            RETRIEVE_ENV_NUM(remaining_delegations);
        } else if (CHECK_KEY("h2o.remaining_reprocesses")) {
            RETRIEVE_ENV_NUM(remaining_reprocesses);
        } else if (CHECK_KEY("rack.errors")) {
            RETRIEVE_ENV_OBJ(rack_errors);
        } else if (CHECK_KEY("rack.hijack?")) {
        } else if (CHECK_KEY("rack.input")) {
            RETRIEVE_ENV_OBJ(rack_input);
        } else if (CHECK_KEY("rack.multiprocess")) {
        } else if (CHECK_KEY("rack.multithread")) {
        } else if (CHECK_KEY("rack.run_once")) {
        } else if (CHECK_KEY("rack.url_scheme")) {
            RETRIEVE_ENV_STR(scheme);
        } else if (keystr_len >= 5 && memcmp(keystr, "HTTP_", 5) == 0) {
            mrb_value http_header = mrb_nil_value();
            RETRIEVE_ENV_STR(http_header);
            if (!mrb_nil_p(http_header))
                h2o_mruby_split_header_pair(ctx->shared, key, http_header, handle_header_env_key, &subreq->super);
        } else if (keystr_len != 0){
            /* set to req->env */
            mrb_value reqenv = mrb_nil_value();
            RETRIEVE_ENV_STR(reqenv);
            if (!mrb_nil_p(reqenv)) {
                h2o_vector_reserve(&subreq->super.pool, &subreq->super.env, subreq->super.env.size + 2);
                subreq->super.env.entries[subreq->super.env.size] = h2o_strdup(&subreq->super.pool, keystr, keystr_len);
                subreq->super.env.entries[subreq->super.env.size + 1] = h2o_strdup(&subreq->super.pool, RSTRING_PTR(reqenv), RSTRING_LEN(reqenv));
                subreq->super.env.size += 2;
            }
        }
    }
#undef RETRIEVE_ENV
#undef RETRIEVE_ENV_OBJ
#undef RETRIEVE_ENV_STR
#undef RETRIEVE_ENV_NUM
#undef COND0
#undef COND1
#undef COND2
#undef COND
#undef CHECK_KEY

    /* do validations */
#define CHECK_REQUIRED(k, v, non_empty) do { \
    if (mrb_nil_p(v)) { \
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "missing required environment key: " k)); \
        goto Failed; \
    } else if (non_empty && RSTRING_LEN(v) == 0) { \
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, k " must be not empty")); \
        goto Failed; \
    } \
} while (0)
    CHECK_REQUIRED("REQUEST_METHOD", method, 1);
    CHECK_REQUIRED("rack.url_scheme", scheme, 1);
    CHECK_REQUIRED("SCRIPT_NAME", script_name, 0);
    CHECK_REQUIRED("PATH_INFO", path_info, 0);
    CHECK_REQUIRED("QUERY_STRING", query_string, 0);
#undef CHECK_REQUIRED

    if (RSTRING_LEN(script_name) != 0 && RSTRING_PTR(script_name)[0] != '/') {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "SCRIPT_NAME must start with `/`"));
        goto Failed;
    }
    if (RSTRING_LEN(path_info) != 0 && RSTRING_PTR(path_info)[0] != '/') {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "PATH_INFO must start with `/`"));
        goto Failed;
    }
    if (mrb_nil_p(http_host) && (mrb_nil_p(server_name) || mrb_nil_p(server_port))) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "HTTP_HOST or (SERVER_NAME and SERVER_PORT) is required"));
        goto Failed;
    }

    if (!is_reprocess) {
        /* ensure that SCRIPT_NAME is not modified */
        h2o_iovec_t confpath = ctx->handler->pathconf->path;
        size_t confpath_len_wo_slash = confpath.base[confpath.len - 1] == '/' ? confpath.len - 1 : confpath.len;
        if (!(RSTRING_LEN(script_name) == confpath_len_wo_slash && memcmp(RSTRING_PTR(script_name), confpath.base, confpath_len_wo_slash) == 0)) {
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "can't modify `SCRIPT_NAME` with `H2O.next`. Is `H2O.reprocess` what you want?"));
            goto Failed;
        }
    }

#define STR_TO_IOVEC(val) h2o_iovec_init(RSTRING_PTR(val), RSTRING_LEN(val))

    /* construct url and parse */
    h2o_iovec_t url_comps[9];
    int num_comps = 0;
    url_comps[num_comps++] = STR_TO_IOVEC(scheme);
    url_comps[num_comps++] = h2o_iovec_init(H2O_STRLIT("://"));
    if (!mrb_nil_p(http_host)) {
        url_comps[num_comps++] = STR_TO_IOVEC(http_host);
    } else {
        url_comps[num_comps++] = STR_TO_IOVEC(server_name);
        url_comps[num_comps++] = h2o_iovec_init(H2O_STRLIT(":"));
        url_comps[num_comps++] = STR_TO_IOVEC(server_port);
    }
    url_comps[num_comps++] = STR_TO_IOVEC(script_name);
    url_comps[num_comps++] = STR_TO_IOVEC(path_info);
    if (RSTRING_LEN(query_string) != 0) {
        url_comps[num_comps++] = h2o_iovec_init(H2O_STRLIT("?"));
        url_comps[num_comps++] = STR_TO_IOVEC(query_string);
    }
    h2o_iovec_t url_str = h2o_concat_list(&subreq->super.pool, url_comps, num_comps);
    h2o_url_t url_parsed;
    if (h2o_url_parse(url_str.base, url_str.len, &url_parsed) != 0) {
        /* TODO is there any other way to show better error message? */
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env variable contains invalid values"));
        goto Failed;
    }

    /* setup req and conn using retrieved values */
    subreq->super.input.scheme = url_parsed.scheme;
    subreq->super.input.method = h2o_strdup(&subreq->super.pool, RSTRING_PTR(method), RSTRING_LEN(method));
    subreq->super.input.authority = h2o_strdup(&subreq->super.pool, url_parsed.authority.base, url_parsed.authority.len);
    subreq->super.input.path = h2o_strdup(&subreq->super.pool, url_parsed.path.base, url_parsed.path.len);
    h2o_hostconf_t *hostconf = h2o_req_setup(&subreq->super);
    subreq->super.hostconf = hostconf;
    subreq->super.pathconf = ctx->handler->pathconf;
    subreq->super.handler = &ctx->handler->super;
    subreq->super.version = h2o_parse_protocol_version(STR_TO_IOVEC(server_protocol));
    if (subreq->super.version == -1)
        subreq->super.version = 0x101;

    if (!mrb_nil_p(server_addr) && !mrb_nil_p(server_port)) {
        subreq->conn.server.host = h2o_strdup(&subreq->super.pool, RSTRING_PTR(server_addr), RSTRING_LEN(server_addr));
        subreq->conn.server.port = h2o_strdup(&subreq->super.pool, RSTRING_PTR(server_port), RSTRING_LEN(server_port));
    }

    if (!mrb_nil_p(remote_addr) && !mrb_nil_p(remote_port)) {
        subreq->conn.remote.host = h2o_strdup(&subreq->super.pool, RSTRING_PTR(remote_addr), RSTRING_LEN(remote_addr));
        subreq->conn.remote.port = h2o_strdup(&subreq->super.pool, RSTRING_PTR(remote_port), RSTRING_LEN(remote_port));
    }

    if (! mrb_nil_p(remaining_delegations)) {
        mrb_int v = mrb_fixnum(remaining_delegations);
        subreq->super.remaining_delegations = (unsigned)(v < 0 ? 0 : v);
    }
    if (! mrb_nil_p(remaining_reprocesses)) {
        mrb_int v = mrb_fixnum(remaining_reprocesses);
        subreq->super.remaining_reprocesses = (unsigned)(v < 0 ? 0 : v);
    }

    if (! mrb_nil_p(rack_errors)) {
        subreq->error_stream = rack_errors;
        mrb_gc_register(mrb, rack_errors);
        subreq->super.error_logger.cb = on_subreq_error_callback;
        subreq->super.error_logger.data = subreq;
    }

    prepare_subreq_entity(&subreq->super, ctx, rack_input);
    if (mrb->exc != NULL)
        goto Failed;

    return subreq;

Failed:
    assert(mrb->exc != NULL);
    dispose_subreq(subreq);
    mrb_gc_arena_restore(mrb, gc_arena);
    return NULL;
#undef STR_TO_IOVEC
}

static mrb_value middleware_wait_response_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args,
                                             int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_mruby_subreq_t *subreq;

    if ((subreq = mrb_data_check_get_ptr(mrb, mrb_ary_entry(args, 0), &app_request_type)) == NULL) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "AppRequest#join wrong self");
    }

    subreq->receiver = *receiver;
    mrb_gc_register(mrb, *receiver);
    return mrb_nil_value();
}

static mrb_value can_build_response_method(mrb_state *mrb, mrb_value self)
{
    struct st_mruby_subreq_t *subreq = mrb_data_check_get_ptr(mrb, self, &app_request_type);
    if (subreq == NULL)
        mrb_raise(mrb, E_ARGUMENT_ERROR, "AppRequest#_can_build_response? wrong self");
    return mrb_bool_value(subreq->state != INITIAL);
}

static mrb_value build_response_method(mrb_state *mrb, mrb_value self)
{
    struct st_mruby_subreq_t *subreq = mrb_data_check_get_ptr(mrb, self, &app_request_type);
    if (subreq == NULL)
        mrb_raise(mrb, E_ARGUMENT_ERROR, "AppRequest#build_response wrong self");

    mrb_value resp = build_app_response(subreq);
    subreq->refs.input_stream = mrb_ary_entry(resp, 2);
    return resp;
}

static mrb_value middleware_request_method(mrb_state *mrb, mrb_value self)
{
    h2o_mruby_shared_context_t *shared_ctx = mrb->ud;
    h2o_mruby_context_t *ctx = shared_ctx->current_context;
    assert(ctx != NULL);

    mrb_value env;
    mrb_value reprocess;
    mrb_get_args(mrb, "H", &env);
    reprocess = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@reprocess"));

    /* create subreq */
    struct st_mruby_subreq_t *subreq = create_subreq(shared_ctx->current_context, env, mrb_bool(reprocess));
    if (mrb->exc != NULL) {
        mrb_value exc = mrb_obj_value(mrb->exc);
        mrb->exc = NULL;
        mrb_exc_raise(mrb, exc);
    }

    subreq->refs.request = h2o_mruby_create_data_instance(mrb, mrb_ary_entry(ctx->shared->constants, H2O_MRUBY_APP_REQUEST_CLASS), subreq, &app_request_type);

    h2o_req_t *super = &subreq->super;
    if (mrb_bool(reprocess)) {
        h2o_reprocess_request_deferred(super, super->method, super->scheme, super->authority, super->path, super->overrides, 1);
    } else {
        h2o_delegate_request_deferred(super);
    }

    return subreq->refs.request;
}

static mrb_value middleware_wait_chunk_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value *receiver, mrb_value args, int *run_again)
{
    mrb_state *mrb = mctx->shared->mrb;
    struct st_mruby_subreq_t *subreq;


    mrb_value obj = mrb_ary_entry(args, 0);
    if (DATA_PTR(obj) == NULL) {
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "downstream HTTP closed");
    } else if ((subreq = mrb_data_check_get_ptr(mrb, obj, &app_input_stream_type)) == NULL) {
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "AppInputStream#each wrong self");
    }

    if (subreq->buf->size != 0) {
        *run_again = 1;
        mrb_value chunk = h2o_mruby_new_str(mrb, subreq->buf->bytes, subreq->buf->size);
        h2o_buffer_consume(&subreq->buf, subreq->buf->size);
        return chunk;
    } else if (subreq->state == FINAL_RECEIVED) {
        *run_again = 1;
        return mrb_nil_value();
    } else {
        assert(mrb_nil_p(subreq->receiver));
        subreq->receiver = *receiver;
        mrb_gc_register(mrb, *receiver);
        return mrb_nil_value();
    }
}

void h2o_mruby_middleware_init_context(h2o_mruby_shared_context_t *shared_ctx)
{
    mrb_state *mrb = shared_ctx->mrb;

    h2o_mruby_eval_expr(mrb, H2O_MRUBY_CODE_MIDDLEWARE);
    h2o_mruby_assert(mrb);

    struct RClass *module = mrb_define_module(mrb, "H2O");

    struct RClass *app_klass = mrb_class_get_under(shared_ctx->mrb, module, "App");
    mrb_define_method(mrb, app_klass, "request", middleware_request_method, MRB_ARGS_ARG(1, 0));

    struct RClass *app_request_klass = mrb_class_get_under(shared_ctx->mrb, module, "AppRequest");
    mrb_ary_set(shared_ctx->mrb, shared_ctx->constants, H2O_MRUBY_APP_REQUEST_CLASS, mrb_obj_value(app_request_klass));
    h2o_mruby_define_callback(mrb, "_h2o_middleware_wait_response", middleware_wait_response_callback);
    mrb_define_method(mrb, app_request_klass, "_can_build_response?", can_build_response_method, MRB_ARGS_NONE());
    mrb_define_method(mrb, app_request_klass, "_build_response", build_response_method, MRB_ARGS_NONE());

    struct RClass *app_input_stream_klass = mrb_class_get_under(shared_ctx->mrb, module, "AppInputStream");
    mrb_ary_set(shared_ctx->mrb, shared_ctx->constants, H2O_MRUBY_APP_INPUT_STREAM_CLASS, mrb_obj_value(app_input_stream_klass));
    h2o_mruby_define_callback(mrb, "_h2o_middleware_wait_chunk", middleware_wait_chunk_callback);

    h2o_mruby_assert(mrb);
}

void do_sender_start(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)generator->sender;
    struct st_mruby_subreq_t *subreq = sender->subreq;

    if (subreq->buf->size == 0 && subreq->state != FINAL_RECEIVED) {
        h2o_doublebuffer_prepare_empty(&sender->sending);
        h2o_send(generator->req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
    } else {
        h2o_mruby_sender_do_send_buffer(generator, &sender->sending, &subreq->buf, subreq->state == FINAL_RECEIVED ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
    }
}

void do_sender_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)generator->sender;
    struct st_mruby_subreq_t *subreq = sender->subreq;

    if (generator->sender->final_sent)
        return; /* TODO: close subreq ASAP */

    if (subreq->buf != NULL) {
        h2o_doublebuffer_consume(&sender->sending);

        if (subreq->buf->size != 0) {
            h2o_mruby_sender_do_send_buffer(generator, &sender->sending, &subreq->buf, subreq->state == FINAL_RECEIVED ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
            return; /* don't proceed because it's already requested in subreq_ostream_send*/
        } else {
            /* start direct shortcut */
            h2o_buffer_dispose(&subreq->buf);
            subreq->buf = NULL;
        }
    }

    if (sender->subreq->chain_proceed)
        h2o_proceed_response(&sender->subreq->super);
}

void do_sender_dispose(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)generator->sender;

    h2o_doublebuffer_dispose(&sender->sending);

    if (sender->subreq->shortcut.response != NULL) {
        assert(!mrb_nil_p(sender->subreq->refs.request));
        mrb_gc_unregister(generator->ctx->shared->mrb, sender->subreq->refs.request);
        sender->subreq->shortcut.response = NULL;
    }

    assert(sender->subreq->shortcut.body == generator);
    sender->subreq->shortcut.body = NULL;

    dispose_subreq(sender->subreq);
    sender->subreq = NULL;

    h2o_mruby_sender_close_body(generator);
}

static h2o_mruby_sender_t *create_sender(h2o_mruby_generator_t *generator, struct st_mruby_subreq_t *subreq, mrb_value body)
{
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)h2o_mruby_sender_create(generator, body, H2O_ALIGNOF(*sender), sizeof(*sender));
    sender->subreq = subreq;

    h2o_doublebuffer_init(&sender->sending, &h2o_socket_buffer_prototype);

    sender->super.start = do_sender_start;
    sender->super.proceed = do_sender_proceed;
    sender->super.dispose = do_sender_dispose;

    subreq->shortcut.body = generator;

    return &sender->super;
}

h2o_mruby_sender_t *h2o_mruby_middleware_sender_create(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    struct st_mruby_subreq_t *subreq;

    assert(mrb->exc == NULL);

    if ((subreq = mrb_data_check_get_ptr(mrb, body, &app_input_stream_type)) == NULL)
        return NULL;

    return create_sender(generator, subreq, body);
}

static void send_response_shortcutted(struct st_mruby_subreq_t *subreq)
{
    h2o_mruby_generator_t *generator = subreq->shortcut.response;
    assert(generator != NULL);

    /* copy response except for headers and original */
    generator->req->res.status = subreq->super.res.status;
    generator->req->res.reason = subreq->super.res.reason;
    generator->req->res.content_length = subreq->super.res.content_length;
    generator->req->res.mime_attr = subreq->super.res.mime_attr;

    /* handle response headers */
    int i;
    for (i = 0; i != subreq->super.res.headers.size; ++i) {
        h2o_header_t *header = subreq->super.res.headers.entries + i;
        h2o_mruby_set_response_header(generator->ctx->shared, header->name, header->value, generator->req);
    }
    /* add date: if it's missing from the response */
    if (h2o_find_header(&generator->req->res.headers, H2O_TOKEN_DATE, SIZE_MAX) == -1)
        h2o_resp_add_date_header(generator->req);

    /* setup body sender */
    h2o_mruby_sender_t *sender = create_sender(generator, subreq, mrb_nil_value());
    generator->sender = sender;
    generator->super.proceed = sender->proceed;

    /* start sending response */
    h2o_start_response(generator->req, &generator->super);
    generator->sender->start(generator);
}

static int send_response_callback(h2o_mruby_generator_t *generator, mrb_int status, mrb_value resp, int *is_delegate)
{
    struct st_mruby_subreq_t *subreq = mrb_data_check_get_ptr(generator->ctx->shared->mrb, resp, &app_request_type);
    assert(subreq != NULL);
    assert(mrb_obj_ptr(subreq->refs.request) == mrb_obj_ptr(resp));

    subreq->shortcut.response = generator;
    mrb_gc_register(generator->ctx->shared->mrb, resp); /* prevent request and subreq from being disposed */

    if (subreq->state != INITIAL) {
        /* immediately start sending response, otherwise defer it until once receive data from upstream (subreq_ostream_send) */
        send_response_shortcutted(subreq);
    }

    return 0;
}

h2o_mruby_send_response_callback_t h2o_mruby_middleware_get_send_response_callback(h2o_mruby_context_t *ctx, mrb_value resp)
{
    mrb_state *mrb = ctx->shared->mrb;
    struct st_mruby_subreq_t *subreq;
    if ((subreq = mrb_data_check_get_ptr(mrb, resp, &app_request_type)) == NULL)
        return NULL;
    return send_response_callback;
}
