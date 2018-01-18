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
        struct sockaddr_storage addr;
        socklen_t len;
    } server;
    struct {
        struct sockaddr_storage addr;
        socklen_t len;
    } remote;
};

struct st_mruby_subreq_t {
    h2o_req_t super;
    struct st_mruby_subreq_conn_t conn;
    h2o_mruby_context_t *ctx;
    mrb_value receiver;
    mrb_value ref;
    mrb_value chunks;
    mrb_value error_stream;
    h2o_mruby_generator_t *shortcut;
    unsigned char final_received : 1;
    unsigned char chain_proceed : 1;
};

struct st_h2o_mruby_middleware_sender_t {
    h2o_mruby_sender_t super;
    struct st_mruby_subreq_t *subreq;
    struct {
        h2o_iovec_t *bufs;
        size_t bufcnt;
    } blocking;
};

static void dispose_subreq(struct st_mruby_subreq_t *subreq)
{
    /* suqbre must be alive until generator gets disposed when shortcut used */
    assert(subreq->shortcut == NULL);

    if (!mrb_nil_p(subreq->error_stream)) {
        mrb_gc_unregister(subreq->ctx->shared->mrb, subreq->error_stream);
        subreq->error_stream = mrb_nil_value();
    }

    if (!mrb_nil_p(subreq->chunks)) {
        mrb_gc_unregister(subreq->ctx->shared->mrb, subreq->chunks);
        subreq->chunks = mrb_nil_value();
    }

    if (! mrb_nil_p(subreq->ref))
        DATA_PTR(subreq->ref) = NULL;
    h2o_dispose_request(&subreq->super);
    free(subreq);
}

static void on_gc_dispose_app_input_stream(mrb_state *mrb, void *_subreq)
{
    struct st_mruby_subreq_t *subreq = _subreq;
    if (subreq == NULL) return;
    dispose_subreq(subreq);
}

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
    mrb_value n = h2o_mruby_new_str(shared_ctx->mrb, name->base, name->len); /* TODO: use prepared constant */
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

static void push_chunks(struct st_mruby_subreq_t *subreq, h2o_iovec_t *inbufs, size_t inbufcnt)
{
    mrb_state *mrb = subreq->ctx->shared->mrb;
    assert(! mrb_nil_p(subreq->chunks));

    int gc_arena = mrb_gc_arena_save(mrb);

    int i;
    for (i = 0; i < inbufcnt; ++i) {
        mrb_value chunk = h2o_mruby_new_str(mrb, inbufs[i].base, inbufs[i].len);
        mrb_ary_push(mrb, subreq->chunks, chunk);
    }

    mrb_gc_arena_restore(mrb, gc_arena);
}

static void subreq_ostream_send(h2o_ostream_t *_self, h2o_req_t *_subreq, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    struct st_mruby_subreq_t *subreq = (void *)_subreq;
    mrb_state *mrb = subreq->ctx->shared->mrb;

    if (subreq->shortcut != NULL) {
        if (subreq->shortcut->sender->final_sent)
            return; /* TODO: close subreq ASAP */

        subreq->chain_proceed = 1;
        if (mrb_nil_p(subreq->chunks)) {
            /* flushing chunks has been finished, so send directly */
            h2o_mruby_sender_do_send(subreq->shortcut, inbufs, inbufcnt, state);
        } else {
            /* flushing, buffer chunks again */
            push_chunks(subreq, inbufs, inbufcnt);
        }
        return;
    }

    if (h2o_send_state_is_in_progress(state)) {
        h2o_proceed_response_deferred(&subreq->super);
    } else {
        subreq->final_received = 1;
    }

    push_chunks(subreq, inbufs, inbufcnt);

    /* detach receiver */
    if (! mrb_nil_p(subreq->receiver)) {
        int gc_arena = mrb_gc_arena_save(mrb);

        mrb_value input = mrb_nil_value();
        if (mrb_nil_p(subreq->ref)) {
            /* at first call, main fiber should be blocking at H2O.next.call */
            mrb_value resp = build_app_response(subreq);
            subreq->ref = mrb_ary_entry(resp, 2);
            input = resp;
        } else {
            input = mrb_ary_shift(mrb, subreq->chunks);
        }

        mrb_value receiver = subreq->receiver;
        mrb_gc_unregister(mrb, receiver);
        mrb_gc_protect(mrb, receiver);
        subreq->receiver = mrb_nil_value();
        h2o_mruby_run_fiber(subreq->ctx, receiver, input, NULL);

        mrb_gc_arena_restore(mrb, gc_arena);
    }
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

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_mruby_subreq_conn_t *conn = (void *)_conn;
    memcpy(sa, &conn->server.addr, conn->server.len);
    return conn->server.len;
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_mruby_subreq_conn_t *conn = (void *)_conn;
    memcpy(sa, &conn->remote.addr, conn->remote.len);
    return conn->remote.len;
}

static h2o_socket_t *get_socket(h2o_conn_t *conn)
{
    return NULL;
}

static socklen_t parse_hostport(mrb_state *mrb, mrb_value host, mrb_value port, struct sockaddr_storage *ss)
{
    const char *hostname, *servname;
    struct addrinfo hints, *res = NULL;

    assert(mrb->exc == NULL);

    if (mrb_nil_p(host) || mrb_nil_p(port))
        goto Error; // FIXME

    hostname = mrb_string_value_cstr(mrb, &host);
    if (mrb->exc != NULL)
        goto Error;

    servname = mrb_string_value_cstr(mrb, &port);
    if (mrb->exc != NULL)
        goto Error;

    /* call getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
    if (getaddrinfo(hostname, servname, &hints, &res) != 0) {
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "getaddrinfo failed"));
        goto Error;
    }

    switch(res->ai_family) {
        case AF_INET:
        case AF_INET6:
            memcpy(ss, res->ai_addr, res->ai_addrlen);
            break;
        default:
            mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "unknown address family"));
            goto Error;
    }

    socklen_t len =  res->ai_addrlen;
    freeaddrinfo(res);
    return len;

Error:
    assert(mrb->exc != NULL);
    if (res != NULL)
        freeaddrinfo(res);
    return 0;
}

static int handle_request_header(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_req)
{
    h2o_req_t *req = _req;
    const h2o_token_t *token;

    /* convert env key to header name (lower case) */
    name = convert_env_to_header_name(&req->pool, name.base, name.len);
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

    h2o_iovec_t list[] = {prefix, msg};
    h2o_iovec_t concat = h2o_concat_list(&subreq->super.pool, list, 2);
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
    h2o_req_t *super = &subreq->super;
    memset(&subreq->conn, 0, sizeof(subreq->conn));
    subreq->ctx = ctx;
    subreq->receiver = mrb_nil_value();
    subreq->ref = mrb_nil_value();
    subreq->chunks = mrb_ary_new(mrb);
    mrb_gc_register(mrb, subreq->chunks);
    subreq->shortcut = NULL;
    subreq->final_received = 0;
    subreq->chain_proceed = 0;

    /* initialize super and conn */
    subreq->conn.super.ctx = ctx->shared->ctx;
    h2o_init_request(&subreq->super, &subreq->conn.super, NULL);
    super->is_subrequest = 1;
    h2o_ostream_t *ostream = h2o_add_ostream(super, H2O_ALIGNOF(*ostream), sizeof(*ostream), &super->_ostr_top);
    ostream->do_send = subreq_ostream_send;
    if (ctx->handler->pathconf->host) {
        subreq->conn.super.hosts = h2o_mem_alloc_pool(&subreq->super.pool, H2O_ALIGNOF(subreq->conn.super.hosts[0]), sizeof(subreq->conn.super.hosts[0]) * 2);
        subreq->conn.super.hosts[0] = ctx->handler->pathconf->host;
        subreq->conn.super.hosts[1] = NULL;
    } else {
        subreq->conn.super.hosts = ctx->handler->pathconf->global->hosts;
    }
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
    mrb_value server_addr = mrb_nil_value();
    mrb_value server_port = mrb_nil_value();
    mrb_value remote_addr = mrb_nil_value();
    mrb_value remote_port = mrb_nil_value();
    mrb_value server_protocol = mrb_nil_value();
    mrb_value remaining_delegations = mrb_nil_value();
    mrb_value remaining_reprocesses = mrb_nil_value();
    mrb_value rack_errors = mrb_nil_value();

#define RETRIEVE_ENV(val, stringify) do { \
    val = kh_value(h, k).v; \
    if (!mrb_nil_p(val) && stringify) { \
        val = h2o_mruby_to_str(mrb, val); \
        if (mrb->exc != NULL) \
            goto Failed; \
    } \
} while (0)
#define CALC_HASH(str, strlen) ((strlen) ^ str[0])
#define CHECK_KEY(lit) (CALC_HASH(lit, sizeof(lit) - 1) == CALC_HASH(RSTRING_PTR(key), RSTRING_LEN(key)) && memcmp(RSTRING_PTR(key), lit, RSTRING_LEN(key)) == 0)

    khiter_t k;
    khash_t(ht) *h = mrb_hash_tbl(mrb, env);
    for (k = kh_begin(h); k != kh_end(h); ++k) {
        if (!kh_exist(h, k))
            continue;
        mrb_value key = h2o_mruby_to_str(mrb, kh_key(h, k));
        if (mrb->exc != NULL)
            goto Failed;
        mrb_value value = h2o_mruby_to_str(mrb, kh_value(h, k).v);
        if (mrb->exc != NULL)
            goto Failed;

        if (CHECK_KEY("CONTENT_LENGTH")) {
            super->content_length = h2o_strtosize(RSTRING_PTR(value), RSTRING_LEN(value));
        } else if (CHECK_KEY("PATH_INFO")) {
            RETRIEVE_ENV(path_info, 1);
        } else if (CHECK_KEY("QUERY_STRING")) {
            RETRIEVE_ENV(query_string, 1);
        } else if (CHECK_KEY("REMOTE_ADDR")) {
            RETRIEVE_ENV(remote_addr, 1);
        } else if (CHECK_KEY("REMOTE_PORT")) {
            RETRIEVE_ENV(remote_port, 1);
        } else if (CHECK_KEY("REQUEST_METHOD")) {
            RETRIEVE_ENV(method, 1);
        } else if (CHECK_KEY("SCRIPT_NAME")) {
            RETRIEVE_ENV(script_name, 1);
        } else if (CHECK_KEY("SERVER_ADDR")) {
            RETRIEVE_ENV(server_addr, 1);
        } else if (CHECK_KEY("SERVER_PORT")) {
            RETRIEVE_ENV(server_port, 1);
        } else if (CHECK_KEY("SERVER_PROTOCOL")) {
            RETRIEVE_ENV(server_protocol, 1);
        } else if (CHECK_KEY("h2o.remaining_delegations")) {
            RETRIEVE_ENV(remaining_delegations, 0);
        } else if (CHECK_KEY("h2o.remaining_reprocesses")) {
            RETRIEVE_ENV(remaining_reprocesses, 0);
        } else if (CHECK_KEY("rack.errors")) {
            RETRIEVE_ENV(rack_errors, 0);
        } else if (CHECK_KEY("rack.input")) {
            RETRIEVE_ENV(rack_input, 0);
        } else if (CHECK_KEY("rack.url_scheme")) {
            RETRIEVE_ENV(scheme, 1);
        } else if (RSTRING_LEN(key) >= 5 && memcmp(RSTRING_PTR(key), "HTTP_", 5) == 0) {
            h2o_mruby_split_header_pair(ctx->shared, key, value, handle_request_header, &subreq->super);
        } else {
            /* set to req->env */
            h2o_vector_reserve(&super->pool, &super->env, super->env.size + 2);
            super->env.entries[super->env.size] = h2o_strdup(&super->pool, RSTRING_PTR(key), RSTRING_LEN(key));
            super->env.entries[super->env.size + 1] = h2o_strdup(&super->pool, RSTRING_PTR(value), RSTRING_LEN(value));
            super->env.size += 2;
        }
    }
#undef RETRIEVE_ENV
#undef CALC_HASH
#undef CHECK_KEY

#define CHECK_REQUIRED(key, val) do { \
    if (mrb_nil_p(val)) { \
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "missing required environment key: ## key")); \
        goto Failed; \
    } \
} while (0)
    CHECK_REQUIRED("REQUEST_METHOD", method);
    CHECK_REQUIRED("rack.url_scheme", scheme);
    CHECK_REQUIRED("SCRIPT_NAME", script_name);
    CHECK_REQUIRED("PATH_INFO", path_info);
    CHECK_REQUIRED("QUERY_STRING", query_string);
#undef CHECK_REQUIRED

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
    h2o_iovec_t *url_comps = alloca(sizeof(*url_comps) * 9);
    int num_comps = 0;
    url_comps[num_comps++] = STR_TO_IOVEC(scheme);
    url_comps[num_comps++] = h2o_iovec_init(H2O_STRLIT("://"));
    url_comps[num_comps++] = STR_TO_IOVEC(server_addr);
    url_comps[num_comps++] = h2o_iovec_init(H2O_STRLIT(":"));
    url_comps[num_comps++] = STR_TO_IOVEC(server_port);
    url_comps[num_comps++] = STR_TO_IOVEC(script_name);
    url_comps[num_comps++] = STR_TO_IOVEC(path_info);
    if (RSTRING_LEN(query_string) != 0) {
        url_comps[num_comps++] = h2o_iovec_init(H2O_STRLIT("?"));
        url_comps[num_comps++] = STR_TO_IOVEC(query_string);
    }
    h2o_iovec_t url_str = h2o_concat_list(&super->pool, url_comps, num_comps);
    h2o_url_t url_parsed;
    if (h2o_url_parse(url_str.base, url_str.len, &url_parsed) != 0) {
        /* TODO is there any other way to show better error message? */
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env variable contains invalid values"));
        goto Failed;
    }

    /* setup req and conn using retrieved values */
    super->input.scheme = url_parsed.scheme;
    super->input.method = h2o_strdup(&super->pool, RSTRING_PTR(method), RSTRING_LEN(method));
    super->input.authority = h2o_strdup(&super->pool, url_parsed.authority.base, url_parsed.authority.len);
    super->input.path = h2o_strdup(&super->pool, url_parsed.path.base, url_parsed.path.len);
    h2o_hostconf_t *hostconf = h2o_req_setup(super);
    super->hostconf = hostconf;
    super->pathconf = ctx->handler->pathconf;
    super->version = h2o_parse_protocol_version(STR_TO_IOVEC(server_protocol));
    if (super->version == -1)
        super->version = 0x101;

    // TODO how about unix socket?
    subreq->conn.server.len = parse_hostport(mrb, server_addr, server_port, &subreq->conn.server.addr);
    if (mrb->exc != NULL)
        goto Failed;
    subreq->conn.remote.len = parse_hostport(mrb, remote_addr, remote_port, &subreq->conn.remote.addr);
    if (mrb->exc != NULL)
        goto Failed;

    if (! mrb_nil_p(remaining_delegations)) {
        mrb_int v = mrb_int(mrb, remaining_delegations);
        super->remaining_delegations = (unsigned)(v < 0 ? 0 : v);
    }
    if (! mrb_nil_p(remaining_reprocesses)) {
        mrb_int v = mrb_int(mrb, remaining_reprocesses);
        super->remaining_reprocesses = (unsigned)(v < 0 ? 0 : v);
    }

    if (! mrb_nil_p(rack_errors)) {
        subreq->error_stream = rack_errors;
        mrb_gc_register(mrb, rack_errors);
        super->error_logger.cb = on_subreq_error_callback;
        super->error_logger.data = subreq;
    }

    prepare_subreq_entity(super, ctx, rack_input);
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

static mrb_value middleware_call_callback(h2o_mruby_context_t *ctx, mrb_value input, mrb_value *receiver, mrb_value args, int *run_again)
{
    mrb_state *mrb = ctx->shared->mrb;

    mrb_value env = mrb_ary_entry(args, 0);
    if (! mrb_hash_p(env)) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env must be a hash");
    }

    mrb_value reprocess = mrb_ary_entry(args, 1);

    /* create subreq */
    struct st_mruby_subreq_t *subreq = create_subreq(ctx, env, mrb_bool(reprocess));
    if (mrb->exc != NULL) {
        mrb_value exc = mrb_obj_value(mrb->exc);
        mrb->exc = NULL;
        *run_again = 1;
        return exc;
    }
    subreq->receiver = *receiver;
    mrb_gc_register(mrb, *receiver);

    h2o_req_t *super = &subreq->super;

    if (mrb_bool(reprocess)) {
        h2o_reprocess_request_deferred(super, super->method, super->scheme, super->authority, super->path, super->overrides, 1);
    } else {
        h2o_delegate_request_deferred(super);
    }

    return mrb_nil_value();
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

    if (RARRAY_LEN(subreq->chunks) > 0) {
        *run_again = 1;
        mrb_value chunk = mrb_ary_shift(mrb, subreq->chunks);
        return chunk;
    } else if (subreq->final_received) {
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

    h2o_mruby_define_callback(mrb, "_h2o_middleware_call", middleware_call_callback);
    h2o_mruby_define_callback(mrb, "_h2o_middleware_wait_chunk", middleware_wait_chunk_callback);
    struct RClass *klass = mrb_class_get_under(shared_ctx->mrb, module, "AppInputStream");
    mrb_ary_set(shared_ctx->mrb, shared_ctx->constants, H2O_MRUBY_APP_INPUT_STREAM_CLASS, mrb_obj_value(klass));
    h2o_mruby_assert(mrb);
}

static void flush_chunks(struct st_mruby_subreq_t *subreq)
{
    h2o_mruby_generator_t *generator = subreq->shortcut;
    mrb_state *mrb = generator->ctx->shared->mrb;
    assert(!mrb_nil_p(subreq->ref));

    size_t bufcnt = RARRAY_LEN(subreq->chunks);
    h2o_iovec_t *bufs = alloca(sizeof(h2o_iovec_t) * bufcnt);

    if (bufcnt > 0) {
        int i;
        for (i = 0; i != bufcnt; ++i) {
            mrb_value chunk = mrb_ary_entry(subreq->chunks, i);
            bufs[i].base = RSTRING_PTR(chunk);
            bufs[i].len = RSTRING_LEN(chunk);
        }
        mrb_ary_clear(mrb, subreq->chunks);
    }

    h2o_mruby_sender_do_send(generator, bufs, bufcnt, subreq->final_received ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
}

void do_sender_start(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)generator->sender;
    struct st_mruby_subreq_t *subreq = sender->subreq;
    flush_chunks(subreq);
}

void do_sender_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    mrb_state *mrb = generator->ctx->shared->mrb;
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)generator->sender;

    if (generator->sender->final_sent)
        return; /* TODO: close subreq ASAP */

    if (!mrb_nil_p(sender->subreq->chunks)) {
        if (RARRAY_LEN(sender->subreq->chunks) > 0) {
            flush_chunks(sender->subreq);
            return;
        } else {
            mrb_gc_unregister(mrb, sender->subreq->chunks);
            sender->subreq->chunks = mrb_nil_value();
        }
    }

    if (sender->subreq->chain_proceed)
        h2o_proceed_response(&sender->subreq->super);
}

void do_sender_dispose(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_middleware_sender_t *sender = (void *)generator->sender;

    assert(sender->subreq->shortcut == generator);
    sender->subreq->shortcut = NULL;
    dispose_subreq(sender->subreq);
    sender->subreq = NULL;

    h2o_mruby_sender_close_body(generator);
}

h2o_mruby_sender_t *h2o_mruby_middleware_sender_create(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    struct st_mruby_subreq_t *subreq;

    assert(mrb->exc == NULL);

    if ((subreq = mrb_data_check_get_ptr(mrb, body, &app_input_stream_type)) == NULL)
        return NULL;

    struct st_h2o_mruby_middleware_sender_t *sender = (void *)h2o_mruby_sender_create(generator, body, H2O_ALIGNOF(*sender), sizeof(*sender));
    sender->subreq = subreq;

    sender->super.start = do_sender_start;
    sender->super.proceed = do_sender_proceed;
    sender->super.dispose = do_sender_dispose;

    subreq->shortcut = generator;

    return &sender->super;
}
