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

struct st_h2o_mruby_middleware_chunked_t {
    h2o_mruby_chunked_t super;
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

    assert(!mrb_nil_p(subreq->error_stream));
    mrb_gc_unregister(subreq->ctx->shared->mrb, subreq->error_stream);
    subreq->error_stream = mrb_nil_value();

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

/* TODO: remove */
static int build_env_sort_header_cb(const void *_x, const void *_y)
{
    const h2o_header_t *x = *(const h2o_header_t **)_x, *y = *(const h2o_header_t **)_y;
    if (x->name->len < y->name->len)
        return -1;
    if (x->name->len > y->name->len)
        return 1;
    if (x->name->base != y->name->base) {
        int r = memcmp(x->name->base, y->name->base, x->name->len);
        if (r != 0)
            return r;
    }
    assert(x != y);
    /* the order of the headers having the same name needs to be retained */
    return x < y ? -1 : 1;
}

static mrb_value build_app_response(struct st_mruby_subreq_t *subreq)
{
    h2o_req_t *req = &subreq->super;
    h2o_mruby_context_t *ctx = subreq->ctx;
    mrb_state *mrb = ctx->shared->mrb;
    size_t i;

    /* build response array */
    mrb_value resp = mrb_ary_new_capa(mrb, 3);

    /* status */
    mrb_ary_set(mrb, resp, 0, mrb_fixnum_value(req->res.status));

    /* headers */
    {
        mrb_value headers_hash = mrb_hash_new_capa(mrb, (int)req->res.headers.size);
        h2o_header_t **headers_sorted = alloca(sizeof(*headers_sorted) * req->res.headers.size);
        for (i = 0; i != req->res.headers.size; ++i)
            headers_sorted[i] = req->res.headers.entries + i;
        qsort(headers_sorted, req->res.headers.size, sizeof(*headers_sorted), build_env_sort_header_cb);
        for (i = 0; i != req->res.headers.size; ++i) {
            const h2o_header_t *header = headers_sorted[i];
            mrb_value n, v;
            if (h2o_iovec_is_token(header->name)) {
                const h2o_token_t *token = H2O_STRUCT_FROM_MEMBER(h2o_token_t, buf, header->name);
                if (token == H2O_TOKEN_TRANSFER_ENCODING)
                    continue;
                n = mrb_str_new(mrb, token->buf.base, token->buf.len);
            } else {
                n = mrb_str_new(mrb, header->name->base, header->name->len);
            }
            v = mrb_str_new(mrb, header->value.base, header->value.len);
            while (i + 1 < req->res.headers.size) {

                if (!h2o_memis(headers_sorted[i]->name->base, headers_sorted[i]->name->len, headers_sorted[i + 1]->name->base,
                               headers_sorted[i + 1]->name->len))
                    break;
                ++i;
                v = mrb_str_cat_lit(mrb, v, "\n");
                v = mrb_str_cat(mrb, v, headers_sorted[i]->value.base, headers_sorted[i]->value.len);
            }
            mrb_hash_set(mrb, headers_hash, n, v);
        }
        if (req->res.content_length != SIZE_MAX) {
            h2o_token_t *token = H2O_TOKEN_CONTENT_LENGTH;
            mrb_value n = mrb_str_new(mrb, token->buf.base, token->buf.len);
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
        mrb_value chunk = mrb_str_new(mrb, inbufs[i].base, inbufs[i].len);
        mrb_ary_push(mrb, subreq->chunks, chunk);
    }

    mrb_gc_arena_restore(mrb, gc_arena);
}

static void subreq_ostream_send(h2o_ostream_t *_self, h2o_req_t *_subreq, h2o_iovec_t *inbufs, size_t inbufcnt, h2o_send_state_t state)
{
    struct st_mruby_subreq_t *subreq = (void *)_subreq;
    mrb_state *mrb = subreq->ctx->shared->mrb;

    if (subreq->shortcut != NULL) {
        subreq->chain_proceed = 1;
        if (mrb_nil_p(subreq->chunks)) {
            /* flushing chunks has been finished, so send directly */
            h2o_mruby_chunked_send(subreq->shortcut, inbufs, inbufcnt, state);
        } else {
            /* flushing, buffer chunks again */
            push_chunks(subreq, inbufs, inbufcnt);
        }
        return;
    }

    push_chunks(subreq, inbufs, inbufcnt);

    if (h2o_send_state_is_in_progress(state)) {
        h2o_proceed_response_deferred(&subreq->super);
    } else {
        subreq->final_received = 1;
    }

    int gc_arena = mrb_gc_arena_save(mrb);

    /* detach receiver */
    if (! mrb_nil_p(subreq->receiver)) {
        mrb_value receiver = subreq->receiver;
        mrb_gc_unregister(mrb, receiver);
        mrb_gc_protect(mrb, receiver);
        subreq->receiver = mrb_nil_value();

        mrb_value chunk = mrb_ary_shift(mrb, subreq->chunks);
        h2o_mruby_run_fiber(subreq->ctx, receiver, chunk, NULL);
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
    subreq->entity = h2o_strdup(&subreq->pool, RSTRING_PTR(body), RSTRING_LEN(body));

    if (subreq->content_length != SIZE_MAX) {
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
        goto Error;

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
    if (getaddrinfo(hostname, servname, &hints, &res) != 0)
        goto Error;

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
    mrb->exc = NULL;
    return 0;
}

#define KEY_PREFIX "HTTP_"
#define KEY_PREFIX_LEN (sizeof(KEY_PREFIX) - 1)

static h2o_iovec_t convert_env_to_header_name(h2o_mem_pool_t *pool, const char *name, size_t len)
{
    if (len < KEY_PREFIX_LEN || ! h2o_memis(name, KEY_PREFIX_LEN, KEY_PREFIX, KEY_PREFIX_LEN)) {
        return h2o_iovec_init(NULL, 0);
    }

    h2o_iovec_t ret;

    ret.len = len - KEY_PREFIX_LEN;
    ret.base = h2o_mem_alloc_pool(pool, ret.len);

    name += KEY_PREFIX_LEN;
    char *d = ret.base;
    for (; len != 0; ++name, --len)
        *d++ = *name == '_' ? '-' : h2o_tolower(*name);

    return ret;
}

#undef KEY_PREFIX
#undef KEY_PREFIX_LEN

static int handle_request_header(h2o_mruby_shared_context_t *shared_ctx, h2o_iovec_t name, h2o_iovec_t value, void *_req)
{
    h2o_req_t *req = _req;
    const h2o_token_t *token;

    /* convert env key to header name (lower case) */
    name = convert_env_to_header_name(&req->pool, name.base, name.len);
    if (name.base == NULL)
        return 0;

    if ((token = h2o_lookup_token(name.base, name.len)) != NULL) {
        if (token == H2O_TOKEN_TRANSFER_ENCODING) {
            /* skip */
        } else if (token == H2O_TOKEN_CONTENT_LENGTH) {
            req->content_length = h2o_strtosize(value.base, value.len);
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

static void on_subreq_error_callback(h2o_req_t *req, void *_data, h2o_iovec_t error)
{
    struct st_mruby_subreq_t *subreq = (void *)_data;
    mrb_state *mrb = subreq->ctx->shared->mrb;

    assert(!mrb_nil_p(subreq->error_stream));

    mrb_value msg = mrb_str_new(mrb, error.base, error.len);
    mrb_funcall(mrb, subreq->error_stream, "write", 1, msg);
}

static struct st_mruby_subreq_t *create_subreq(h2o_mruby_context_t *ctx, mrb_value env)
{
    mrb_state *mrb = ctx->shared->mrb;
    int i;
    int gc_arena = mrb_gc_arena_save(mrb);
    mrb_gc_protect(mrb, env);

    mrb_value dupenv = mrb_funcall(mrb, env, "dup", 0);

#define RETRIEVE_ENV(key, v, required, stringify) do { \
    v = mrb_hash_delete_key(mrb, dupenv, mrb_ary_entry(ctx->shared->constants, H2O_MRUBY_LIT_ ## key)); \
    if (required && mrb_nil_p(v)) { \
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_RUNTIME_ERROR, "missing required environment key: ## key")); \
        goto Failed; \
    } \
    if (stringify) { \
        v = h2o_mruby_to_str(mrb, v); \
    } \
} while (0)

    /* retrieve env variables */
    mrb_value scheme, method, script_name, path_info, query_string, rack_input, server_addr, server_port, remote_addr, remote_port, server_protocol, remaining_delegations, remaining_reprocesses, rack_errors, _dummy;
    RETRIEVE_ENV(RACK_URL_SCHEME, scheme, 1, 1);
    RETRIEVE_ENV(REQUEST_METHOD, method, 1, 1);
    RETRIEVE_ENV(SERVER_ADDR, server_addr, 0, 1);
    RETRIEVE_ENV(SERVER_PORT, server_port, 0, 1);
    RETRIEVE_ENV(REMOTE_ADDR, remote_addr, 0, 1);
    RETRIEVE_ENV(REMOTE_PORT, remote_port, 0, 1);
    RETRIEVE_ENV(SCRIPT_NAME, script_name, 1, 1);
    RETRIEVE_ENV(PATH_INFO, path_info, 1, 1);
    RETRIEVE_ENV(QUERY_STRING, query_string, 1, 1);
    RETRIEVE_ENV(RACK_INPUT, rack_input, 0, 0);
    RETRIEVE_ENV(SERVER_NAME, _dummy, 0, 0);
    RETRIEVE_ENV(SERVER_PROTOCOL, server_protocol, 1, 1);
    RETRIEVE_ENV(CONTENT_LENGTH, _dummy, 0, 0);
    RETRIEVE_ENV(RACK_MULTITHREAD, _dummy, 0, 0);
    RETRIEVE_ENV(RACK_MULTIPROCESS, _dummy, 0, 0);
    RETRIEVE_ENV(RACK_RUN_ONCE, _dummy, 0, 0);
    RETRIEVE_ENV(RACK_HIJACK_, _dummy, 0, 0);
    RETRIEVE_ENV(RACK_ERRORS, rack_errors, 0, 0);
    RETRIEVE_ENV(SERVER_SOFTWARE, _dummy, 0, 0);
    RETRIEVE_ENV(H2O_REMAINING_DELEGATIONS, remaining_delegations, 0, 0);
    RETRIEVE_ENV(H2O_REMAINING_REPROCESSES, remaining_reprocesses, 0, 0);
#undef RETRIEVE_ENV

    /* construct url and parse */
    mrb_value url = mrb_obj_dup(mrb, scheme);
    mrb_str_concat(mrb, url, mrb_str_new_lit(mrb, "://"));
    mrb_str_concat(mrb, url, server_addr);
    mrb_str_concat(mrb, url, mrb_str_new_lit(mrb, ":"));
    mrb_str_concat(mrb, url, server_port);
    // TODO: what happens if the user modifies SCRIPT_NAME and PATH_INFO?
    mrb_str_concat(mrb, url, script_name);
    mrb_str_concat(mrb, url, path_info);
    if (RSTRING_LEN(query_string) != 0) {
        mrb_str_concat(mrb, url, mrb_str_new_lit(mrb, "?"));
        mrb_str_concat(mrb, url, query_string);
    }

    h2o_url_t url_parsed;
    if (h2o_url_parse(RSTRING_PTR(url), RSTRING_LEN(url), &url_parsed) != 0) {
        /* TODO is there any other way to show better error message? */
        mrb->exc = mrb_obj_ptr(mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env variable contains invalid values"));
        goto Failed;
    }

    struct st_mruby_subreq_t *subreq = h2o_mem_alloc(sizeof(*subreq));
    memset(&subreq->conn, 0, sizeof(subreq->conn));
    subreq->conn.super.ctx = ctx->shared->ctx;
    h2o_init_request(&subreq->super, &subreq->conn.super, NULL);

    /* setup conn */
    if (ctx->pathconf->host) {
        subreq->conn.super.hosts = h2o_mem_alloc_pool(&subreq->super.pool, sizeof(subreq->conn.super.hosts[0]) * 2);
        subreq->conn.super.hosts[0] = ctx->pathconf->host;
        subreq->conn.super.hosts[1] = NULL;
    } else {
        subreq->conn.super.hosts = ctx->pathconf->global->hosts;
    }
    subreq->conn.server.len = parse_hostport(mrb, server_addr, server_port, &subreq->conn.server.addr);
    subreq->conn.remote.len = parse_hostport(mrb, remote_addr, remote_port, &subreq->conn.remote.addr);

    subreq->conn.super.connected_at = (struct timeval){0}; /* no need because subreq won't logged */
    subreq->conn.super.id = 0; /* currently conn->id is used only for logging, so set zero as a meaningless value */

    static const h2o_conn_callbacks_t callbacks = {
        get_sockname,    /* stringify address */
        get_peername,    /* ditto */
        NULL,            /* push (no push in subrequest) */
        get_socket,      /* get underlying socket */
        NULL,            /* get debug state */
        {{{NULL}}}};

    subreq->conn.super.callbacks = &callbacks;

    subreq->ctx = ctx;
    subreq->receiver = mrb_nil_value();
    subreq->ref = mrb_nil_value();
    subreq->chunks = mrb_ary_new(mrb);
    mrb_gc_register(mrb, subreq->chunks);
    subreq->shortcut = NULL;
    subreq->final_received = 0;
    subreq->chain_proceed = 0;

    h2o_req_t *super = &subreq->super;
    super->is_subrequest = 1;
    super->input.scheme = url_parsed.scheme;
    super->input.method = h2o_strdup(&super->pool, RSTRING_PTR(method), RSTRING_LEN(method));
    super->input.authority = h2o_strdup(&super->pool, url_parsed.authority.base, url_parsed.authority.len);
    super->input.path = h2o_strdup(&super->pool, url_parsed.path.base, url_parsed.path.len);
    h2o_hostconf_t *hostconf = h2o_req_setup(super);
    super->hostconf = hostconf;
    super->pathconf = ctx->pathconf;
    super->version = h2o_parse_protocol_version_string(h2o_iovec_init(RSTRING_PTR(server_protocol), RSTRING_LEN(server_protocol)));
    if (super->version == -1)
        super->version = 0x101;

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
        super->error.cb = on_subreq_error_callback;
        super->error.data = subreq;
    }

    /* headers */
    super->headers = (h2o_headers_t){NULL};
    if (h2o_mruby_iterate_headers(ctx->shared, dupenv, handle_request_header, subreq) != 0) {
        goto Failed;
    }

    /* entity */
    prepare_subreq_entity(super, ctx, rack_input);
    if (mrb->exc != NULL)
        goto Failed;

    /* env */
    mrb_value other_keys = mrb_hash_keys(mrb, dupenv);
    for (i = 0; i != RARRAY_LEN(other_keys); ++i) {
        mrb_value key = h2o_mruby_to_str(mrb, mrb_ary_entry(other_keys, i));
        if (memcmp(RSTRING_PTR(key), "HTTP_", 5) == 0)
            continue;
        mrb_value val = h2o_mruby_to_str(mrb, mrb_hash_get(mrb, dupenv, key));
        h2o_vector_reserve(&super->pool, &super->env, super->env.size + 2);
        super->env.entries[super->env.size] = h2o_strdup(&super->pool, RSTRING_PTR(key), RSTRING_LEN(key));
        super->env.entries[super->env.size + 1] = h2o_strdup(&super->pool, RSTRING_PTR(val), RSTRING_LEN(val));
        super->env.size += 2;
    }

    return subreq;

Failed:
    assert(mrb->exc != NULL);
    mrb_gc_arena_restore(mrb, gc_arena);
    return NULL;
}

static void on_postfilter_setup_stream(h2o_req_filter_t *self, h2o_req_t *req, h2o_ostream_t **slot)
{
    struct st_mruby_subreq_t *subreq = (void *)req;
    mrb_state *mrb = subreq->ctx->shared->mrb;

    assert(mrb_nil_p(subreq->ref));
    assert(! mrb_nil_p(subreq->receiver));

    /* at first call, mruby is blocking by H2O.next.call */

    int gc_arena = mrb_gc_arena_save(mrb);

    mrb_value resp = build_app_response(subreq);
    subreq->ref = mrb_ary_entry(resp, 2);

    /* detach receiver */
    mrb_value receiver = subreq->receiver;
    mrb_gc_unregister(mrb, receiver);
    mrb_gc_protect(mrb, receiver);
    subreq->receiver = mrb_nil_value();
    h2o_mruby_run_fiber(subreq->ctx, receiver, resp, NULL);

    mrb_gc_arena_restore(mrb, gc_arena);


    h2o_setup_next_req_filter(self, req, slot);
}

static mrb_value middleware_call_callback(h2o_mruby_context_t *ctx, mrb_value input, mrb_value receiver, mrb_value args, int *run_again)
{
    mrb_state *mrb = ctx->shared->mrb;

    mrb_value env = mrb_ary_entry(args, 0);
    if (! mrb_hash_p(env)) {
        *run_again = 1;
        return mrb_exc_new_str_lit(mrb, E_ARGUMENT_ERROR, "env must be a hash");
    }

    mrb_value reprocess = mrb_ary_entry(args, 1);

    /* create subreq */
    struct st_mruby_subreq_t *subreq = create_subreq(ctx, env);
    if (mrb->exc != NULL) {
        *run_again = 1;
        return mrb_obj_value(mrb->exc);
    }
    subreq->receiver = receiver;
    mrb_gc_register(mrb, receiver);

    h2o_req_t *super = &subreq->super;

    /* create postfilter and final ostream for subreq */
    h2o_req_filter_t *postfilter = (void *)h2o_add_req_filter(super, sizeof(*postfilter), 1);
    postfilter->on_setup_ostream = on_postfilter_setup_stream;
    h2o_ostream_t *ostream = h2o_add_ostream(super, sizeof(*ostream), &super->_ostr_top);
    ostream->do_send = subreq_ostream_send;

    if (mrb_bool(reprocess)) {
        h2o_reprocess_request_deferred(super, super->method, super->scheme, super->authority, super->path, super->overrides, 1);
    } else {
        h2o_delegate_request_deferred(super, &ctx->handler->super);
    }

    return mrb_nil_value();
}

static mrb_value middleware_wait_chunk_callback(h2o_mruby_context_t *mctx, mrb_value input, mrb_value receiver, mrb_value args, int *run_again)
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
        subreq->receiver = receiver;
        mrb_gc_register(mrb, receiver);
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

    h2o_mruby_chunked_send(generator, bufs, bufcnt, subreq->final_received ? H2O_SEND_STATE_FINAL : H2O_SEND_STATE_IN_PROGRESS);
}

void do_chunked_start(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_middleware_chunked_t *chunked = (void *)generator->chunked;
    struct st_mruby_subreq_t *subreq = chunked->subreq;
    flush_chunks(subreq);
}

void do_chunked_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    h2o_mruby_generator_t *generator = (void *)_generator;
    mrb_state *mrb = generator->ctx->shared->mrb;
    struct st_h2o_mruby_middleware_chunked_t *chunked = (void *)generator->chunked;

    if (!mrb_nil_p(chunked->subreq->chunks)) {
        if (RARRAY_LEN(chunked->subreq->chunks) > 0) {
            flush_chunks(chunked->subreq);
            return;
        } else {
            mrb_gc_unregister(mrb, chunked->subreq->chunks);
            chunked->subreq->chunks = mrb_nil_value();
        }
    }

    if (chunked->subreq->chain_proceed)
        h2o_proceed_response(&chunked->subreq->super);
}

void do_chunked_dispose(h2o_mruby_generator_t *generator)
{
    struct st_h2o_mruby_middleware_chunked_t *chunked = (void *)generator->chunked;

    assert(chunked->subreq->shortcut == generator);
    chunked->subreq->shortcut = NULL;
    dispose_subreq(chunked->subreq);
    chunked->subreq = NULL;

    h2o_mruby_chunked_close_body(generator);
}

h2o_mruby_chunked_t *h2o_mruby_middleware_chunked_create(h2o_mruby_generator_t *generator, mrb_value body)
{
    mrb_state *mrb = generator->ctx->shared->mrb;
    struct st_mruby_subreq_t *subreq;

    assert(mrb->exc == NULL);

    if ((subreq = mrb_data_check_get_ptr(mrb, body, &app_input_stream_type)) == NULL)
        return NULL;

    struct st_h2o_mruby_middleware_chunked_t *chunked = (void *)h2o_mruby_chunked_create(generator, body, sizeof(*chunked));
    chunked->subreq = subreq;

    chunked->super.start = do_chunked_start;
    chunked->super.proceed = do_chunked_proceed;
    chunked->super.stop = NULL; /* never be called */
    chunked->super.dispose = do_chunked_dispose;

    subreq->shortcut = generator;

    return &chunked->super;
}
