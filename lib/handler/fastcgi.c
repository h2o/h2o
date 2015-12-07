/*
 * Copyright (c) 2015 DeNA Co., Ltd. Kazuho Oku
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
#include <inttypes.h>
#include <stdio.h>
#include "picohttpparser.h"
#include "h2o.h"

#define FCGI_VERSION_1 1

#define FCGI_RESPONDER 1
#define FCGI_KEEP_CONN 1

#define FCGI_BEGIN_REQUEST 1
#define FCGI_END_REQUEST 3
#define FCGI_PARAMS 4
#define FCGI_STDIN 5
#define FCGI_STDOUT 6
#define FCGI_STDERR 7
#define FCGI_DATA 8

#define FCGI_RECORD_HEADER_SIZE (sizeof(struct st_fcgi_record_header_t))
#define FCGI_BEGIN_REQUEST_BODY_SIZE 8

#define MODULE_NAME "lib/handler/fastcgi.c"

#define APPEND_BLOCKSIZE 512 /* the size should be small enough to be allocated within the buffer of the memory pool */

struct st_fcgi_record_header_t {
    uint8_t version;
    uint8_t type;
    uint16_t requestId;
    uint16_t contentLength;
    uint8_t paddingLength;
    uint8_t reserved;
};

struct st_fcgi_begin_request_body_t {
    uint16_t role;
    uint8_t flags;
    uint8_t reserved[5];
};

typedef H2O_VECTOR(h2o_iovec_t) iovec_vector_t;

struct st_fcgi_context_t {
    h2o_fastcgi_handler_t *handler;
    h2o_timeout_t io_timeout;
};

struct st_fcgi_generator_t {
    h2o_generator_t super;
    struct st_fcgi_context_t *ctx;
    h2o_req_t *req;
    h2o_socketpool_connect_request_t *connect_req;
    h2o_socket_t *sock;
    int sent_headers;
    size_t leftsize; /* remaining amount of the content to receive (or SIZE_MAX if unknown) */
    struct {
        h2o_doublebuffer_t sending;
        h2o_buffer_t *receiving;
    } resp;
    h2o_timeout_entry_t timeout;
};

struct st_h2o_fastcgi_handler_t {
    h2o_handler_t super;
    h2o_socketpool_t sockpool;
    h2o_fastcgi_config_vars_t config;
};

static void encode_uint16(void *_p, unsigned v)
{
    unsigned char *p = _p;
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
}

static void encode_record_header(void *p, uint8_t type, uint16_t reqId, uint16_t sz)
{
    struct st_fcgi_record_header_t *header = p;
    header->version = FCGI_VERSION_1;
    header->type = type;
    encode_uint16(&header->requestId, reqId);
    encode_uint16(&header->contentLength, sz);
    header->paddingLength = 0;
    header->reserved = 0;
}

static void encode_begin_request(void *p, uint16_t reqId, uint16_t role, uint8_t flags)
{
    encode_record_header(p, FCGI_BEGIN_REQUEST, reqId, FCGI_BEGIN_REQUEST_BODY_SIZE);
    struct st_fcgi_begin_request_body_t *body = (void *)((char *)p + FCGI_RECORD_HEADER_SIZE);
    encode_uint16(&body->role, role);
    body->flags = flags;
    memset(body->reserved, 0, sizeof(body->reserved));
}

static h2o_iovec_t create_begin_request(h2o_mem_pool_t *pool, uint16_t reqId, uint16_t role, uint8_t flags)
{
    h2o_iovec_t rec = h2o_iovec_init(h2o_mem_alloc_pool(pool, FCGI_RECORD_HEADER_SIZE + FCGI_BEGIN_REQUEST_BODY_SIZE),
                                     FCGI_RECORD_HEADER_SIZE + FCGI_BEGIN_REQUEST_BODY_SIZE);
    encode_begin_request(rec.base, reqId, role, flags);
    return rec;
}

static h2o_iovec_t create_header(h2o_mem_pool_t *pool, uint8_t type, uint16_t reqId, uint16_t sz)
{
    h2o_iovec_t rec = h2o_iovec_init(h2o_mem_alloc_pool(pool, FCGI_RECORD_HEADER_SIZE), FCGI_RECORD_HEADER_SIZE);
    encode_record_header(rec.base, type, reqId, sz);
    return rec;
}

static void decode_header(struct st_fcgi_record_header_t *decoded, const void *s)
{
    memcpy(decoded, s, sizeof(*decoded));
    decoded->requestId = htons(decoded->requestId);
    decoded->contentLength = htons(decoded->contentLength);
}

static char *allocate_buffer(h2o_mem_pool_t *pool, iovec_vector_t *blocks, size_t len)
{
    h2o_iovec_t *slot;

    if (blocks->entries[blocks->size - 1].len + len > APPEND_BLOCKSIZE) {
        h2o_vector_reserve(pool, (void *)blocks, sizeof(blocks->entries[0]), blocks->size + 1);
        slot = blocks->entries + blocks->size++;
        slot->base = h2o_mem_alloc_pool(pool, len < APPEND_BLOCKSIZE ? APPEND_BLOCKSIZE : len);
        slot->len = 0;
    } else {
        slot = blocks->entries + blocks->size - 1;
    }

    slot->len += len;
    return slot->base + slot->len - len;
}

static char *encode_length(char *p, size_t len)
{
    if (len < 127) {
        *p++ = (char)len;
    } else {
        *p++ = (unsigned char)(len >> 24) | 0x80;
        *p++ = (unsigned char)(len >> 16);
        *p++ = (unsigned char)(len >> 8);
        *p++ = (unsigned char)len;
    }
    return p;
}

static void *append_field(h2o_req_t *req, const char *name, size_t namelen, int is_http_header, size_t valuelen, void *append_arg)
{
    iovec_vector_t *blocks = (void *)append_arg;
    char lenbuf[8];
    size_t lengths_len;
    char *dst;

    if (is_http_header)
        namelen += 5;

    lengths_len = encode_length(encode_length(lenbuf, namelen), valuelen) - lenbuf;
    dst = allocate_buffer(&req->pool, blocks, lengths_len);
    memcpy(dst, lenbuf, lengths_len);

    dst = allocate_buffer(&req->pool, blocks, namelen);
    if (is_http_header) {
        memcpy(dst, "HTTP_", 5);
        for (dst += 5, namelen -= 5; namelen != 0; --namelen, ++dst, ++name)
            *dst = *name == '-' ? '_' : h2o_toupper(*name);
    } else {
        memcpy(dst, name, namelen);
    }

    return allocate_buffer(&req->pool, blocks, valuelen);
}

static void annotate_params(h2o_mem_pool_t *pool, iovec_vector_t *vecs, unsigned request_id, size_t max_record_size)
{
    size_t index = 2, recsize = 0, header_slot = 1;

    while (index != vecs->size) {
        if (recsize + vecs->entries[index].len < max_record_size) {
            recsize += vecs->entries[index].len;
            ++index;
        } else {
            vecs->entries[header_slot] = create_header(pool, FCGI_PARAMS, request_id, max_record_size);
            if (recsize + vecs->entries[index].len == max_record_size) {
                h2o_vector_reserve(pool, (void *)vecs, sizeof(vecs->entries[0]), vecs->size + 1);
                memmove(vecs->entries + index + 2, vecs->entries + index + 1,
                        (vecs->size - (index + 1)) * sizeof(vecs->entries[0]));
                ++vecs->size;
            } else {
                h2o_vector_reserve(pool, (void *)vecs, sizeof(vecs->entries[0]), vecs->size + 2);
                memmove(vecs->entries + index + 2, vecs->entries + index, (vecs->size - index) * sizeof(vecs->entries[0]));
                vecs->size += 2;
                size_t lastsz = max_record_size - recsize;
                vecs->entries[index].len = lastsz;
                vecs->entries[index + 2].base += lastsz;
                vecs->entries[index + 2].len -= lastsz;
            }
            header_slot = index + 1;
            index += 2;
            recsize = 0;
        }
    }

    vecs->entries[header_slot] = create_header(pool, FCGI_PARAMS, request_id, recsize);
    if (recsize != 0) {
        h2o_vector_reserve(pool, (void *)vecs, sizeof(vecs->entries[0]), vecs->size + 1);
        vecs->entries[vecs->size++] = create_header(pool, FCGI_PARAMS, request_id, 0);
    }
}

static void build_request(h2o_req_t *req, iovec_vector_t *vecs, unsigned request_id, size_t max_record_size,
                          h2o_fastcgi_config_vars_t *config)
{
    *vecs = (iovec_vector_t){};

    /* first entry is FCGI_BEGIN_REQUEST */
    h2o_vector_reserve(&req->pool, (void *)vecs, sizeof(vecs->entries[0]), 5 /* we send at least 5 iovecs */);
    vecs->entries[0] =
        create_begin_request(&req->pool, request_id, FCGI_RESPONDER, config->keepalive_timeout != 0 ? FCGI_KEEP_CONN : 0);
    /* second entry is reserved for FCGI_PARAMS header */
    vecs->entries[1] = h2o_iovec_init(NULL, APPEND_BLOCKSIZE); /* dummy value set to prevent params being appended to the entry */
    vecs->size = 2;
    /* accumulate the params data, and annotate them with FCGI_PARAM headers */
    h2o_cgiutil_build_request(req, config->document_root, config->send_delegated_uri, append_field, vecs);
    annotate_params(&req->pool, vecs, request_id, max_record_size);
    /* setup FCGI_STDIN headers */
    if (req->entity.len != 0) {
        size_t off = 0;
        for (; off + max_record_size < req->entity.len; off += max_record_size) {
            h2o_vector_reserve(&req->pool, (void *)vecs, sizeof(vecs->entries[0]), vecs->size + 2);
            vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, max_record_size);
            vecs->entries[vecs->size++] = h2o_iovec_init(req->entity.base + off, max_record_size);
        }
        if (off != req->entity.len) {
            h2o_vector_reserve(&req->pool, (void *)vecs, sizeof(vecs->entries[0]), vecs->size + 2);
            vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, req->entity.len - off);
            vecs->entries[vecs->size++] = h2o_iovec_init(req->entity.base + off, req->entity.len - off);
        }
    }
    h2o_vector_reserve(&req->pool, (void *)vecs, sizeof(vecs->entries[0]), vecs->size + 1);
    vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, 0);
}

static void set_timeout(struct st_fcgi_generator_t *generator, h2o_timeout_t *timeout, h2o_timeout_cb cb)
{
    if (h2o_timeout_is_linked(&generator->timeout))
        h2o_timeout_unlink(&generator->timeout);

    generator->timeout.cb = cb;
    h2o_timeout_link(generator->req->conn->ctx->loop, timeout, &generator->timeout);
}

static void close_generator(struct st_fcgi_generator_t *generator)
{
    /* can be called more than once */

    if (h2o_timeout_is_linked(&generator->timeout))
        h2o_timeout_unlink(&generator->timeout);
    if (generator->connect_req != NULL) {
        h2o_socketpool_cancel_connect(generator->connect_req);
        generator->connect_req = NULL;
    }
    if (generator->sock != NULL) {
        h2o_socket_close(generator->sock);
        generator->sock = NULL;
    }
    if (generator->resp.sending.buf != NULL)
        h2o_doublebuffer_dispose(&generator->resp.sending);
    if (generator->resp.receiving != NULL)
        h2o_buffer_dispose(&generator->resp.receiving);
}

static void do_send(struct st_fcgi_generator_t *generator)
{
    h2o_iovec_t vecs[1];
    size_t veccnt;
    int is_final;

    vecs[0] = h2o_doublebuffer_prepare(&generator->resp.sending, &generator->resp.receiving, generator->req->preferred_chunk_size);
    veccnt = vecs[0].len != 0 ? 1 : 0;
    if (generator->sock == NULL && vecs[0].len == generator->resp.sending.buf->size && generator->resp.receiving->size == 0) {
        is_final = 1;
    } else {
        if (veccnt == 0)
            return;
        is_final = 0;
    }
    h2o_send(generator->req, vecs, veccnt, is_final);
}

static void send_eos_and_close(struct st_fcgi_generator_t *generator, int can_keepalive)
{
    if (generator->ctx->handler->config.keepalive_timeout != 0 && can_keepalive)
        h2o_socketpool_return(&generator->ctx->handler->sockpool, generator->sock);
    else
        h2o_socket_close(generator->sock);
    generator->sock = NULL;

    if (h2o_timeout_is_linked(&generator->timeout))
        h2o_timeout_unlink(&generator->timeout);

    /* disconnect HTTP1, if failed to accumulate amount of bytes sent in content-length header */
    if (generator->leftsize != 0 && generator->leftsize != SIZE_MAX)
        generator->req->http1_is_persistent = 0;

    if (generator->resp.sending.bytes_inflight == 0)
        do_send(generator);
}

static void errorclose(struct st_fcgi_generator_t *generator)
{
    if (generator->sent_headers) {
        send_eos_and_close(generator, 0);
    } else {
        h2o_req_t *req = generator->req;
        close_generator(generator);
        h2o_send_error(req, 503, "Internal Server Error", "Internal Server Error", 0);
    }
}

static void append_content(struct st_fcgi_generator_t *generator, const void *src, size_t len)
{
    /* do not accumulate more than content-length bytes */
    if (generator->leftsize != SIZE_MAX) {
        if (generator->leftsize < len) {
            len = generator->leftsize;
            if (len == 0)
                return;
        }
        generator->leftsize -= len;
    }

    h2o_iovec_t reserved = h2o_buffer_reserve(&generator->resp.receiving, len);
    memcpy(reserved.base, src, len);
    generator->resp.receiving->size += len;
}

static int handle_stdin_record(struct st_fcgi_generator_t *generator, struct st_fcgi_record_header_t *header)
{
    h2o_buffer_t *input = generator->sock->input;
    struct phr_header headers[100];
    size_t num_headers;
    int parse_result;
    const char *fill_err;

    if (header->contentLength == 0)
        return 0;

    if (generator->sent_headers) {
        /* simply accumulate the data to response buffer */
        append_content(generator, input->bytes + FCGI_RECORD_HEADER_SIZE, header->contentLength);
        return 0;
    }

    /* parse the headers using the input buffer (or keep it in response buffer and parse) */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    if (generator->resp.receiving->size == 0) {
        parse_result = phr_parse_headers(input->bytes + FCGI_RECORD_HEADER_SIZE, input->size, headers, &num_headers, 0);
    } else {
        size_t prevlen = generator->resp.receiving->size;
        memcpy(h2o_buffer_reserve(&generator->resp.receiving, header->contentLength).base, input->bytes + FCGI_RECORD_HEADER_SIZE,
               header->contentLength);
        generator->resp.receiving->size = prevlen + header->contentLength;
        parse_result =
            phr_parse_headers(generator->resp.receiving->bytes, generator->resp.receiving->size, headers, &num_headers, prevlen);
    }
    if (parse_result < 0) {
        if (parse_result == -2) {
            /* incomplete */
            return 0;
        } else {
            h2o_req_log_error(generator->req, MODULE_NAME, "received broken response");
            return -1;
        }
    }

    /* fill-in the headers, and start the response */
    if ((fill_err = h2o_cgiutil_build_response(generator->req, headers, num_headers)) != NULL) {
        h2o_req_log_error(generator->req, MODULE_NAME, "%s", fill_err);
        return -1;
    }
    generator->leftsize = generator->req->res.content_length;
    h2o_start_response(generator->req, &generator->super);
    generator->sent_headers = 1;

    /* rest of the contents should be stored in the response buffer */
    if (generator->resp.receiving->size == 0) {
        size_t leftlen = header->contentLength - parse_result;
        if (leftlen != 0) {
            append_content(generator, input->bytes + FCGI_RECORD_HEADER_SIZE + parse_result, leftlen);
        }
    } else {
        h2o_buffer_consume(&generator->resp.receiving, parse_result);
    }

    return 0;
}

static void on_rw_timeout(h2o_timeout_entry_t *entry)
{
    struct st_fcgi_generator_t *generator = H2O_STRUCT_FROM_MEMBER(struct st_fcgi_generator_t, timeout, entry);

    h2o_req_log_error(generator->req, MODULE_NAME, "I/O timeout");
    errorclose(generator);
}

static void on_read(h2o_socket_t *sock, int status)
{
    struct st_fcgi_generator_t *generator = sock->data;
    int can_keepalive = 0;

    if (status != 0) {
        h2o_req_log_error(generator->req, MODULE_NAME, "fastcgi connection closed unexpectedly");
        errorclose(generator);
        return;
    }

    /* handle the records */
    while (1) {
        struct st_fcgi_record_header_t header;
        size_t recsize;
        if (sock->input->size < FCGI_RECORD_HEADER_SIZE)
            break;
        decode_header(&header, sock->input->bytes);
        recsize = FCGI_RECORD_HEADER_SIZE + header.contentLength + header.paddingLength;
        if (sock->input->size < recsize)
            break;
        /* we have a complete record */
        switch (header.type) {
        case FCGI_STDOUT:
            if (handle_stdin_record(generator, &header) != 0)
                goto Error;
            h2o_buffer_consume(&sock->input, recsize);
            break;
        case FCGI_STDERR:
            if (header.contentLength != 0)
                h2o_req_log_error(generator->req, MODULE_NAME, "%.*s", (int)header.contentLength,
                                  sock->input->bytes + FCGI_RECORD_HEADER_SIZE);
            h2o_buffer_consume(&sock->input, recsize);
            break;
        case FCGI_END_REQUEST:
            if (!generator->sent_headers) {
                h2o_req_log_error(generator->req, MODULE_NAME, "received FCGI_END_REQUEST before end of the headers");
                goto Error;
            }
            h2o_buffer_consume(&sock->input, recsize);
            can_keepalive = 1;
            goto EOS_Received;
        default:
            h2o_req_log_error(generator->req, MODULE_NAME, "received unexpected record, type: %u", header.type);
            h2o_buffer_consume(&sock->input, recsize);
            if (!generator->sent_headers)
                goto Error;
            goto EOS_Received;
        }
    }

    /* send data if necessary */
    if (generator->sent_headers && generator->resp.sending.bytes_inflight == 0)
        do_send(generator);

    set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);
    return;

EOS_Received:
    send_eos_and_close(generator, can_keepalive);
    return;

Error:
    errorclose(generator);
}

static void on_send_complete(h2o_socket_t *sock, int status)
{
    struct st_fcgi_generator_t *generator = sock->data;

    set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);
    /* do nothing else!  all the rest is handled by the on_read */
}

static void on_connect(h2o_socket_t *sock, const char *errstr, void *data)
{
    struct st_fcgi_generator_t *generator = data;
    iovec_vector_t vecs;

    generator->connect_req = NULL;

    if (sock == NULL) {
        h2o_req_log_error(generator->req, MODULE_NAME, "connection failed:%s", errstr);
        errorclose(generator);
        return;
    }

    generator->sock = sock;
    sock->data = generator;

    build_request(generator->req, &vecs, 1, 65535, &generator->ctx->handler->config);

    /* start sending the response */
    h2o_socket_write(generator->sock, vecs.entries, vecs.size, on_send_complete);

    set_timeout(generator, &generator->ctx->io_timeout, on_rw_timeout);

    /* activate the receiver; note: FCGI spec allows the app to start sending the response before it receives FCGI_STDIN */
    h2o_socket_read_start(sock, on_read);
}

static void do_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    struct st_fcgi_generator_t *generator = (void *)_generator;

    h2o_doublebuffer_consume(&generator->resp.sending);
    do_send(generator);
}

static void do_stop(h2o_generator_t *_generator, h2o_req_t *req)
{
    struct st_fcgi_generator_t *generator = (void *)_generator;
    close_generator(generator);
}

static void on_connect_timeout(h2o_timeout_entry_t *entry)
{
    struct st_fcgi_generator_t *generator = H2O_STRUCT_FROM_MEMBER(struct st_fcgi_generator_t, timeout, entry);

    h2o_req_log_error(generator->req, MODULE_NAME, "connect timeout");
    errorclose(generator);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;
    struct st_fcgi_generator_t *generator;

    generator = h2o_mem_alloc_shared(&req->pool, sizeof(*generator), (void (*)(void *))close_generator);
    generator->super.proceed = do_proceed;
    generator->super.stop = do_stop;
    generator->ctx = h2o_context_get_handler_context(req->conn->ctx, &handler->super);
    generator->req = req;
    generator->sock = NULL;
    generator->sent_headers = 0;
    h2o_doublebuffer_init(&generator->resp.sending, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&generator->resp.receiving, &h2o_socket_buffer_prototype);
    generator->timeout = (h2o_timeout_entry_t){};

    set_timeout(generator, &generator->ctx->io_timeout, on_connect_timeout);
    h2o_socketpool_connect(&generator->connect_req, &handler->sockpool, req->conn->ctx->loop,
                           &req->conn->ctx->receivers.hostinfo_getaddr, on_connect, generator);

    return 0;
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;
    struct st_fcgi_context_t *handler_ctx = h2o_mem_alloc(sizeof(*handler_ctx));

    /* use the first event loop for handling timeouts of the socket pool */
    if (handler->sockpool.timeout == UINT64_MAX)
        h2o_socketpool_set_timeout(&handler->sockpool, ctx->loop,
                                   handler->config.keepalive_timeout != 0 ? handler->config.keepalive_timeout : 60000);

    handler_ctx->handler = handler;
    h2o_timeout_init(ctx->loop, &handler_ctx->io_timeout, handler->config.io_timeout);

    h2o_context_set_handler_context(ctx, &handler->super, handler_ctx);
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;
    struct st_fcgi_context_t *handler_ctx = h2o_context_get_handler_context(ctx, &handler->super);

    if (handler_ctx == NULL)
        return;

    h2o_timeout_dispose(ctx->loop, &handler_ctx->io_timeout);
    free(handler_ctx);
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;

    if (handler->config.callbacks.dispose != NULL)
        handler->config.callbacks.dispose(handler, handler->config.callbacks.data);

    h2o_socketpool_dispose(&handler->sockpool);
    free(handler->config.document_root.base);
    free(handler);
}

static h2o_fastcgi_handler_t *register_common(h2o_pathconf_t *pathconf, h2o_fastcgi_config_vars_t *vars)
{
    h2o_fastcgi_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->config = *vars;
    if (vars->document_root.base != NULL)
        handler->config.document_root = h2o_strdup(NULL, vars->document_root.base, vars->document_root.len);

    return handler;
}

h2o_fastcgi_handler_t *h2o_fastcgi_register_by_hostport(h2o_pathconf_t *pathconf, const char *host, uint16_t port,
                                                        h2o_fastcgi_config_vars_t *vars)
{
    h2o_fastcgi_handler_t *handler = register_common(pathconf, vars);

    h2o_socketpool_init_by_hostport(&handler->sockpool, h2o_iovec_init(host, strlen(host)), port, SIZE_MAX /* FIXME */);
    return handler;
}

h2o_fastcgi_handler_t *h2o_fastcgi_register_by_address(h2o_pathconf_t *pathconf, struct sockaddr *sa, socklen_t salen,
                                                       h2o_fastcgi_config_vars_t *vars)
{
    h2o_fastcgi_handler_t *handler = register_common(pathconf, vars);

    h2o_socketpool_init_by_address(&handler->sockpool, sa, salen, SIZE_MAX /* FIXME */);
    return handler;
}
