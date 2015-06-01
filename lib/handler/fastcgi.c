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

struct st_fcgi_generator_t {
    h2o_generator_t super;
    h2o_req_t *req;
    h2o_socket_t *sock;
    int sent_headers;
    struct {
        h2o_buffer_t *inflight;
        h2o_buffer_t *receiving;
    } resp;
};

struct st_h2o_fastcgi_handler_t {
    h2o_handler_t super;
    union {
        struct sockaddr sa;
        struct sockaddr_storage sa_storage;
    };
    socklen_t salen;
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

static void *append(h2o_mem_pool_t *pool, iovec_vector_t *blocks, const void *s, size_t len)
{
    h2o_iovec_t *slot;

    if (blocks->entries[blocks->size - 1].len + len > APPEND_BLOCKSIZE) {
        h2o_vector_reserve(pool, (void *)&blocks, sizeof(blocks->entries[0]), blocks->size + 1);
        slot = blocks->entries + blocks->size++;
        slot->base = h2o_mem_alloc_pool(pool, len < APPEND_BLOCKSIZE ? APPEND_BLOCKSIZE : len);
        slot->len = 0;
    } else {
        slot = blocks->entries + blocks->size - 1;
    }

    if (s != NULL)
        memcpy(slot->base + slot->len, s, len);
    slot->len += len;

    return slot->base + slot->len - len;
}

static char *encode_length_of_pair(char *p, size_t len)
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

static void *append_pair(h2o_mem_pool_t *pool, iovec_vector_t *blocks, const char *name, size_t namelen, const char *value,
                         size_t valuelen)
{
    char lenbuf[8];
    void *name_buf;

    append(pool, blocks, lenbuf, encode_length_of_pair(encode_length_of_pair(lenbuf, namelen), valuelen) - lenbuf);
    name_buf = append(pool, blocks, name, namelen);
    if (valuelen != 0)
        append(pool, blocks, value, valuelen);

    return name_buf;
}

static void append_params(h2o_req_t *req, iovec_vector_t *vecs)
{
    /* CONTENT_LENGTH */
    if (req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", req->entity.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("CONTENT_LENGTH"), buf, (size_t)l);
    }
    /* TODO: PATH_INFO & PATH_TRANSLATED */
    /* QUERY_STRING */
    if (req->query_at != SIZE_MAX) {
        append_pair(&req->pool, vecs, H2O_STRLIT("QUERY_STRING"), req->path.base + req->query_at + 1,
                    req->path.len - (req->query_at + 1));
    } else {
        append_pair(&req->pool, vecs, H2O_STRLIT("QUERY_SRTING"), NULL, 0);
    }
    { /* REMOTE_ADDR */
        char buf[NI_MAXHOST];
        size_t l = h2o_socket_getnumerichost(req->conn->peername.addr, req->conn->peername.len, buf);
        if (l != SIZE_MAX)
            append_pair(&req->pool, vecs, H2O_STRLIT("REMOTE_ADDR"), buf, l);
    }
    { /* REMOTE_PORT */
        int32_t port = h2o_socket_getport(req->conn->peername.addr);
        if (port != -1) {
            char buf[6];
            int l = sprintf(buf, "%" PRIu16, (uint16_t)port);
            append_pair(&req->pool, vecs, H2O_STRLIT("REMOTE_PORT"), buf, (size_t)l);
        }
    }
    /* REQUEST_METHOD */
    append_pair(&req->pool, vecs, H2O_STRLIT("REQUEST_METHOD"), req->method.base, req->method.len);
    /* REQUEST_URI */
    append_pair(&req->pool, vecs, H2O_STRLIT("REQUEST_URI"), req->path.base, req->path.len);
    /* SERVER_NAME */
    append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_NAME"), req->pathconf->host->authority.host.base,
                req->pathconf->host->authority.host.len);
    { /* SERVER_PORT */
        char buf[6];
        int l = sprintf(buf, "%" PRIu16, req->pathconf->host->authority.port);
        append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_PORT"), buf, (size_t)l);
    }
    { /* SERVER_PROTOCOL */
        char buf[sizeof("HTTP/1.1") - 1];
        size_t l = h2o_stringify_protocol_version(buf, req->version);
        append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_PROTOCOL"), buf, l);
    }
    /* SERVER_SOFTWARE */
    append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_SOFTWARE"), req->conn->ctx->globalconf->server_name.base,
                req->conn->ctx->globalconf->server_name.len);
    /* SCRIPT_FILENAME */
    append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_NAME"), req->path_normalized.base, req->path_normalized.len);
    { /* headers */
        const h2o_header_t *h = req->headers.entries, *h_end = h + req->headers.size;
        for (; h != h_end; ++h) {
            if (h->name == &H2O_TOKEN_CONTENT_TYPE->buf) {
                append_pair(&req->pool, vecs, H2O_STRLIT("CONTENT_TYPE"), h->value.base, h->value.len);
            } else {
                char *dst = append_pair(&req->pool, vecs, NULL, h->name->len + sizeof("HTTP_") - 1, h->value.base, h->value.len);
                const char *src = h->name->base, *src_end = src + h->name->len;
                *dst++ = 'H';
                *dst++ = 'T';
                *dst++ = 'T';
                *dst++ = 'P';
                *dst++ = '_';
                for (; src != src_end; ++src)
                    *dst++ = *src == '-' ? '_' : h2o_toupper(*src);
            }
        }
    }
}

static void close_generator(struct st_fcgi_generator_t *generator)
{
    /* can be called more than once */

    if (generator->sock != NULL) {
        h2o_socket_close(generator->sock);
        generator->sock = NULL;
    }
    if (generator->resp.inflight != NULL)
        h2o_buffer_dispose(&generator->resp.inflight);
    if (generator->resp.receiving != NULL)
        h2o_buffer_dispose(&generator->resp.receiving);
}

static void send_error_and_close(struct st_fcgi_generator_t *generator)
{
    h2o_req_t *req = generator->req;

    assert(!generator->sent_headers);
    close_generator(generator);
    h2o_send_error(req, 503, "Internal Server Error", "Internal Server Error", 0);
}

static void do_send(struct st_fcgi_generator_t *generator)
{
    h2o_iovec_t vec;

    assert(generator->resp.inflight->size == 0);

    /* just return if nothing to send */
    if (generator->sock != NULL && generator->sock->input->size == 0)
        return;

    { /* swap the buffers */
        h2o_buffer_t *t = generator->resp.inflight;
        generator->resp.inflight = generator->resp.receiving;
        generator->resp.receiving = t;
    }

    /* send */
    vec = h2o_iovec_init(generator->resp.inflight->bytes, generator->resp.inflight->size);
    h2o_send(generator->req, &vec, 1, generator->sock == NULL);
}

static void send_eos_and_close(struct st_fcgi_generator_t *generator)
{
    h2o_socket_close(generator->sock);
    generator->sock = NULL;

    if (generator->resp.inflight->size == 0)
        do_send(generator);
}

static int _isdigit(int ch)
{
    return '0' <= ch && ch <= '9';
}

static int fill_headers(h2o_req_t *req, struct phr_header *headers, size_t num_headers)
{
    size_t i;

    /* set the defaults */
    req->res.status = 200;
    req->res.reason = "OK";

    for (i = 0; i != num_headers; ++i) {
        const h2o_token_t *token;
        h2o_strtolower((char *)headers[i].name, headers[i].name_len);
        if ((token = h2o_lookup_token(headers[i].name, headers[i].name_len)) != NULL) {
            /*
                RFC 3875 defines three headers to have special meaning: Content-Type, Status, Location.
                Status is handled as below.
                Content-Type does not seem to have any need to be handled specially.
                RFC suggests abs-path-style Location headers should trigger an internal redirection, but is that how the web serers
                work?
             */
            h2o_add_header_token(&req->pool, &req->res.headers, token,
                                 h2o_strdup(&req->pool, headers[i].value, headers[i].value_len).base, headers[i].value_len);
        } else if (h2o_memis(headers[i].name, headers[i].name_len, H2O_STRLIT("status"))) {
            h2o_iovec_t value = h2o_iovec_init(headers[i].value, headers[i].value_len);
            if (value.len < 3 || !(_isdigit(value.base[0]) && _isdigit(value.base[1]) && _isdigit(value.base[2])) ||
                (value.len >= 4 && value.base[3] != ' ')) {
                h2o_req_log_error(req, MODULE_NAME, "failed to parse Status header, got: %.*s", (int)value.len, value.base);
                return -1;
            }
            req->res.status = (value.base[0] - '0') * 100 + (value.base[1] - '0') * 10 + (value.base[2] - '0');
            req->res.reason = value.len >= 5 ? h2o_strdup(&req->pool, value.base + 4, value.len - 4).base : "OK";
        } else {
            h2o_iovec_t name_duped = h2o_strdup(&req->pool, headers[i].name, headers[i].name_len),
                        value_duped = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
            h2o_add_header_by_str(&req->pool, &req->res.headers, name_duped.base, name_duped.len, 0, value_duped.base,
                                  value_duped.len);
        }
    }

    return 0;
}

static int handle_stdin_record(struct st_fcgi_generator_t *generator, struct st_fcgi_record_header_t *header)
{
    h2o_buffer_t *input = generator->sock->input;
    struct phr_header headers[100];
    size_t num_headers;
    int parse_result;

    if (header->contentLength == 0)
        return 0;

    if (generator->sent_headers) {
        /* simply accumulate the data to response buffer */
        memcpy(h2o_buffer_reserve(&generator->resp.receiving, header->contentLength).base, input->bytes + FCGI_RECORD_HEADER_SIZE,
               header->contentLength);
        return 0;
    }

    /* parse the headers using the input buffer (or keep it in response buffer and parse) */
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
    if (fill_headers(generator->req, headers, num_headers) != 0)
        return -1;
    h2o_start_response(generator->req, &generator->super);
    generator->sent_headers = 1;

    /* rest of the contents should be stored in the response buffer */
    if (generator->resp.receiving->size == 0) {
        size_t leftlen = header->contentLength - parse_result;
        if (leftlen != 0) {
            memcpy(h2o_buffer_reserve(&generator->resp.receiving, leftlen).base,
                   input->bytes + FCGI_RECORD_HEADER_SIZE + parse_result, leftlen);
            generator->resp.receiving->size = leftlen;
        }
    } else {
        h2o_buffer_consume(&generator->resp.receiving, parse_result);
    }

    return 0;
}

static void on_read(h2o_socket_t *sock, int status)
{
    struct st_fcgi_generator_t *generator = sock->data;

    if (status != 0) {
        h2o_req_log_error(generator->req, MODULE_NAME, "fastcgi connection closed unexpectedly");
        if (generator->sent_headers)
            send_eos_and_close(generator);
        else
            send_error_and_close(generator);
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
            break;
        case FCGI_STDERR:
            if (header.contentLength != 0)
                write(2, sock->input->bytes + FCGI_RECORD_HEADER_SIZE, header.contentLength);
            break;
        case FCGI_END_REQUEST:
            if (!generator->sent_headers) {
                h2o_req_log_error(generator->req, MODULE_NAME, "received FCGI_END_REQUEST before end of the headers");
                goto Error;
            }
            goto EOS_Received;
        default:
            h2o_req_log_error(generator->req, MODULE_NAME, "received unexpected record, type: %u", header.type);
            if (!generator->sent_headers)
                goto Error;
            goto EOS_Received;
        }
        h2o_buffer_consume(&sock->input, recsize);
    }

    /* send data if necessary */
    if (generator->sent_headers && generator->resp.inflight->size == 0)
        do_send(generator);
    return;

EOS_Received:
    send_eos_and_close(generator);
    return;

Error:
    if (generator->sent_headers) {
        send_eos_and_close(generator);
    } else {
        send_error_and_close(generator);
    }
}

static void on_send_complete(h2o_socket_t *sock, int status)
{
    /* do nothing!  all the rest is handled by the on_read */
}

static void on_connect(h2o_socket_t *sock, int status)
{
#define REQUEST_ID 1

    struct st_fcgi_generator_t *generator = sock->data;
    h2o_req_t *req = generator->req;
    iovec_vector_t vecs = {};

    if (status != 0) {
        generator->sock = NULL;
        send_error_and_close(generator);
        return;
    }

    /* build the fcgi records */

    /* first entry is FCGI_BEGIN_REQUEST */
    h2o_vector_reserve(&req->pool, (void *)&vecs, sizeof(vecs.entries[0]), 5 /* we send at least 5 iovecs */);
    vecs.entries[0] = create_begin_request(&req->pool, REQUEST_ID, FCGI_RESPONDER, 0);
    /* second entry is reserved for FCGI_PARAMS header */
    vecs.entries[1] = h2o_iovec_init(NULL, APPEND_BLOCKSIZE); /* dummy value set to prevent params being appended to the entry */
    vecs.size = 2;
    /* accumulate the params data */
    append_params(req, &vecs);
    { /* setup the FCGI_PARAMS headers */
        size_t i, recsize = 0, header_slot = 1;
        for (i = 2; i != vecs.size; ++i) {
            if (recsize + vecs.entries[i].len > 65535) {
                /* write the header, expand, and update header_slot */
                vecs.entries[header_slot] = create_header(&req->pool, FCGI_PARAMS, REQUEST_ID, recsize);
                h2o_vector_reserve(&req->pool, (void *)&vecs, sizeof(vecs.entries[0]), vecs.size + 1);
                memmove(vecs.entries + i + 1, vecs.entries + i, vecs.size - i);
                ++vecs.size;
                recsize = 0;
                header_slot = i;
            } else {
                recsize += vecs.entries[i].len;
            }
        }
        vecs.entries[header_slot] = create_header(&req->pool, FCGI_PARAMS, REQUEST_ID, recsize);
        if (recsize != 0) {
            h2o_vector_reserve(&req->pool, (void *)&vecs, sizeof(vecs.entries[0]), vecs.size + 1);
            vecs.entries[vecs.size++] = create_header(&req->pool, FCGI_PARAMS, REQUEST_ID, 0);
        }
    }
    /* setup FCGI_STDIN headers */
    if (req->entity.len != 0) {
#define CHUNKSIZE 0xffc0 /* an aligned number below 0xffff */
        size_t off = 0;
        for (; off + CHUNKSIZE < req->entity.len; off += CHUNKSIZE) {
            h2o_vector_reserve(&req->pool, (void *)&vecs, sizeof(vecs.entries[0]), vecs.size + 2);
            vecs.entries[vecs.size++] = create_header(&req->pool, FCGI_STDIN, REQUEST_ID, CHUNKSIZE);
            vecs.entries[vecs.size++] = h2o_iovec_init(req->entity.base + off, CHUNKSIZE);
        }
        if (off != req->entity.len) {
            h2o_vector_reserve(&req->pool, (void *)&vecs, sizeof(vecs.entries[0]), vecs.size + 2);
            vecs.entries[vecs.size++] = create_header(&req->pool, FCGI_STDIN, REQUEST_ID, req->entity.len - off);
            vecs.entries[vecs.size++] = h2o_iovec_init(req->entity.base + off, req->entity.len - off);
        }
#undef CHUNKSIZE
    }
    h2o_vector_reserve(&req->pool, (void *)&vecs, sizeof(vecs.entries[0]), vecs.size + 1);
    vecs.entries[vecs.size++] = create_header(&req->pool, FCGI_STDIN, REQUEST_ID, 0);

    /* start sending the response */
    h2o_socket_write(generator->sock, vecs.entries, vecs.size, on_send_complete);

    /* activate the receiver; note: FCGI spec allows the app to start sending the response before it receives FCGI_STDIN */
    h2o_socket_read_start(sock, on_read);

#undef REQUEST_ID
}

static void do_proceed(h2o_generator_t *_generator, h2o_req_t *req)
{
    struct st_fcgi_generator_t *generator = (void *)_generator;

    h2o_buffer_consume(&generator->resp.inflight, generator->resp.inflight->size);
    do_send(generator);
}

static void do_stop(h2o_generator_t *_generator, h2o_req_t *req)
{
    struct st_fcgi_generator_t *generator = (void *)_generator;
    close_generator(generator);
}

static int on_req(h2o_handler_t *_handler, h2o_req_t *req)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;
    h2o_socket_t *sock;
    struct st_fcgi_generator_t *generator;

    if ((sock = h2o_socket_connect(req->conn->ctx->loop, &handler->sa, handler->salen, on_connect)) == NULL) {
        h2o_req_log_error(req, MODULE_NAME, "failed to connect to upstream");
        h2o_send_error(req, 503, "Internal Server Error", "Internal Server Error", 0);
        return 0;
    }

    generator = h2o_mem_alloc_shared(&req->pool, sizeof(*generator), (void (*)(void *))close_generator);
    generator->super.proceed = do_proceed;
    generator->super.stop = do_stop;
    generator->req = req;
    generator->sock = sock;
    generator->sock->data = generator;
    generator->sent_headers = 0;
    h2o_buffer_init(&generator->resp.inflight, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&generator->resp.receiving, &h2o_socket_buffer_prototype);

    return 0;
}

h2o_fastcgi_handler_t *h2o_fastcgi_register(h2o_pathconf_t *pathconf, struct sockaddr *sa, socklen_t salen)
{
    h2o_fastcgi_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    assert(salen <= sizeof(handler->sa_storage));
    memcpy(&handler->sa_storage, sa, salen);
    handler->salen = salen;

    handler->super.on_req = on_req;

    return handler;
}
