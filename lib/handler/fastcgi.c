/*
 * Copyright (c) 2015-2016 DeNA Co., Ltd. Kazuho Oku
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

struct st_fcgi_generator_t {
    h2o_generator_t super;
    h2o_fastcgi_handler_t *handler;
    h2o_req_t *req;
    h2o_socketpool_connect_request_t *connect_req;
    h2o_socket_t *sock;
    int sent_headers;
    size_t leftsize; /* remaining amount of the content to receive (or SIZE_MAX if unknown) */
    struct {
        h2o_doublebuffer_t sending;
        h2o_buffer_t *receiving;
    } resp;
    h2o_timer_t timeout;
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
    h2o_iovec_t rec = h2o_iovec_init(h2o_mem_alloc_pool(pool, char, FCGI_RECORD_HEADER_SIZE + FCGI_BEGIN_REQUEST_BODY_SIZE),
                                     FCGI_RECORD_HEADER_SIZE + FCGI_BEGIN_REQUEST_BODY_SIZE);
    encode_begin_request(rec.base, reqId, role, flags);
    return rec;
}

static h2o_iovec_t create_header(h2o_mem_pool_t *pool, uint8_t type, uint16_t reqId, uint16_t sz)
{
    h2o_iovec_t rec = h2o_iovec_init(h2o_mem_alloc_pool(pool, char, FCGI_RECORD_HEADER_SIZE), FCGI_RECORD_HEADER_SIZE);
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
        h2o_vector_reserve(pool, blocks, blocks->size + 1);
        slot = blocks->entries + blocks->size++;
        slot->base = h2o_mem_alloc_pool(pool, char, len < APPEND_BLOCKSIZE ? APPEND_BLOCKSIZE : len);
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

static void append_address_info(h2o_req_t *req, iovec_vector_t *vecs, const char *addrlabel, size_t addrlabel_len,
                                const char *portlabel, size_t portlabel_len, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *))
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    char buf[NI_MAXHOST];

    if ((sslen = cb(req->conn, (void *)&ss)) == 0)
        return;

    size_t l = h2o_socket_getnumerichost((void *)&ss, sslen, buf);
    if (l != SIZE_MAX)
        append_pair(&req->pool, vecs, addrlabel, addrlabel_len, buf, l);
    int32_t port = h2o_socket_getport((void *)&ss);
    if (port != -1) {
        char buf[6];
        int l = sprintf(buf, "%" PRIu16, (uint16_t)port);
        append_pair(&req->pool, vecs, portlabel, portlabel_len, buf, (size_t)l);
    }
}

static int envname_is_headername(const h2o_iovec_t *env, const h2o_iovec_t *header)
{
    const char *ep, *hp, *hend;

    if (env->len != 5 + header->len)
        return 0;
    if (memcmp(env->base, "HTTP_", 5) != 0)
        return 0;
    for (ep = env->base + 5, hp = header->base, hend = hp + header->len; hp < hend; ++ep, ++hp)
        if (*ep != h2o_toupper(*hp))
            return 0;
    return 1;
}

static void append_params(h2o_req_t *req, iovec_vector_t *vecs, h2o_fastcgi_config_vars_t *config)
{
    h2o_iovec_t path_info = {NULL};

    /* CONTENT_LENGTH */
    if (req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", req->entity.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("CONTENT_LENGTH"), buf, (size_t)l);
    }
    /* SCRIPT_FILENAME, SCRIPT_NAME, PATH_INFO */
    if (req->filereq != NULL) {
        h2o_filereq_t *filereq = req->filereq;
        append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_FILENAME"), filereq->local_path.base, filereq->local_path.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_NAME"), filereq->script_name.base, filereq->script_name.len);
        path_info = filereq->path_info;
    } else {
        append_pair(&req->pool, vecs, H2O_STRLIT("SCRIPT_NAME"), NULL, 0);
        path_info = req->path_normalized;
    }
    if (path_info.base != NULL)
        append_pair(&req->pool, vecs, H2O_STRLIT("PATH_INFO"), path_info.base, path_info.len);
    /* DOCUMENT_ROOT and PATH_TRANSLATED */
    if (config->document_root.base != NULL) {
        append_pair(&req->pool, vecs, H2O_STRLIT("DOCUMENT_ROOT"), config->document_root.base, config->document_root.len);
        if (path_info.base != NULL) {
            append_pair(&req->pool, vecs, H2O_STRLIT("PATH_TRANSLATED"), NULL, config->document_root.len + path_info.len);
            char *dst_end = vecs->entries[vecs->size - 1].base + vecs->entries[vecs->size - 1].len;
            memcpy(dst_end - path_info.len, path_info.base, path_info.len);
            memcpy(dst_end - path_info.len - config->document_root.len, config->document_root.base, config->document_root.len);
        }
    }
    /* QUERY_STRING (and adjust PATH_INFO) */
    if (req->query_at != SIZE_MAX) {
        append_pair(&req->pool, vecs, H2O_STRLIT("QUERY_STRING"), req->path.base + req->query_at + 1,
                    req->path.len - (req->query_at + 1));
    } else {
        append_pair(&req->pool, vecs, H2O_STRLIT("QUERY_STRING"), NULL, 0);
    }
    /* REMOTE_ADDR & REMOTE_PORT */
    append_address_info(req, vecs, H2O_STRLIT("REMOTE_ADDR"), H2O_STRLIT("REMOTE_PORT"), req->conn->callbacks->get_peername);
    { /* environment variables (REMOTE_USER, etc.) */
        size_t i;
        for (i = 0; i != req->env.size; i += 2) {
            h2o_iovec_t *name = req->env.entries + i, *value = name + 1;
            append_pair(&req->pool, vecs, name->base, name->len, value->base, value->len);
        }
    }
    /* REQUEST_METHOD */
    append_pair(&req->pool, vecs, H2O_STRLIT("REQUEST_METHOD"), req->method.base, req->method.len);
    /* HTTP_HOST & REQUEST_URI */
    if (config->send_delegated_uri) {
        append_pair(&req->pool, vecs, H2O_STRLIT("HTTP_HOST"), req->authority.base, req->authority.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("REQUEST_URI"), req->path.base, req->path.len);
    } else {
        append_pair(&req->pool, vecs, H2O_STRLIT("HTTP_HOST"), req->input.authority.base, req->input.authority.len);
        append_pair(&req->pool, vecs, H2O_STRLIT("REQUEST_URI"), req->input.path.base, req->input.path.len);
    }
    /* SERVER_ADDR & SERVER_PORT */
    append_address_info(req, vecs, H2O_STRLIT("SERVER_ADDR"), H2O_STRLIT("SERVER_PORT"), req->conn->callbacks->get_sockname);
    /* SERVER_NAME */
    append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_NAME"), req->hostconf->authority.host.base, req->hostconf->authority.host.len);
    { /* SERVER_PROTOCOL */
        char buf[sizeof("HTTP/1.1")];
        size_t l = h2o_stringify_protocol_version(buf, req->version);
        append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_PROTOCOL"), buf, l);
    }
    /* SERVER_SOFTWARE */
    append_pair(&req->pool, vecs, H2O_STRLIT("SERVER_SOFTWARE"), req->conn->ctx->globalconf->server_name.base,
                req->conn->ctx->globalconf->server_name.len);
    /* set HTTPS: on if necessary */
    if (req->scheme == &H2O_URL_SCHEME_HTTPS)
        append_pair(&req->pool, vecs, H2O_STRLIT("HTTPS"), H2O_STRLIT("on"));
    { /* headers */
        const h2o_header_t *h = req->headers.entries, *h_end = h + req->headers.size;
        size_t cookie_length = 0;
        int found_early_data = 0;
        for (; h != h_end; ++h) {
            if (h->name == &H2O_TOKEN_CONTENT_TYPE->buf) {
                append_pair(&req->pool, vecs, H2O_STRLIT("CONTENT_TYPE"), h->value.base, h->value.len);
            } else if (h->name == &H2O_TOKEN_COOKIE->buf) {
                /* accumulate the length of the cookie, together with the separator */
                cookie_length += h->value.len + 1;
            } else {
                if (h->name == &H2O_TOKEN_EARLY_DATA->buf)
                    found_early_data = 1;
                size_t i;
                for (i = 0; i != req->env.size; i += 2) {
                    h2o_iovec_t *envname = req->env.entries + i;
                    if (envname_is_headername(envname, h->name))
                        goto NextHeader;
                }
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
        NextHeader:;
        }
        if (cookie_length != 0) {
            /* emit the cookie merged */
            cookie_length -= 1;
            append_pair(&req->pool, vecs, H2O_STRLIT("HTTP_COOKIE"), NULL, cookie_length);
            char *dst = vecs->entries[vecs->size - 1].base + vecs->entries[vecs->size - 1].len - cookie_length;
            for (h = req->headers.entries;; ++h) {
                if (h->name == &H2O_TOKEN_COOKIE->buf) {
                    if (cookie_length == h->value.len)
                        break;
                    memcpy(dst, h->value.base, h->value.len);
                    dst += h->value.len;
                    *dst++ = ';';
                    cookie_length -= h->value.len + 1;
                }
            }
            memcpy(dst, h->value.base, h->value.len);
        }
        if (!found_early_data && h2o_conn_is_early_data(req->conn)) {
            append_pair(&req->pool, vecs, H2O_STRLIT("HTTP_EARLY_DATA"), H2O_STRLIT("1"));
            req->reprocess_if_too_early = 1;
        }
    }
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
                h2o_vector_reserve(pool, vecs, vecs->size + 1);
                memmove(vecs->entries + index + 2, vecs->entries + index + 1,
                        (vecs->size - (index + 1)) * sizeof(vecs->entries[0]));
                ++vecs->size;
            } else {
                h2o_vector_reserve(pool, vecs, vecs->size + 2);
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
        h2o_vector_reserve(pool, vecs, vecs->size + 1);
        vecs->entries[vecs->size++] = create_header(pool, FCGI_PARAMS, request_id, 0);
    }
}

static void build_request(h2o_req_t *req, iovec_vector_t *vecs, unsigned request_id, size_t max_record_size,
                          h2o_fastcgi_config_vars_t *config)
{
    *vecs = (iovec_vector_t){NULL};

    /* first entry is FCGI_BEGIN_REQUEST */
    h2o_vector_reserve(&req->pool, vecs, 5 /* we send at least 5 iovecs */);
    vecs->entries[0] =
        create_begin_request(&req->pool, request_id, FCGI_RESPONDER, config->keepalive_timeout != 0 ? FCGI_KEEP_CONN : 0);
    /* second entry is reserved for FCGI_PARAMS header */
    vecs->entries[1] = h2o_iovec_init(NULL, APPEND_BLOCKSIZE); /* dummy value set to prevent params being appended to the entry */
    vecs->size = 2;
    /* accumulate the params data, and annotate them with FCGI_PARAM headers */
    append_params(req, vecs, config);
    annotate_params(&req->pool, vecs, request_id, max_record_size);
    /* setup FCGI_STDIN headers */
    if (req->entity.len != 0) {
        size_t off = 0;
        for (; off + max_record_size < req->entity.len; off += max_record_size) {
            h2o_vector_reserve(&req->pool, vecs, vecs->size + 2);
            vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, max_record_size);
            vecs->entries[vecs->size++] = h2o_iovec_init(req->entity.base + off, max_record_size);
        }
        if (off != req->entity.len) {
            h2o_vector_reserve(&req->pool, vecs, vecs->size + 2);
            vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, req->entity.len - off);
            vecs->entries[vecs->size++] = h2o_iovec_init(req->entity.base + off, req->entity.len - off);
        }
    }
    h2o_vector_reserve(&req->pool, vecs, vecs->size + 1);
    vecs->entries[vecs->size++] = create_header(&req->pool, FCGI_STDIN, request_id, 0);
}

static void set_timeout(struct st_fcgi_generator_t *generator, uint64_t timeout, h2o_timer_cb cb)
{
    if (h2o_timer_is_linked(&generator->timeout))
        h2o_timer_unlink(&generator->timeout);
    generator->timeout.cb = cb;
    h2o_timer_link(generator->req->conn->ctx->loop, timeout, &generator->timeout);
}

static void close_generator(struct st_fcgi_generator_t *generator)
{
    /* can be called more than once */
    if (h2o_timer_is_linked(&generator->timeout))
        h2o_timer_unlink(&generator->timeout);
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
    h2o_send_state_t send_state;

    vecs[0] = h2o_doublebuffer_prepare(&generator->resp.sending, &generator->resp.receiving, generator->req->preferred_chunk_size);
    veccnt = vecs[0].len != 0 ? 1 : 0;
    if (generator->sock == NULL && vecs[0].len == generator->resp.sending.buf->size && generator->resp.receiving->size == 0) {
        if (generator->leftsize == 0 || generator->leftsize == SIZE_MAX) {
            send_state = H2O_SEND_STATE_FINAL;
        } else {
            send_state = H2O_SEND_STATE_ERROR;
        }
    } else {
        if (veccnt == 0)
            return;
        send_state = H2O_SEND_STATE_IN_PROGRESS;
    }
    h2o_send(generator->req, vecs, veccnt, send_state);
}

static void send_eos_and_close(struct st_fcgi_generator_t *generator, int can_keepalive)
{
    if (generator->handler->config.keepalive_timeout != 0 && can_keepalive)
        h2o_socketpool_return(&generator->handler->sockpool, generator->sock);
    else
        h2o_socket_close(generator->sock);
    generator->sock = NULL;
    if (h2o_timer_is_linked(&generator->timeout))
        h2o_timer_unlink(&generator->timeout);
    if (!generator->resp.sending.inflight)
        do_send(generator);
}

static void errorclose(struct st_fcgi_generator_t *generator)
{
    if (generator->sent_headers) {
        send_eos_and_close(generator, 0);
    } else {
        h2o_req_t *req = generator->req;
        close_generator(generator);
        h2o_send_error_503(req, "Internal Server Error", "Internal Server Error", 0);
    }
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
    req->res.content_length = SIZE_MAX;

    for (i = 0; i != num_headers; ++i) {
        const h2o_token_t *token;
        h2o_strtolower((char *)headers[i].name, headers[i].name_len);
        if ((token = h2o_lookup_token(headers[i].name, headers[i].name_len)) != NULL) {
            if (token->flags.proxy_should_drop_for_res) {
                /* skip */
            } else if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (req->res.content_length != SIZE_MAX) {
                    h2o_req_log_error(req, MODULE_NAME, "received multiple content-length headers from fcgi");
                    return -1;
                }
                if ((req->res.content_length = h2o_strtosize(headers[i].value, headers[i].value_len)) == SIZE_MAX) {
                    h2o_req_log_error(req, MODULE_NAME, "failed to parse content-length header sent from fcgi: %.*s",
                                      (int)headers[i].value_len, headers[i].value);
                    return -1;
                }
            } else {
                /*
                RFC 3875 defines three headers to have special meaning: Content-Type, Status, Location.
                Status is handled as below.
                Content-Type does not seem to have any need to be handled specially.
                RFC suggests abs-path-style Location headers should trigger an internal redirection, but is that how the web servers
                work?
                 */
                h2o_add_header(&req->pool, &req->res.headers, token, NULL,
                               h2o_strdup(&req->pool, headers[i].value, headers[i].value_len).base, headers[i].value_len);
                if (token == H2O_TOKEN_LINK)
                    h2o_push_path_in_link_header(req, headers[i].value, headers[i].value_len);
            }
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
            h2o_add_header_by_str(&req->pool, &req->res.headers, name_duped.base, name_duped.len, 0, NULL, value_duped.base,
                                  value_duped.len);
        }
    }

    /* add date: if it's missing from the response */
    if (h2o_find_header(&req->res.headers, H2O_TOKEN_DATE, -1) == -1)
        h2o_resp_add_date_header(req);

    return 0;
}

static int append_content(struct st_fcgi_generator_t *generator, const void *src, size_t len)
{
    /* do not accumulate more than content-length bytes */
    if (generator->leftsize != SIZE_MAX) {
        if (generator->leftsize < len) {
            len = generator->leftsize;
            if (len == 0)
                return 0;
        }
        generator->leftsize -= len;
    }
    h2o_iovec_t reserved = h2o_buffer_try_reserve(&generator->resp.receiving, len);
    if (reserved.base == NULL) {
        return -1;
    }
    memcpy(reserved.base, src, len);
    generator->resp.receiving->size += len;
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
        if (append_content(generator, input->bytes + FCGI_RECORD_HEADER_SIZE, header->contentLength) != 0) {
            h2o_req_log_error(generator->req, MODULE_NAME, "failed to allocate memory");
            return -1;
        }
        return 0;
    }

    /* parse the headers using the input buffer (or keep it in response buffer and parse) */
    num_headers = sizeof(headers) / sizeof(headers[0]);
    if (generator->resp.receiving->size == 0) {
        parse_result = phr_parse_headers(input->bytes + FCGI_RECORD_HEADER_SIZE, header->contentLength, headers, &num_headers, 0);
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
            if (generator->resp.receiving->size == 0) {
                memcpy(h2o_buffer_reserve(&generator->resp.receiving, header->contentLength).base,
                       input->bytes + FCGI_RECORD_HEADER_SIZE, header->contentLength);
                generator->resp.receiving->size = header->contentLength;
            }
            return 0;
        } else {
            h2o_req_log_error(generator->req, MODULE_NAME, "received broken response");
            return -1;
        }
    }

    /* fill-in the headers, and start the response */
    if (fill_headers(generator->req, headers, num_headers) != 0)
        return -1;
    generator->leftsize = generator->req->res.content_length;
    h2o_start_response(generator->req, &generator->super);
    generator->sent_headers = 1;

    /* rest of the contents should be stored in the response buffer */
    if (generator->resp.receiving->size == 0) {
        size_t leftlen = header->contentLength - parse_result;
        if (leftlen != 0) {
            if (append_content(generator, input->bytes + FCGI_RECORD_HEADER_SIZE + parse_result, leftlen) != 0) {
                h2o_req_log_error(generator->req, MODULE_NAME, "failed to allocate memory");
                return -1;
            }
        }
    } else {
        h2o_buffer_consume(&generator->resp.receiving, parse_result);
    }

    return 0;
}

static void on_rw_timeout(h2o_timer_t *entry)
{
    struct st_fcgi_generator_t *generator = H2O_STRUCT_FROM_MEMBER(struct st_fcgi_generator_t, timeout, entry);

    h2o_req_log_error(generator->req, MODULE_NAME, "I/O timeout");
    errorclose(generator);
}

static void on_read(h2o_socket_t *sock, const char *err)
{
    struct st_fcgi_generator_t *generator = sock->data;
    int can_keepalive = 0;
    int sent_headers_before = generator->sent_headers;

    if (err != NULL) {
        /* note: FastCGI server is allowed to close the connection any time after sending an empty FCGI_STDOUT record */
        if (!generator->sent_headers)
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
    if (generator->sent_headers) {
        if (!sent_headers_before && generator->resp.receiving->size == 0) {
            /* send headers immediately */
            h2o_doublebuffer_prepare_empty(&generator->resp.sending);
            h2o_send(generator->req, NULL, 0, H2O_SEND_STATE_IN_PROGRESS);
        } else if (!generator->resp.sending.inflight) {
            do_send(generator);
        }
    }

    set_timeout(generator, generator->handler->config.io_timeout, on_rw_timeout);
    return;

EOS_Received:
    send_eos_and_close(generator, can_keepalive);
    return;

Error:
    errorclose(generator);
}

static void on_send_complete(h2o_socket_t *sock, const char *err)
{
    struct st_fcgi_generator_t *generator = sock->data;

    set_timeout(generator, generator->handler->config.io_timeout, on_rw_timeout);
    /* do nothing else!  all the rest is handled by the on_read */
}

static void on_connect(h2o_socket_t *sock, const char *errstr, void *data, h2o_url_t *_dummy)
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

    build_request(generator->req, &vecs, 1, 65535, &generator->handler->config);

    /* start sending the response */
    h2o_socket_write(generator->sock, vecs.entries, vecs.size, on_send_complete);

    set_timeout(generator, generator->handler->config.io_timeout, on_rw_timeout);

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

static void on_connect_timeout(h2o_timer_t *entry)
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
    generator->handler = handler;
    generator->req = req;
    generator->sock = NULL;
    generator->sent_headers = 0;
    h2o_doublebuffer_init(&generator->resp.sending, &h2o_socket_buffer_prototype);
    h2o_buffer_init(&generator->resp.receiving, &h2o_socket_buffer_prototype);
    h2o_timer_init(&generator->timeout, on_connect_timeout);
    h2o_timer_link(req->conn->ctx->loop, generator->handler->config.io_timeout, &generator->timeout);

    h2o_socketpool_connect(&generator->connect_req, &handler->sockpool, &handler->sockpool.targets.entries[0]->url,
                           req->conn->ctx->loop, &req->conn->ctx->receivers.hostinfo_getaddr, h2o_iovec_init(NULL, 0), on_connect,
                           generator);

    return 0;
}

static void on_context_init(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;
    h2o_socketpool_register_loop(&handler->sockpool, ctx->loop);
}

static void on_context_dispose(h2o_handler_t *_handler, h2o_context_t *ctx)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;
    h2o_socketpool_unregister_loop(&handler->sockpool, ctx->loop);
}

static void on_handler_dispose(h2o_handler_t *_handler)
{
    h2o_fastcgi_handler_t *handler = (void *)_handler;

    if (handler->config.callbacks.dispose != NULL)
        handler->config.callbacks.dispose(handler, handler->config.callbacks.data);

    h2o_socketpool_dispose(&handler->sockpool);
    free(handler->config.document_root.base);
}

h2o_fastcgi_handler_t *h2o_fastcgi_register(h2o_pathconf_t *pathconf, h2o_url_t *upstream, h2o_fastcgi_config_vars_t *vars)
{
    h2o_fastcgi_handler_t *handler = (void *)h2o_create_handler(pathconf, sizeof(*handler));

    handler->super.on_context_init = on_context_init;
    handler->super.on_context_dispose = on_context_dispose;
    handler->super.dispose = on_handler_dispose;
    handler->super.on_req = on_req;
    handler->config = *vars;
    if (vars->document_root.base != NULL)
        handler->config.document_root = h2o_strdup(NULL, vars->document_root.base, vars->document_root.len);

    h2o_socketpool_target_t *target = h2o_socketpool_create_target(upstream, NULL);
    h2o_socketpool_target_t **targets = &target;
    h2o_socketpool_init_specific(&handler->sockpool, SIZE_MAX /* FIXME */, targets, 1, NULL);
    h2o_socketpool_set_timeout(&handler->sockpool, handler->config.keepalive_timeout);
    return handler;
}
