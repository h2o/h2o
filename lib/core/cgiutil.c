/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <string.h>
#include "picohttpparser.h"
#include "h2o.h"

static int _isdigit(int ch)
{
    return '0' <= ch && ch <= '9';
}

static void append_address_info(h2o_req_t *req, const char *addrlabel, size_t addrlabel_len, const char *portlabel,
                                size_t portlabel_len, socklen_t (*cb)(h2o_conn_t *conn, struct sockaddr *),
                                void *(append_cb)(h2o_req_t *, const char *, size_t, int, size_t, void *), void *append_arg)
{
    struct sockaddr_storage ss;
    socklen_t sslen;
    char buf[NI_MAXHOST], *dst;

    if ((sslen = cb(req->conn, (void *)&ss)) == 0)
        return;

    size_t l = h2o_socket_getnumerichost((void *)&ss, sslen, buf);
    if (l != SIZE_MAX) {
        dst = append_cb(req, addrlabel, addrlabel_len, 0, l, append_arg);
        memcpy(dst, buf, l);
    }
    int32_t port = h2o_socket_getport((void *)&ss);
    if (port != -1) {
        char buf[6];
        int l = sprintf(buf, "%" PRIu16, (uint16_t)port);
        dst = append_cb(req, portlabel, portlabel_len, 0, (size_t)l, append_arg);
        memcpy(dst, buf, l);
    }
}

void h2o_cgiutil_build_request(h2o_req_t *req, h2o_iovec_t document_root, int send_delegated_uri,
                               void *(*append_cb)(h2o_req_t *req, const char *name, size_t name_len, int is_http_header,
                                                  size_t value_len, void *append_arg), void *append_arg)
{
    h2o_iovec_t path_info = {};
    char *dst;

    /* CONTENT_LENGTH */
    if (req->entity.base != NULL) {
        char buf[32];
        int l = sprintf(buf, "%zu", req->entity.len);
        dst = append_cb(req, H2O_STRLIT("CONTENT_LENGTH"), 0, (size_t)l, append_arg);
        memcpy(dst, buf, l);
    }
    /* SCRIPT_FILENAME, SCRIPT_NAME, PATH_INFO */
    if (req->filereq != NULL) {
        h2o_filereq_t *filereq = req->filereq;
        dst = append_cb(req, H2O_STRLIT("SCRIPT_FILENAME"), 0, filereq->local_path.len, append_arg);
        memcpy(dst, filereq->local_path.base, filereq->local_path.len);
        dst = append_cb(req, H2O_STRLIT("SCRIPT_NAME"), 0, filereq->url_path_len, append_arg);
        memcpy(dst, req->path_normalized.base, filereq->url_path_len);
        if (req->path_normalized.len != filereq->url_path_len)
            path_info =
                h2o_iovec_init(req->path_normalized.base + filereq->url_path_len, req->path_normalized.len - filereq->url_path_len);
    } else {
        (void)append_cb(req, H2O_STRLIT("SCRIPT_NAME"), 0, 0, append_arg);
        path_info = req->path_normalized;
    }
    if (path_info.base != NULL) {
        dst = append_cb(req, H2O_STRLIT("PATH_INFO"), 0, path_info.len, append_arg);
        memcpy(dst, path_info.base, path_info.len);
    }
    /* DOCUMENT_ROOT and PATH_TRANSLATED */
    if (document_root.base != NULL) {
        dst = append_cb(req, H2O_STRLIT("DOCUMENT_ROOT"), 0, document_root.len, append_arg);
        memcpy(dst, document_root.base, document_root.len);
        if (path_info.base != NULL) {
            dst = append_cb(req, H2O_STRLIT("PATH_TRANSLATED"), 0, document_root.len + path_info.len, append_arg);
            memcpy(dst, document_root.base, document_root.len);
            memcpy(dst + document_root.len, path_info.base, path_info.len);
        }
    }
    /* QUERY_STRING (and adjust PATH_INFO) */
    if (req->query_at != SIZE_MAX) {
        size_t len = req->path.len - (req->query_at + 1);
        dst = append_cb(req, H2O_STRLIT("QUERY_STRING"), 0, len, append_arg);
        memcpy(dst, req->path.base + req->query_at + 1, len);
    } else {
        append_cb(req, H2O_STRLIT("QUERY_STRING"), 0, 0, append_arg);
    }
    /* REMOTE_ADDR & REMOTE_PORT */
    append_address_info(req, H2O_STRLIT("REMOTE_ADDR"), H2O_STRLIT("REMOTE_PORT"), req->conn->callbacks->get_peername, append_cb,
                        append_arg);
    /* REQUEST_METHOD */
    dst = append_cb(req, H2O_STRLIT("REQUEST_METHOD"), 0, req->method.len, append_arg);
    memcpy(dst, req->method.base, req->method.len);
    /* HTTP_HOST & REQUEST_URI */
    if (send_delegated_uri) {
        dst = append_cb(req, H2O_STRLIT("HTTP_HOST"), 0, req->authority.len, append_arg);
        memcpy(dst, req->authority.base, req->authority.len);
        dst = append_cb(req, H2O_STRLIT("REQUEST_URI"), 0, req->path.len, append_arg);
        memcpy(dst, req->path.base, req->path.len);
    } else {
        dst = append_cb(req, H2O_STRLIT("HTTP_HOST"), 0, req->input.authority.len, append_arg);
        memcpy(dst, req->input.authority.base, req->input.authority.len);
        dst = append_cb(req, H2O_STRLIT("REQUEST_URI"), 0, req->input.path.len, append_arg);
        memcpy(dst, req->input.path.base, req->input.path.len);
    }
    /* SERVER_ADDR & SERVER_PORT */
    append_address_info(req, H2O_STRLIT("SERVER_ADDR"), H2O_STRLIT("SERVER_PORT"), req->conn->callbacks->get_sockname, append_cb,
                        append_arg);
    /* SERVER_NAME */
    dst = append_cb(req, H2O_STRLIT("SERVER_NAME"), 0, req->hostconf->authority.host.len, append_arg);
    memcpy(dst, req->hostconf->authority.host.base, req->hostconf->authority.host.len);
    { /* SERVER_PROTOCOL */
        char buf[sizeof("HTTP/1.1") - 1];
        size_t l = h2o_stringify_protocol_version(buf, req->version);
        dst = append_cb(req, H2O_STRLIT("SERVER_PROTOCOL"), 0, l, append_arg);
        memcpy(dst, buf, l);
    }
    /* SERVER_SOFTWARE */
    dst = append_cb(req, H2O_STRLIT("SERVER_SOFTWARE"), 0, req->conn->ctx->globalconf->server_name.len, append_arg);
    memcpy(dst, req->conn->ctx->globalconf->server_name.base, req->conn->ctx->globalconf->server_name.len);
    /* set HTTPS: on if necessary */
    if (req->scheme == &H2O_URL_SCHEME_HTTPS) {
        dst = append_cb(req, H2O_STRLIT("HTTPS"), 0, 2, append_arg);
        memcpy(dst, "on", 2);
    }
    { /* headers */
        const h2o_header_t *h = req->headers.entries, *h_end = h + req->headers.size;
        size_t cookie_length = 0;
        for (; h != h_end; ++h) {
            if (h->name == &H2O_TOKEN_CONTENT_TYPE->buf) {
                dst = append_cb(req, H2O_STRLIT("CONTENT_TYPE"), 0, h->value.len, append_arg);
                memcpy(dst, h->value.base, h->value.len);
            } else if (h->name == &H2O_TOKEN_COOKIE->buf) {
                /* accumulate the length of the cookie, together with the separator */
                cookie_length += h->value.len + 1;
            } else {
                char *dst = append_cb(req, h->name->base, h->name->len, 1, h->value.len, append_arg);
                memcpy(dst, h->value.base, h->value.len);
            }
        }
        if (cookie_length != 0) {
            /* emit the cookie merged */
            cookie_length -= 1;
            dst = append_cb(req, H2O_STRLIT("HTTP_COOKIE"), 0, cookie_length, append_arg);
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
    }
}

const char *h2o_cgiutil_build_response(h2o_req_t *req, struct phr_header *headers, size_t num_headers)
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
            if (token == H2O_TOKEN_CONTENT_LENGTH) {
                if (req->res.content_length != SIZE_MAX)
                    return "received multiple content-length headers";
                if ((req->res.content_length = h2o_strtosize(headers[i].value, headers[i].value_len)) == SIZE_MAX)
                    return "failed to parse content-length header";
            } else {
                /*
                RFC 3875 defines three headers to have special meaning: Content-Type, Status, Location.
                Status is handled as below.
                Content-Type does not seem to have any need to be handled specially.
                RFC suggests abs-path-style Location headers should trigger an internal redirection, but is that how the web servers
                work?
                 */
                h2o_add_header(&req->pool, &req->res.headers, token,
                               h2o_strdup(&req->pool, headers[i].value, headers[i].value_len).base, headers[i].value_len);
                if (token == H2O_TOKEN_LINK)
                    h2o_puth_path_in_link_header(req, headers[i].value, headers[i].value_len);
            }
        } else if (h2o_memis(headers[i].name, headers[i].name_len, H2O_STRLIT("status"))) {
            h2o_iovec_t value = h2o_iovec_init(headers[i].value, headers[i].value_len);
            if (value.len < 3 || !(_isdigit(value.base[0]) && _isdigit(value.base[1]) && _isdigit(value.base[2])) ||
                (value.len >= 4 && value.base[3] != ' '))
                return "failed to parse Status header";
            req->res.status = (value.base[0] - '0') * 100 + (value.base[1] - '0') * 10 + (value.base[2] - '0');
            req->res.reason = value.len >= 5 ? h2o_strdup(&req->pool, value.base + 4, value.len - 4).base : "OK";
        } else {
            h2o_iovec_t name_duped = h2o_strdup(&req->pool, headers[i].name, headers[i].name_len),
                        value_duped = h2o_strdup(&req->pool, headers[i].value, headers[i].value_len);
            h2o_add_header_by_str(&req->pool, &req->res.headers, name_duped.base, name_duped.len, 0, value_duped.base,
                                  value_duped.len);
        }
    }

    return NULL;
}
