/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Fastly, Inc.
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
#ifndef h2o__probes_h
#define h2o__probes_h

/* This file is placed under lib, and must only be included from the source files of the h2o / libh2o, because H2O_USE_DTRACE is a
 * symbol available only during the build phase of h2o.  That's fine, because only h2o / libh2o has the sole right to define probes
 * belonging to the h2o namespace.
 */
#if H2O_USE_DTRACE

#include "picotls.h"
#include "h2o-probes.h"

#define H2O_CONN_IS_PROBED(label, conn) (PTLS_UNLIKELY(H2O_##label##_ENABLED()) && !conn->callbacks->skip_tracing(conn))

#define H2O_PROBE_CONN0(label, conn)                                                                                               \
    do {                                                                                                                           \
        h2o_conn_t *_conn = (conn);                                                                                                \
        if (H2O_CONN_IS_PROBED(label, _conn)) {                                                                                    \
            H2O_##label(_conn->id);                                                                                                \
        }                                                                                                                          \
    } while (0)

#define H2O_PROBE_CONN(label, conn, ...)                                                                                           \
    do {                                                                                                                           \
        h2o_conn_t *_conn = (conn);                                                                                                \
        if (H2O_CONN_IS_PROBED(label, _conn)) {                                                                                    \
            H2O_##label(_conn->id, __VA_ARGS__);                                                                                   \
        }                                                                                                                          \
    } while (0)

#define H2O_PROBE(label, ...)                                                                                                      \
    do {                                                                                                                           \
        if (PTLS_UNLIKELY(H2O_##label##_ENABLED())) {                                                                              \
            H2O_##label(__VA_ARGS__);                                                                                              \
        }                                                                                                                          \
    } while (0)

#define H2O_PROBE_HEXDUMP(s, l)                                                                                                    \
    ({                                                                                                                             \
        size_t _l = (l);                                                                                                           \
        ptls_hexdump(alloca(_l * 2 + 1), (s), _l);                                                                                 \
    })

#else

#define H2O_CONN_IS_PROBED(label, conn) (0)
#define H2O_PROBE_CONN0(label, conn)
#define H2O_PROBE_CONN(label, conn, ...)
#define H2O_PROBE(label, ...)
#define H2O_PROBE_HEXDUMP(s, l)

#endif

/* utility functions follow */

/* define the functions as non-inlineable, as bcc cannot handle relative offset against a static const (e.g.,
 * H2O_TOKEN_PATH->buf.base) */
__attribute__((noinline)) static void h2o_probe_request_header(h2o_req_t *req, uint64_t req_index, h2o_iovec_t name,
                                                               h2o_iovec_t value)
{
    H2O_PROBE_CONN(RECEIVE_REQUEST_HEADER, req->conn, req_index, name.base, name.len, value.base, value.len);
}

__attribute__((noinline)) static void h2o_probe_response_header(h2o_req_t *req, uint64_t req_index, h2o_iovec_t name,
                                                                h2o_iovec_t value)
{
    H2O_PROBE_CONN(SEND_RESPONSE_HEADER, req->conn, req_index, name.base, name.len, value.base, value.len);
}

static inline void h2o_probe_log_request(h2o_req_t *req, uint64_t req_index)
{
    H2O_PROBE_CONN(RECEIVE_REQUEST, req->conn, req_index, req->version);
    if (H2O_CONN_IS_PROBED(RECEIVE_REQUEST_HEADER, req->conn)) {
        h2o_probe_request_header(req, req_index, H2O_TOKEN_AUTHORITY->buf, req->input.authority);
        h2o_probe_request_header(req, req_index, H2O_TOKEN_METHOD->buf, req->input.method);
        h2o_probe_request_header(req, req_index, H2O_TOKEN_PATH->buf, req->input.path);
        h2o_probe_request_header(req, req_index, H2O_TOKEN_SCHEME->buf, req->input.scheme->name);
        size_t i;
        for (i = 0; i != req->headers.size; ++i) {
            h2o_header_t *h = req->headers.entries + i;
            h2o_probe_request_header(req, req_index, *h->name, h->value);
        }
    }
}

static inline void h2o_probe_log_response(h2o_req_t *req, uint64_t req_index)
{
    H2O_PROBE_CONN(SEND_RESPONSE_STATUS, req->conn, req_index, req->res.status);
    if (H2O_CONN_IS_PROBED(SEND_RESPONSE_HEADER, req->conn)) {
        if (req->res.content_length != SIZE_MAX) {
            char buf[sizeof(H2O_UINT64_LONGEST_STR)];
            h2o_iovec_t cl_buf = {.base = buf};
            cl_buf.len = sprintf(cl_buf.base, "%" PRIu64, req->res.content_length);
            h2o_probe_response_header(req, req_index, H2O_TOKEN_CONTENT_LENGTH->buf, cl_buf);
        }
        size_t i;
        for (i = 0; i != req->res.headers.size; ++i) {
            h2o_header_t *h = req->res.headers.entries + i;
            h2o_probe_response_header(req, req_index, *h->name, h->value);
        }
    }
}

#endif
