#include <alloca.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"

struct st_h2o_http1_req_entity_reader {
    int (*handle_incoming)(h2o_http1_conn_t *conn);
    size_t entity_offset;
};

static void finalostream_send(h2o_ostream_t *_self, h2o_req_t *req, uv_buf_t *inbufs, size_t inbufcnt, int is_final);

static void init_request(h2o_http1_conn_t *conn, int reinit)
{
    if (reinit)
        h2o_dispose_request(&conn->req);
    h2o_init_request(&conn->req, &conn->super, NULL);

    conn->req._ostr_top = &conn->_ostr_final.super;
    conn->_ostr_final.super.do_send = finalostream_send;
    conn->_ostr_final.sent_headers = 0;
}

static uv_buf_t alloc_inbuf(uv_handle_t *handle, size_t _suggested_size)
{
    h2o_http1_conn_t *conn = handle->data;
    return h2o_allocate_input_buffer(&conn->_input, 8192);
}

static void close_connection(h2o_http1_conn_t *conn)
{
    h2o_timeout_unlink_entry(conn->_timeout, &conn->_timeout_entry);
    h2o_dispose_request(&conn->req);
    free(conn->_input);
    free(conn->_req_entity_reader);
    conn->close_cb(conn);
}

static void set_timeout(h2o_http1_conn_t *conn, h2o_timeout_t *timeout, h2o_timeout_cb cb)
{
    if (conn->_timeout != NULL) {
        h2o_timeout_unlink_entry(conn->_timeout, &conn->_timeout_entry);
        conn->_timeout_entry.cb = NULL;
    }
    conn->_timeout = timeout;
    if (timeout != NULL) {
        h2o_timeout_link_entry(timeout, &conn->_timeout_entry);
        conn->_timeout_entry.cb = cb;
    }
}

static int create_chunked_entity_reader(h2o_http1_conn_t *conn)
{
    return -1;
}

static int handle_content_length_entity_read(h2o_http1_conn_t *conn)
{
    /* wait until: reqsize == conn->_input.size */
    if (conn->_input->size < conn->_reqsize)
        return -2;

    /* all input has arrived */
    h2o_vector_reserve(&conn->req.pool, (h2o_vector_t*)&conn->req.entity, sizeof(uv_buf_t), 1);
    conn->req.entity.entries[0].base = conn->_input->bytes + conn->_req_entity_reader->entity_offset;
    conn->req.entity.entries[0].len = conn->_reqsize - conn->_req_entity_reader->entity_offset;
    conn->req.entity.size = 1;
    free(conn->_req_entity_reader);
    conn->_req_entity_reader = NULL;
    set_timeout(conn, NULL, NULL);
    uv_read_stop(conn->stream);
    h2o_process_request(&conn->req);

    return 0;
}

static int create_content_length_entity_reader(h2o_http1_conn_t *conn, size_t content_length)
{
    struct st_h2o_http1_req_entity_reader *reader = malloc(sizeof(struct st_h2o_http1_req_entity_reader));
    conn->_req_entity_reader = reader;

    reader->handle_incoming = handle_content_length_entity_read;
    reader->entity_offset = conn->_reqsize;
    conn->_reqsize += content_length;

    return 0;
}

static int create_entity_reader(h2o_http1_conn_t *conn, const struct phr_header *entity_header)
{
    if (entity_header->name_len == sizeof("content-encoding") - 1) {
        /* content-encoding */
        if (h2o_lcstris(entity_header->value, entity_header->value_len, H2O_STRLIT("chunked"))) {
            return create_chunked_entity_reader(conn);
        }
    } else {
        /* content-length */
        char *endptr;
        intmax_t content_length = strtoimax(h2o_strdup(&conn->req.pool, entity_header->value, entity_header->value_len).base, &endptr, 10);
        if (*endptr == '\0' && content_length != INTMAX_MAX && 0 <= content_length && content_length <= conn->super.ctx->max_request_entity_size) {
            return create_content_length_entity_reader(conn, (size_t)content_length);
        }
    }
    /* failed */
    return -1;
}

static ssize_t fixup_request(h2o_http1_conn_t *conn, struct phr_header *headers, size_t num_headers, int minor_version)
{
    ssize_t entity_header_index;
    uv_buf_t connection = { NULL, 0 }, host = { NULL, 0 }, upgrade = { NULL, 0 };

    conn->req.scheme = "http";
    conn->req.scheme_len = 4;
    conn->req.version = 0x100 | minor_version;

    /* init headers */
    entity_header_index = h2o_init_headers(&conn->req.pool, &conn->req.headers, headers, num_headers, &connection, &host, &upgrade);

    /* move host header to req->authority */
    if (host.base != NULL) {
        conn->req.authority = host.base;
        conn->req.authority_len = host.len;
    }

    /* setup persistent flag (and upgrade info) */
    if (connection.base != NULL) {
        /* TODO contains_token function can be faster */
        if (h2o_contains_token(connection.base, connection.len, H2O_STRLIT("keep-alive"))) {
            conn->req.http1_is_persistent = 1;
        }
        if (upgrade.base != NULL && h2o_contains_token(connection.base, connection.len, H2O_STRLIT("upgrade"))) {
            conn->req.upgrade = upgrade;
        }
    } else if (conn->req.version >= 0x101) {
        /* defaults to keep-alive if >= HTTP/1.1 */
            conn->req.http1_is_persistent = 1;
    }

    return entity_header_index;
}

static int handle_incoming(h2o_http1_conn_t *conn, size_t prevreqlen)
{
    size_t inreqlen = conn->_input->size < H2O_MAX_REQLEN ? conn->_input->size : H2O_MAX_REQLEN;
    int reqlen, minor_version;
    struct phr_header headers[H2O_MAX_HEADERS];
    size_t num_headers = H2O_MAX_HEADERS;
    ssize_t entity_body_header_index;

    reqlen = phr_parse_request(conn->_input->bytes, inreqlen, &conn->req.method, &conn->req.method_len,
                               &conn->req.path, &conn->req.path_len, &minor_version,
                               headers, &num_headers, prevreqlen);
    switch (reqlen) {
    default: // parse complete
        conn->_reqsize = reqlen;
        if ((entity_body_header_index = fixup_request(conn, headers, num_headers, minor_version)) != -1) {
            if (create_entity_reader(conn, headers + entity_body_header_index) != 0) {
                set_timeout(conn, NULL, NULL);
                uv_read_stop(conn->stream);
                conn->req.http1_is_persistent = 0;
                h2o_send_error(&conn->req, 400, "Invalid Request", "unknown entity encoding");
                return 0;
            }
            return conn->_req_entity_reader->handle_incoming(conn);
        } else {
            set_timeout(conn, NULL, NULL);
            uv_read_stop(conn->stream);
            h2o_process_request(&conn->req);
        }
        return 0;
    case -2: // incomplete
        if (inreqlen == H2O_MAX_REQLEN) {
            // request is too long (TODO notify)
            close_connection(conn);
            return 0;
        }
        return 1;
    case -1: // error
        close_connection(conn);
        return 0;
    }
}

static void reqread_on_read(uv_stream_t *stream, ssize_t nread, uv_buf_t _buf)
{
    h2o_http1_conn_t *conn = stream->data;
    size_t prevreqlen;

    if (nread == -1) {
        close_connection(conn);
        return;
    }

    prevreqlen = conn->_input->size;
    conn->_input->size += nread;
    if (conn->_req_entity_reader == NULL)
        handle_incoming(conn, prevreqlen);
    else
        conn->_req_entity_reader->handle_incoming(conn);
}

static void reqread_on_timeout(h2o_timeout_entry_t *entry)
{
    h2o_http1_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http1_conn_t, _timeout_entry, entry);

    /* TODO log */
    conn->req.http1_is_persistent = 0;
    close_connection(conn);
}

static inline void reqread_start(h2o_http1_conn_t *conn)
{
    set_timeout(conn, &conn->super.ctx->req_timeout, reqread_on_timeout);
    uv_read_start(conn->stream, alloc_inbuf, reqread_on_read);
}

static void on_send_next(uv_write_t *wreq, int status)
{
    h2o_http1_conn_t *conn = wreq->data;

    if (status != 0)
        close_connection(conn);
    else
        h2o_proceed_response(&conn->req);
}

static void on_send_complete(uv_write_t *wreq, int status)
{
    h2o_http1_conn_t *conn = wreq->data;

    assert(conn->req._ostr_top == &conn->_ostr_final.super);

    if (! conn->req.http1_is_persistent) {
        /* TODO use lingering close */
        close_connection(conn);
        return;
    }

    /* handle next request */
    init_request(conn, 1);
    h2o_consume_input_buffer(&conn->_input, conn->_reqsize);
    if (conn->_input->size != 0) {
        if (handle_incoming(conn, 0) == 0) {
            return;
        }
    }
    reqread_start(conn);
}

static void on_upgrade_complete(uv_write_t *wreq, int status)
{
    h2o_http1_conn_t *conn = wreq->data;
    h2o_http1_upgrade_cb cb = conn->upgrade.cb;
    void *data = conn->upgrade.data;
    uv_stream_t *stream = NULL;
    h2o_input_buffer_t *buffered_input = NULL;
    size_t reqsize = 0;

    h2o_dispose_request(&conn->req);

    /* call close_cb (with conn->tcp set to NULL) */
    if (status == 0) {
        stream = conn->stream;
        conn->stream = NULL;
        buffered_input = conn->_input;
        conn->_input = NULL;
        reqsize = conn->_reqsize;
    }
    conn->close_cb(conn);
    conn = NULL;

    cb(data, stream, buffered_input, reqsize);
}

static void flatten_headers(h2o_req_t *req, uv_buf_t *bufs, const char *connection)
{
    h2o_timestamp_t ts;

    h2o_get_timestamp(req->conn->ctx, &req->pool, &ts);

    if (req->res.content_length != SIZE_MAX) {
        bufs[0] = h2o_sprintf(
            &req->pool,
            "HTTP/1.1 %d %s\r\ndate: %.*s\r\nserver: %.*s\r\nconnection: %s\r\ncontent-length: %zu\r\n",
            req->res.status, req->res.reason,
            (int)H2O_TIMESTR_RFC1123_LEN, ts.str->rfc1123,
            (int)req->conn->ctx->server_name.len, req->conn->ctx->server_name.base,
            connection,
            req->res.content_length);
    } else {
        bufs[0] = h2o_sprintf(
            &req->pool,
            "HTTP/1.1 %d %s\r\ndate: %.*s\r\nserver: %.*s\r\nconnection: %s\r\n",
            req->res.status, req->res.reason,
            (int)H2O_TIMESTR_RFC1123_LEN, ts.str->rfc1123,
            (int)req->conn->ctx->server_name.len, req->conn->ctx->server_name.base,
            connection);
    }
    bufs[1] = h2o_flatten_headers(&req->pool, &req->res.headers);
}

void finalostream_send(h2o_ostream_t *_self, h2o_req_t *req, uv_buf_t *inbufs, size_t inbufcnt, int is_final)
{
    h2o_http1_finalostream_t *self = (void*)_self;
    h2o_http1_conn_t *conn = (h2o_http1_conn_t*)req->conn;
    uv_buf_t *bufs = alloca(sizeof(uv_buf_t) * (inbufcnt + 2));
    int bufcnt = 0;

    assert(self == &conn->_ostr_final);

    if (! self->sent_headers) {
        /* build headers and send */
        self->sent_headers = 1;
        flatten_headers(req, bufs + bufcnt, req->http1_is_persistent ? "keep-alive" : "close");
        bufcnt += 2;
    }
    memcpy(bufs + bufcnt, inbufs, sizeof(uv_buf_t) * inbufcnt);
    bufcnt += inbufcnt;

    if (bufcnt != 0) {
        uv_write(&conn->_wreq, conn->stream, bufs, bufcnt, is_final ? on_send_complete : on_send_next);
    } else {
        on_send_complete(&conn->_wreq, 0);
    }
}

static int get_peername(h2o_conn_t *_conn, struct sockaddr *name, int *namelen)
{
    h2o_http1_conn_t *conn = (h2o_http1_conn_t*)_conn;
    return uv_tcp_getpeername((uv_tcp_t*)conn->stream, name, namelen);
}

void h2o_http1_init(h2o_http1_conn_t *conn, uv_stream_t *stream, h2o_loop_context_t *ctx, h2o_req_cb req_cb, h2o_http1_close_cb close_cb)
{
    /* zero-fill all properties expect req */
    memset(conn, 0, offsetof(h2o_http1_conn_t, req));

    /* init properties that need to be non-zero */
    conn->super.ctx = ctx;
    conn->super.req_cb = req_cb;
    conn->super.getpeername = get_peername;
    conn->stream = stream;
    conn->stream->data = conn;
    conn->close_cb = close_cb;
    conn->_wreq.data = conn;

    init_request(conn, 0);
    reqread_start(conn);
}

void h2o_http1_upgrade(h2o_http1_conn_t *conn, uv_buf_t *inbufs, size_t inbufcnt, h2o_http1_upgrade_cb on_complete, void *user_data)
{
    uv_buf_t *bufs = alloca(sizeof(uv_buf_t) * (inbufcnt + 2));

    conn->upgrade.data = user_data;
    conn->upgrade.cb = on_complete;

    flatten_headers(&conn->req, bufs, "upgrade");
    memcpy(bufs + 2, inbufs, sizeof(uv_buf_t) * inbufcnt);

    uv_write(&conn->_wreq, conn->stream, bufs, (int)(inbufcnt + 2), on_upgrade_complete);
}

void h2o_http1_close_and_free(h2o_http1_conn_t *conn)
{
    if (conn->stream != NULL)
        uv_close((uv_handle_t*)conn->stream, (uv_close_cb)free);
    free(conn);
}
