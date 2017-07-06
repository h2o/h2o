#include <arpa/inet.h>
#include <stdlib.h>

#include "h2get.h"
#include "hpack.h"

#include <ctype.h>
#include <stdio.h>

static const char *h2_err_to_txt[] = {
        [H2GET_ERR_NO_ERROR] = "Graceful shutdown",
        [H2GET_ERR_PROTOCOL_ERROR] = "Protocol error detected",
        [H2GET_ERR_INTERNAL_ERROR] = "Implementation fault",
        [H2GET_ERR_FLOW_CONTROL_ERROR] = "Flow-control limits exceeded",
        [H2GET_ERR_SETTINGS_TIMEOUT] = "Settings not acknowledged",
        [H2GET_ERR_STREAM_CLOSED] = "Frame received for closed stream",
        [H2GET_ERR_FRAME_SIZE_ERROR] = "Frame size incorrect",
        [H2GET_ERR_REFUSED_STREAM] = "Stream not processed",
        [H2GET_ERR_CANCEL] = "Stream cancelled",
        [H2GET_ERR_COMPRESSION_ERROR] = "Compression state not updated",
        [H2GET_ERR_CONNECT_ERROR] = "TCP connection error for CONNECT method",
        [H2GET_ERR_ENHANCE_YOUR_CALM] = "Processing capacity exceeded",
        [H2GET_ERR_INADEQUATE_SECURITY] = "Negotiated TLS parameters not acceptable",
        [H2GET_ERR_HTTP_1_1_REQUIRED] = "Use HTTP/1.1 for the request",
};

const char *h2get_render_error_code(uint32_t err)
{
    if (err > H2GET_ERR_HTTP_1_1_REQUIRED) {
        return "Unknown error code";
    }
    return h2_err_to_txt[err];
}
static char *h2get_header_to_txt[] = {
    "DATA",         "HEADERS", "PRIORITY", "RST_STREAM",    "SETTINGS",
    "PUSH_PROMISE", "PING",    "GOAWAY",   "WINDOW_UPDATE", "CONTINUATION",
};

#define RENDERER(name)                                                                                                 \
    static void h2get_frame_render_##name(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,     \
                                          char *p, size_t plen)                                                        \
    {                                                                                                                  \
        h2get_buf_printf(out, "\n%s", "h2get_frame_" #name "_render");                                                 \
    }

RENDERER(priority)
RENDERER(rst_stream)
RENDERER(push_promise)
RENDERER(ping)
RENDERER(continuation)

#undef RENDERER

#define H2GET_HEADERS_HEADERS_END_STREAM 0x1
#define H2GET_HEADERS_HEADERS_END_HEADERS 0x4
#define H2GET_HEADERS_HEADERS_PADDED 0x8
#define H2GET_HEADERS_HEADERS_PRIORITY 0x20

static void h2get_frame_render_headers(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,
                                       char *payload, size_t plen)
{
    struct list headers, *cur, *next;
    int ret;

    if (h->flags) {
        h2get_buf_printf(out, "\n\tflags: ");
        if (h->flags & H2GET_HEADERS_HEADERS_END_STREAM)
            h2get_buf_printf(out, "END_STREAM ");
        if (h->flags & H2GET_HEADERS_HEADERS_END_HEADERS)
            h2get_buf_printf(out, "END_HEADERS ");
        if (h->flags & H2GET_HEADERS_HEADERS_PADDED)
            h2get_buf_printf(out, "PADDED ");
        if (h->flags & H2GET_HEADERS_HEADERS_PRIORITY)
            h2get_buf_printf(out, "PRIORITY ");
    }

    if (h->flags & H2GET_HEADERS_HEADERS_PRIORITY) {
        struct h2get_h2_priority *prio = (struct h2get_h2_priority *)payload;
        payload += sizeof(*prio);
        plen -= sizeof(*prio);
        h2get_buf_printf(out, "\nPriority: %sexclusive, stream dependency: %lu, weight: %u",
                         h2get_h2_priority_is_exclusive(prio) ? "" : "not ", h2get_h2_priority_get_dep_stream_id(prio),
                         prio->weight);
    }

    list_init(&headers);

    ret = h2get_hpack_decode(&ctx->own_hpack, payload, plen, &headers);
    if (ret < 0) {
        h2get_buf_printf(out, "\nError decoding headers");
        return;
    }
    for (cur = headers.next; cur != &headers; cur = next) {
        struct h2get_decoded_header *hdh = list_to_dh(cur);

        next = cur->next;
        list_del(&hdh->node);

        h2get_buf_printf(out, "\n\t'%.*s' => '%.*s'", hdh->key.len, hdh->key.buf, hdh->value.len, hdh->value.buf);
        h2get_decoded_header_free(hdh);
    }
    return;
}

static void h2get_frame_render_window_update(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,
                                             char *payload, size_t plen)
{
    h2get_buf_printf(out, "\n\tincrement => %lu", ntohl(*(uint32_t *)payload) >> 1);
    return;
}

static void h2get_frame_render_data(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,
                                    char *payload, size_t plen)
{
    dump_zone(payload, plen);
}

static void h2get_frame_render_unknown(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,
                                       char *payload, size_t plen)
{
    h2get_buf_write(out, H2GET_BUF(payload, plen));
}

static void h2get_frame_render_goaway(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,
                                      char *payload, size_t plen)
{
    struct h2get_h2_goaway *f = (struct h2get_h2_goaway *)payload;
    h2get_buf_printf(out, "\n\tstream_id: %u, error: '%s'", ntohl(f->last_stream_id),
                     h2get_render_error_code(ntohl(f->error_code)));
    if (plen > sizeof(*f)) {
        h2get_buf_printf(out, ", debug data: '%.*s'", (int)(plen - sizeof(*f)), f->additional_debug_data);
    }
}

static void h2get_frame_render_settings(struct h2get_ctx *ctx, struct h2get_buf *out, struct h2get_h2_header *h,
                                        char *payload, size_t plen)
{
    struct h2get_h2_setting *settings;
    int i;

    if (h->flags & H2GET_HEADERS_SETTINGS_FLAGS_ACK) {
        if (plen) {
            /* Receipt of a SETTINGS frame with the ACK flag set and a length
             * field value other than 0 MUST be treated as a connection error */
            h2get_buf_printf(out, "%s", "\nerror: frame size error: ack must be of size zero");
            return;
        }
        h2get_buf_printf(out, "%s", " ack flag set");
    }

    /* The stream identifier for a SETTINGS frame MUST be zero (0x0). */
    if (h->stream_id) {
        h2get_buf_printf(out, "%s", "\nerror: stream id must be zero");
        return;
    }

    /* A SETTINGS frame with a length other than a multiple of 6 octets MUST
     * be treated as a connection error. */
    if (plen % 6) {
        h2get_buf_printf(out, "%s", "\nerror: frame size must be a multiple of 6");
        return;
    }

    settings = (struct h2get_h2_setting *)payload;
    for (i = 0; i < (plen) / sizeof(*settings); i++) {
        unsigned int v = ntohl(settings[i].value);
        switch (ntohs(settings[i].id)) {
        case H2GET_HEADERS_SETTINGS_HEADER_TABLE_SIZE:
            h2get_buf_printf(out, "\n\theader table size: %u", v);
            break;
        case H2GET_HEADERS_SETTINGS_ENABLE_PUSH:
            /** Any value other than 0 or 1 MUST be treated as a connection
             * error. */
            if (v != 0 && v != 1) {
                h2get_buf_printf(out, "\nerror: invalid value for enable push: %u", v);
                return;
            }
            h2get_buf_printf(out, "\n\tenable push: %s", v ? "true" : "false");
            break;
        case H2GET_HEADERS_SETTINGS_MAX_CONCURRENT_STREAMS:
            h2get_buf_printf(out, "\n\tmax concurrent streams: %u", v);
            break;
        case H2GET_HEADERS_SETTINGS_INITIAL_WINDOW_SIZE:
            h2get_buf_printf(out, "\n\tinitial window size: %u", v);
            break;
        case H2GET_HEADERS_SETTINGS_MAX_FRAME_SIZE:
            h2get_buf_printf(out, "\n\tmax frame size: %u", v);
            break;
        case H2GET_HEADERS_SETTINGS_MAX_HEADER_LIST_SIZE:
            h2get_buf_printf(out, "\n\tmax header list size: %u", v);
            break;
        default:
            /* An endpoint that receives a SETTINGS frame with any unknown or
             * unsupported identifier MUST ignore that setting. */
            h2get_buf_printf(out, "\n\tunknown frame type: %u", ntohs(settings[i].id));
            break;
        }
    }
    return;
}

static h2get_frame_render_t h2get_frame_render_by_type[] = {
    h2get_frame_render_data,         h2get_frame_render_headers,  h2get_frame_render_priority,
    h2get_frame_render_rst_stream,   h2get_frame_render_settings, h2get_frame_render_push_promise,
    h2get_frame_render_ping,         h2get_frame_render_goaway,   h2get_frame_render_window_update,
    h2get_frame_render_continuation,
};

h2get_frame_render_t h2get_frame_get_renderer(uint8_t type)
{
    if (type >= (sizeof(h2get_frame_render_by_type) / sizeof(h2get_frame_render_by_type[0])))
        return h2get_frame_render_unknown;
    return h2get_frame_render_by_type[type];
}

static struct h2get_h2_header h2get_h2_settings_ack = {
    0, H2GET_HEADERS_SETTINGS, H2GET_HEADERS_SETTINGS_FLAGS_ACK, 0, 0,
};

int h2get_send_settings_ack(struct h2get_ctx *ctx, int timeout)
{
    return ctx->ops->write(&ctx->conn, &H2GET_BUF(&h2get_h2_settings_ack, sizeof(h2get_h2_settings_ack)), timeout);
}

const char *h2get_frame_type_to_str(uint8_t type)
{
    static __thread char unknown_err[] = "Unknown frame type 0x00";
    if (type >= 0 && type < H2GET_HEADERS_MAX) {
        return h2get_header_to_txt[type];
    }
    sprintf(unknown_err, "Unknown frame type 0x%02x", type);
    return unknown_err;
}

static unsigned int len24_toh(unsigned int be_24_bits_len)
{
    be_24_bits_len <<= 8;
    return ntohl(be_24_bits_len & 0xffffff00);
}

const char *err_read_timeout = "read failed: timeout";
int h2get_read_one_frame(struct h2get_ctx *ctx, struct h2get_h2_header *header, struct h2get_buf *buf, int timeout,
                         const char **err)
{
    int ret, plen;
    char *payload = NULL;

    ret = ctx->ops->read(&ctx->conn, &H2GET_BUF(header, sizeof(*header)), timeout);
    if (ret < 0) {
        *err = "read failed";
        return -1;
    } else if (ret == 0) {
        *err = err_read_timeout;
        return -1;
    }

    plen = len24_toh(header->len);
    if (!plen) {
        buf->buf = NULL;
        buf->len = 0;
        return 0;
    }
    payload = malloc(plen);
    size_t to_read = plen;
    do {
        ret = ctx->ops->read(&ctx->conn, &H2GET_BUF(payload + (plen - to_read), to_read), timeout);
        if (ret <= 0) {
            if (!ret) {
                *err = err_read_timeout;
            } else {
                *err = "read failed";
            }
            free(payload);
            return -1;
        }
        to_read -= ret;
    } while (to_read > 0);

    buf->len = plen;
    buf->buf = payload;
    return 0;
}
