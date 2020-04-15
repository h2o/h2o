#ifndef H2OLOG_DATA_TYPES_H
#define H2OLOG_DATA_TYPES_H

#define MAX_HDR_LEN 128

/*
 * Supported USDT events for the HTTP trace mode.
 */
enum { HTTP_EVENT_RECEIVE_REQ, HTTP_EVENT_RECEIVE_REQ_HDR, HTTP_EVENT_SEND_RESP, HTTP_EVENT_SEND_RESP_HDR };

/*
 * Message structure of an HTTP event.
 */
typedef struct st_http_event_t {
    uint8_t type;
    uint64_t conn_id;
    uint64_t req_id;
    union {
        uint32_t http_version;
        uint32_t http_status;
        struct {
            uint64_t name_len;
            uint64_t value_len;
            char name[MAX_HDR_LEN];
            char value[MAX_HDR_LEN];
        } header;
    };
} http_event_t;

// Those structs must be synchronized to h2o and quicly.
// Fields that include "dummy" are ignored.

// from quicly

struct st_quicly_stream_t {
    uint64_t dummy;
    int64_t stream_id;
};

struct st_quicly_conn_t {
    uint32_t dummy[4];
    uint32_t master_id;
};

struct quicly_rtt_t {
    uint32_t minimum;
    uint32_t smoothed;
    uint32_t variance;
    uint32_t latest;
};

struct st_quicly_address_token_plaintext_t {
    int dummy;
};

// from h2o

struct st_h2o_conn_t {
    int dummy;
};

#endif
