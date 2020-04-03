#ifndef H2OLOG_DATA_TYPES_H
#define H2OLOG_DATA_TYPES_H

// Those structs must be synchronized to h2o and quicly.
// Fields that include "dummy" are ignored.

struct st_quicly_stream_t {
    uint64_t dummy;
    int64_t stream_id;
};

struct st_quicly_conn_t {
    uint32_t dummy[4];
    uint32_t master_id;
};

struct st_h2o_conn_t {
    void *dummy_ctx;
    void **dummy_hosts;
    uint64_t dummy_connected_at[2];
    uint64_t h2o_conn_id;
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

#endif