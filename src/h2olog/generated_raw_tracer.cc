// Generated code. Do not edit it here!

extern "C" {
#include <sys/time.h>
#include "quicly.h"
}

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <algorithm>

#include "h2olog.h"
#include "json.h"

#include "raw_tracer.h.cc"

#define STR_LEN 64
#define STR_LIT(s) s, strlen(s)

using namespace std;


// This is enough for here. See `quicly.c` for the full definition.
struct st_quicly_conn_t {
  struct _st_quicly_conn_public_t super;
};
using typeof_st_quicly_stream_t__stream_id = decltype(st_quicly_stream_t::stream_id);
using typeof_quicly_rtt_t__minimum = decltype(quicly_rtt_t::minimum);
using typeof_quicly_rtt_t__smoothed = decltype(quicly_rtt_t::smoothed);
using typeof_quicly_rtt_t__variance = decltype(quicly_rtt_t::variance);
using typeof_quicly_rtt_t__latest = decltype(quicly_rtt_t::latest);
using typeof_st_quicly_conn_t__master_id = decltype(st_quicly_conn_t::super.local.cid_set.plaintext.master_id);


#define GEN_FIELD_INFO(type, field, name) gen_field_info(#type, #field, &((type *)NULL)->field, name)

#define DEFINE_RESOLVE_FUNC(field_type) \
std::string gen_field_info(const char *struct_type, const char *field_name, const field_type *field_ptr, const char *name) \
{ \
    return do_resolve(struct_type, field_name, #field_type, field_ptr, name); \
}

template <typename FieldType>
static std::string do_resolve(const char *struct_type, const char *field_name, const char *field_type, const FieldType *field_ptr, const char *name) {
    char *buff = NULL;
    size_t buff_len = 0;
    FILE *mem = open_memstream(&buff, &buff_len);
    fprintf(mem, "/* %s (%s#%s) */\n", name, struct_type, field_name);
    fprintf(mem, "#define offsetof_%s %zd\n", name, (const char *)field_ptr - (const char *)NULL);
    fprintf(mem, "#define typeof_%s %s\n", name, field_type);
    fprintf(mem, "#define get_%s(st) *((const %s *) ((const char*)st + offsetof_%s))\n", name, field_type, name);
    fprintf(mem, "\n");
    fflush(mem);
    std::string s(buff, buff_len);
    fclose(mem);
    return s;
}

DEFINE_RESOLVE_FUNC(int16_t);
DEFINE_RESOLVE_FUNC(uint16_t);
DEFINE_RESOLVE_FUNC(int32_t);
DEFINE_RESOLVE_FUNC(uint32_t);
DEFINE_RESOLVE_FUNC(int64_t);
DEFINE_RESOLVE_FUNC(uint64_t);

static std::string gen_bpf_header() {
  std::string bpf;

  bpf += "#define sizeof_st_quicly_stream_t " + std::to_string(std::min<size_t>(sizeof(struct st_quicly_stream_t), 100)) + "\n";
  bpf += GEN_FIELD_INFO(struct st_quicly_stream_t, stream_id, "st_quicly_stream_t__stream_id");

  bpf += "#define sizeof_quicly_rtt_t " + std::to_string(std::min<size_t>(sizeof(struct quicly_rtt_t), 100)) + "\n";
  bpf += GEN_FIELD_INFO(struct quicly_rtt_t, minimum, "quicly_rtt_t__minimum");
  bpf += GEN_FIELD_INFO(struct quicly_rtt_t, smoothed, "quicly_rtt_t__smoothed");
  bpf += GEN_FIELD_INFO(struct quicly_rtt_t, variance, "quicly_rtt_t__variance");
  bpf += GEN_FIELD_INFO(struct quicly_rtt_t, latest, "quicly_rtt_t__latest");

  bpf += "#define sizeof_st_quicly_conn_t " + std::to_string(std::min<size_t>(sizeof(struct st_quicly_conn_t), 100)) + "\n";
  bpf += GEN_FIELD_INFO(struct st_quicly_conn_t, super.local.cid_set.plaintext.master_id, "st_quicly_conn_t__master_id");

  bpf += "#define sizeof_sockaddr " + std::to_string(std::min<size_t>(sizeof(struct sockaddr), 100)) + "\n";

  bpf += "#define sizeof_sockaddr_in " + std::to_string(std::min<size_t>(sizeof(struct sockaddr_in), 100)) + "\n";

  bpf += "#define sizeof_sockaddr_in6 " + std::to_string(std::min<size_t>(sizeof(struct sockaddr_in6), 100)) + "\n";

  bpf += GEN_FIELD_INFO(struct sockaddr, sa_family, "sockaddr__sa_family");
  bpf += "#define AF_INET  " + std::to_string(AF_INET) + "\n";
  bpf += "#define AF_INET6 " + std::to_string(AF_INET6) + "\n";

  return bpf;
}


struct event_t {
  uint8_t id;

  union {
    struct { // quicly:connect
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      char dcid[STR_LEN];
    } accept;
    struct { // quicly:free
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[1];
      size_t bytes_len;
    } receive;
    struct { // quicly:version_switch
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_decrypt
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      size_t decrypted_len;
    } crypto_decrypt;
    struct { // quicly:crypto_handshake
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t phase;
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_prepare
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_commit
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      int ack_only;
    } packet_commit;
    struct { // quicly:packet_acked
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      int is_late_ack;
    } packet_acked;
    struct { // quicly:packet_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
    } packet_lost;
    struct { // quicly:pto
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:ack_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t largest_acked;
      uint64_t ack_delay;
    } ack_send;
    struct { // quicly:ping_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } ping_send;
    struct { // quicly:ping_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } ping_receive;
    struct { // quicly:transport_close_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:max_data_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
    } max_data_send;
    struct { // quicly:max_data_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
    } max_data_receive;
    struct { // quicly:max_streams_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t limit;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:new_connection_id_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_send;
    struct { // quicly:new_connection_id_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_receive;
    struct { // quicly:retire_connection_id_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_send;
    struct { // quicly:retire_connection_id_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_receive;
    struct { // quicly:data_blocked_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_send;
    struct { // quicly:data_blocked_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_send;
    struct { // quicly:stream_data_blocked_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_receive;
    struct { // quicly:datagram_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t payload[STR_LEN];
      size_t payload_len;
    } datagram_send;
    struct { // quicly:datagram_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t payload[STR_LEN];
      size_t payload_len;
    } datagram_receive;
    struct { // quicly:ack_frequency_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t packet_tolerance;
      uint64_t max_ack_delay;
      int ignore_order;
    } ack_frequency_receive;
    struct { // quicly:quictrace_sent
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
    } quictrace_sent;
    struct { // quicly:quictrace_recv
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_recv;
    struct { // quicly:quictrace_send_stream
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_recv_ack
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } quictrace_recv_ack;
    struct { // quicly:quictrace_recv_ack_delay
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t ack_delay;
    } quictrace_recv_ack_delay;
    struct { // quicly:quictrace_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_lost;
    struct { // quicly:quictrace_cc_ack
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum minimum;
      typeof_quicly_rtt_t__smoothed smoothed;
      typeof_quicly_rtt_t__variance variance;
      typeof_quicly_rtt_t__latest latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum minimum;
      typeof_quicly_rtt_t__smoothed smoothed;
      typeof_quicly_rtt_t__variance variance;
      typeof_quicly_rtt_t__latest latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // quicly:stream_on_open
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
    } stream_on_open;
    struct { // quicly:stream_on_destroy
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      int err;
    } stream_on_destroy;
    struct { // quicly:stream_on_send_shift
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      size_t delta;
    } stream_on_send_shift;
    struct { // quicly:stream_on_send_emit
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      size_t off;
      size_t capacity;
    } stream_on_send_emit;
    struct { // quicly:stream_on_send_stop
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      int err;
    } stream_on_send_stop;
    struct { // quicly:stream_on_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      size_t off;
      uint8_t src[STR_LEN];
      size_t src_len;
    } stream_on_receive;
    struct { // quicly:stream_on_receive_reset
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      int err;
    } stream_on_receive_reset;
    struct { // quicly:conn_stats
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      size_t size;
    } conn_stats;
    struct { // h2o:receive_request
      uint64_t conn_id;
      uint64_t req_id;
      int http_version;
    } receive_request;
    struct { // h2o:receive_request_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
    } receive_request_header;
    struct { // h2o:send_response
      uint64_t conn_id;
      uint64_t req_id;
      int status;
    } send_response;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
    } send_response_header;
    struct { // h2o:h1_accept
      uint64_t conn_id;
    } h1_accept;
    struct { // h2o:h1_close
      uint64_t conn_id;
    } h1_close;
    struct { // h2o:h2_unknown_frame_type
      uint64_t conn_id;
      uint8_t frame_type;
    } h2_unknown_frame_type;
    struct { // h2o:h3s_accept
      uint64_t conn_id;
      typeof_st_quicly_conn_t__master_id master_id;
    } h3s_accept;
    struct { // h2o:h3s_destroy
      uint64_t conn_id;
    } h3s_destroy;
    struct { // h2o:h3s_stream_set_state
      uint64_t conn_id;
      uint64_t req_id;
      unsigned state;
    } h3s_stream_set_state;
    struct { // h2o:h3_frame_receive
      uint64_t frame_type;
      uint8_t bytes[STR_LEN];
      size_t bytes_len;
    } h3_frame_receive;
    struct { // h2o:h3_packet_receive
      h2olog_address_t dest;
      h2olog_address_t src;
      size_t bytes_len;
    } h3_packet_receive;
    struct { // h2o:h3_packet_forward
      h2olog_address_t dest;
      h2olog_address_t src;
      size_t num_packets;
      size_t num_bytes;
      int fd;
    } h3_packet_forward;

    };
  };
  

void h2o_raw_tracer::initialize() {
  available_usdts.assign({
    h2o_tracer::usdt("quicly", "connect", "trace_quicly__connect"),
    h2o_tracer::usdt("quicly", "accept", "trace_quicly__accept"),
    h2o_tracer::usdt("quicly", "free", "trace_quicly__free"),
    h2o_tracer::usdt("quicly", "send", "trace_quicly__send"),
    h2o_tracer::usdt("quicly", "receive", "trace_quicly__receive"),
    h2o_tracer::usdt("quicly", "version_switch", "trace_quicly__version_switch"),
    h2o_tracer::usdt("quicly", "idle_timeout", "trace_quicly__idle_timeout"),
    h2o_tracer::usdt("quicly", "stateless_reset_receive", "trace_quicly__stateless_reset_receive"),
    h2o_tracer::usdt("quicly", "crypto_decrypt", "trace_quicly__crypto_decrypt"),
    h2o_tracer::usdt("quicly", "crypto_handshake", "trace_quicly__crypto_handshake"),
    h2o_tracer::usdt("quicly", "crypto_update_secret", "trace_quicly__crypto_update_secret"),
    h2o_tracer::usdt("quicly", "crypto_send_key_update", "trace_quicly__crypto_send_key_update"),
    h2o_tracer::usdt("quicly", "crypto_send_key_update_confirmed", "trace_quicly__crypto_send_key_update_confirmed"),
    h2o_tracer::usdt("quicly", "crypto_receive_key_update", "trace_quicly__crypto_receive_key_update"),
    h2o_tracer::usdt("quicly", "crypto_receive_key_update_prepare", "trace_quicly__crypto_receive_key_update_prepare"),
    h2o_tracer::usdt("quicly", "packet_prepare", "trace_quicly__packet_prepare"),
    h2o_tracer::usdt("quicly", "packet_commit", "trace_quicly__packet_commit"),
    h2o_tracer::usdt("quicly", "packet_acked", "trace_quicly__packet_acked"),
    h2o_tracer::usdt("quicly", "packet_lost", "trace_quicly__packet_lost"),
    h2o_tracer::usdt("quicly", "pto", "trace_quicly__pto"),
    h2o_tracer::usdt("quicly", "cc_ack_received", "trace_quicly__cc_ack_received"),
    h2o_tracer::usdt("quicly", "cc_congestion", "trace_quicly__cc_congestion"),
    h2o_tracer::usdt("quicly", "ack_send", "trace_quicly__ack_send"),
    h2o_tracer::usdt("quicly", "ping_send", "trace_quicly__ping_send"),
    h2o_tracer::usdt("quicly", "ping_receive", "trace_quicly__ping_receive"),
    h2o_tracer::usdt("quicly", "transport_close_send", "trace_quicly__transport_close_send"),
    h2o_tracer::usdt("quicly", "transport_close_receive", "trace_quicly__transport_close_receive"),
    h2o_tracer::usdt("quicly", "application_close_send", "trace_quicly__application_close_send"),
    h2o_tracer::usdt("quicly", "application_close_receive", "trace_quicly__application_close_receive"),
    h2o_tracer::usdt("quicly", "stream_send", "trace_quicly__stream_send"),
    h2o_tracer::usdt("quicly", "stream_receive", "trace_quicly__stream_receive"),
    h2o_tracer::usdt("quicly", "stream_acked", "trace_quicly__stream_acked"),
    h2o_tracer::usdt("quicly", "stream_lost", "trace_quicly__stream_lost"),
    h2o_tracer::usdt("quicly", "max_data_send", "trace_quicly__max_data_send"),
    h2o_tracer::usdt("quicly", "max_data_receive", "trace_quicly__max_data_receive"),
    h2o_tracer::usdt("quicly", "max_streams_send", "trace_quicly__max_streams_send"),
    h2o_tracer::usdt("quicly", "max_streams_receive", "trace_quicly__max_streams_receive"),
    h2o_tracer::usdt("quicly", "max_stream_data_send", "trace_quicly__max_stream_data_send"),
    h2o_tracer::usdt("quicly", "max_stream_data_receive", "trace_quicly__max_stream_data_receive"),
    h2o_tracer::usdt("quicly", "new_token_send", "trace_quicly__new_token_send"),
    h2o_tracer::usdt("quicly", "new_token_acked", "trace_quicly__new_token_acked"),
    h2o_tracer::usdt("quicly", "new_token_receive", "trace_quicly__new_token_receive"),
    h2o_tracer::usdt("quicly", "handshake_done_send", "trace_quicly__handshake_done_send"),
    h2o_tracer::usdt("quicly", "handshake_done_receive", "trace_quicly__handshake_done_receive"),
    h2o_tracer::usdt("quicly", "streams_blocked_send", "trace_quicly__streams_blocked_send"),
    h2o_tracer::usdt("quicly", "streams_blocked_receive", "trace_quicly__streams_blocked_receive"),
    h2o_tracer::usdt("quicly", "new_connection_id_send", "trace_quicly__new_connection_id_send"),
    h2o_tracer::usdt("quicly", "new_connection_id_receive", "trace_quicly__new_connection_id_receive"),
    h2o_tracer::usdt("quicly", "retire_connection_id_send", "trace_quicly__retire_connection_id_send"),
    h2o_tracer::usdt("quicly", "retire_connection_id_receive", "trace_quicly__retire_connection_id_receive"),
    h2o_tracer::usdt("quicly", "data_blocked_send", "trace_quicly__data_blocked_send"),
    h2o_tracer::usdt("quicly", "data_blocked_receive", "trace_quicly__data_blocked_receive"),
    h2o_tracer::usdt("quicly", "stream_data_blocked_send", "trace_quicly__stream_data_blocked_send"),
    h2o_tracer::usdt("quicly", "stream_data_blocked_receive", "trace_quicly__stream_data_blocked_receive"),
    h2o_tracer::usdt("quicly", "datagram_send", "trace_quicly__datagram_send"),
    h2o_tracer::usdt("quicly", "datagram_receive", "trace_quicly__datagram_receive"),
    h2o_tracer::usdt("quicly", "ack_frequency_receive", "trace_quicly__ack_frequency_receive"),
    h2o_tracer::usdt("quicly", "quictrace_sent", "trace_quicly__quictrace_sent"),
    h2o_tracer::usdt("quicly", "quictrace_recv", "trace_quicly__quictrace_recv"),
    h2o_tracer::usdt("quicly", "quictrace_send_stream", "trace_quicly__quictrace_send_stream"),
    h2o_tracer::usdt("quicly", "quictrace_recv_stream", "trace_quicly__quictrace_recv_stream"),
    h2o_tracer::usdt("quicly", "quictrace_recv_ack", "trace_quicly__quictrace_recv_ack"),
    h2o_tracer::usdt("quicly", "quictrace_recv_ack_delay", "trace_quicly__quictrace_recv_ack_delay"),
    h2o_tracer::usdt("quicly", "quictrace_lost", "trace_quicly__quictrace_lost"),
    h2o_tracer::usdt("quicly", "quictrace_cc_ack", "trace_quicly__quictrace_cc_ack"),
    h2o_tracer::usdt("quicly", "quictrace_cc_lost", "trace_quicly__quictrace_cc_lost"),
    h2o_tracer::usdt("quicly", "stream_on_open", "trace_quicly__stream_on_open"),
    h2o_tracer::usdt("quicly", "stream_on_destroy", "trace_quicly__stream_on_destroy"),
    h2o_tracer::usdt("quicly", "stream_on_send_shift", "trace_quicly__stream_on_send_shift"),
    h2o_tracer::usdt("quicly", "stream_on_send_emit", "trace_quicly__stream_on_send_emit"),
    h2o_tracer::usdt("quicly", "stream_on_send_stop", "trace_quicly__stream_on_send_stop"),
    h2o_tracer::usdt("quicly", "stream_on_receive", "trace_quicly__stream_on_receive"),
    h2o_tracer::usdt("quicly", "stream_on_receive_reset", "trace_quicly__stream_on_receive_reset"),
    h2o_tracer::usdt("quicly", "conn_stats", "trace_quicly__conn_stats"),
    h2o_tracer::usdt("h2o", "receive_request", "trace_h2o__receive_request"),
    h2o_tracer::usdt("h2o", "receive_request_header", "trace_h2o__receive_request_header"),
    h2o_tracer::usdt("h2o", "send_response", "trace_h2o__send_response"),
    h2o_tracer::usdt("h2o", "send_response_header", "trace_h2o__send_response_header"),
    h2o_tracer::usdt("h2o", "h1_accept", "trace_h2o__h1_accept"),
    h2o_tracer::usdt("h2o", "h1_close", "trace_h2o__h1_close"),
    h2o_tracer::usdt("h2o", "h2_unknown_frame_type", "trace_h2o__h2_unknown_frame_type"),
    h2o_tracer::usdt("h2o", "h3s_accept", "trace_h2o__h3s_accept"),
    h2o_tracer::usdt("h2o", "h3s_destroy", "trace_h2o__h3s_destroy"),
    h2o_tracer::usdt("h2o", "h3s_stream_set_state", "trace_h2o__h3s_stream_set_state"),
    h2o_tracer::usdt("h2o", "h3_frame_receive", "trace_h2o__h3_frame_receive"),
    h2o_tracer::usdt("h2o", "h3_packet_receive", "trace_h2o__h3_packet_receive"),
    h2o_tracer::usdt("h2o", "h3_packet_forward", "trace_h2o__h3_packet_forward"),

  });
}


void h2o_raw_tracer::do_handle_event(const void *data, int data_len) {
  const event_t *event = static_cast<const event_t*>(data);

  if (event->id == 1) { // sched:sched_process_exit
    exit(0);
  }

  // output JSON
  fprintf(out_, "{");

  switch (event->id) {
  case 2: { // quicly:connect
    json_write_pair_n(out_, STR_LIT("type"), "connect");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->connect.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->connect.at);
    json_write_pair_c(out_, STR_LIT("version"), event->connect.version);
    break;
  }
  case 3: { // quicly:accept
    json_write_pair_n(out_, STR_LIT("type"), "accept");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->accept.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->accept.at);
    json_write_pair_c(out_, STR_LIT("dcid"), event->accept.dcid);
    break;
  }
  case 4: { // quicly:free
    json_write_pair_n(out_, STR_LIT("type"), "free");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->free.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->free.at);
    break;
  }
  case 5: { // quicly:send
    json_write_pair_n(out_, STR_LIT("type"), "send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->send.at);
    json_write_pair_c(out_, STR_LIT("state"), event->send.state);
    json_write_pair_c(out_, STR_LIT("dcid"), event->send.dcid);
    break;
  }
  case 6: { // quicly:receive
    json_write_pair_n(out_, STR_LIT("type"), "receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->receive.at);
    json_write_pair_c(out_, STR_LIT("dcid"), event->receive.dcid);
    json_write_pair_c(out_, STR_LIT("first-octet"), event->receive.bytes[0]);
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->receive.bytes_len);
    break;
  }
  case 7: { // quicly:version_switch
    json_write_pair_n(out_, STR_LIT("type"), "version-switch");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->version_switch.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->version_switch.at);
    json_write_pair_c(out_, STR_LIT("new-version"), event->version_switch.new_version);
    break;
  }
  case 8: { // quicly:idle_timeout
    json_write_pair_n(out_, STR_LIT("type"), "idle-timeout");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->idle_timeout.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->idle_timeout.at);
    break;
  }
  case 9: { // quicly:stateless_reset_receive
    json_write_pair_n(out_, STR_LIT("type"), "stateless-reset-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stateless_reset_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stateless_reset_receive.at);
    break;
  }
  case 10: { // quicly:crypto_decrypt
    json_write_pair_n(out_, STR_LIT("type"), "crypto-decrypt");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_decrypt.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_decrypt.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->crypto_decrypt.pn);
    json_write_pair_c(out_, STR_LIT("decrypted-len"), event->crypto_decrypt.decrypted_len);
    break;
  }
  case 11: { // quicly:crypto_handshake
    json_write_pair_n(out_, STR_LIT("type"), "crypto-handshake");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_handshake.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_handshake.at);
    json_write_pair_c(out_, STR_LIT("ret"), event->crypto_handshake.ret);
    break;
  }
  case 12: { // quicly:crypto_update_secret
    json_write_pair_n(out_, STR_LIT("type"), "crypto-update-secret");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_update_secret.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_update_secret.at);
    json_write_pair_c(out_, STR_LIT("is-enc"), event->crypto_update_secret.is_enc);
    json_write_pair_c(out_, STR_LIT("epoch"), event->crypto_update_secret.epoch);
    json_write_pair_c(out_, STR_LIT("label"), event->crypto_update_secret.label);
    break;
  }
  case 13: { // quicly:crypto_send_key_update
    json_write_pair_n(out_, STR_LIT("type"), "crypto-send-key-update");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_send_key_update.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_send_key_update.at);
    json_write_pair_c(out_, STR_LIT("phase"), event->crypto_send_key_update.phase);
    break;
  }
  case 14: { // quicly:crypto_send_key_update_confirmed
    json_write_pair_n(out_, STR_LIT("type"), "crypto-send-key-update-confirmed");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_send_key_update_confirmed.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_send_key_update_confirmed.at);
    json_write_pair_c(out_, STR_LIT("next-pn"), event->crypto_send_key_update_confirmed.next_pn);
    break;
  }
  case 15: { // quicly:crypto_receive_key_update
    json_write_pair_n(out_, STR_LIT("type"), "crypto-receive-key-update");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_receive_key_update.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_receive_key_update.at);
    json_write_pair_c(out_, STR_LIT("phase"), event->crypto_receive_key_update.phase);
    break;
  }
  case 16: { // quicly:crypto_receive_key_update_prepare
    json_write_pair_n(out_, STR_LIT("type"), "crypto-receive-key-update-prepare");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_receive_key_update_prepare.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_receive_key_update_prepare.at);
    json_write_pair_c(out_, STR_LIT("phase"), event->crypto_receive_key_update_prepare.phase);
    break;
  }
  case 17: { // quicly:packet_prepare
    json_write_pair_n(out_, STR_LIT("type"), "packet-prepare");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_prepare.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_prepare.at);
    json_write_pair_c(out_, STR_LIT("first-octet"), event->packet_prepare.first_octet);
    json_write_pair_c(out_, STR_LIT("dcid"), event->packet_prepare.dcid);
    break;
  }
  case 18: { // quicly:packet_commit
    json_write_pair_n(out_, STR_LIT("type"), "packet-commit");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_commit.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_commit.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_commit.pn);
    json_write_pair_c(out_, STR_LIT("len"), event->packet_commit.len);
    json_write_pair_c(out_, STR_LIT("ack-only"), event->packet_commit.ack_only);
    break;
  }
  case 19: { // quicly:packet_acked
    json_write_pair_n(out_, STR_LIT("type"), "packet-acked");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_acked.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_acked.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_acked.pn);
    json_write_pair_c(out_, STR_LIT("is-late-ack"), event->packet_acked.is_late_ack);
    break;
  }
  case 20: { // quicly:packet_lost
    json_write_pair_n(out_, STR_LIT("type"), "packet-lost");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_lost.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_lost.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_lost.pn);
    break;
  }
  case 21: { // quicly:pto
    json_write_pair_n(out_, STR_LIT("type"), "pto");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->pto.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->pto.at);
    json_write_pair_c(out_, STR_LIT("inflight"), event->pto.inflight);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->pto.cwnd);
    json_write_pair_c(out_, STR_LIT("pto-count"), event->pto.pto_count);
    break;
  }
  case 22: { // quicly:cc_ack_received
    json_write_pair_n(out_, STR_LIT("type"), "cc-ack-received");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->cc_ack_received.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->cc_ack_received.at);
    json_write_pair_c(out_, STR_LIT("largest-acked"), event->cc_ack_received.largest_acked);
    json_write_pair_c(out_, STR_LIT("bytes-acked"), event->cc_ack_received.bytes_acked);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->cc_ack_received.cwnd);
    json_write_pair_c(out_, STR_LIT("inflight"), event->cc_ack_received.inflight);
    break;
  }
  case 23: { // quicly:cc_congestion
    json_write_pair_n(out_, STR_LIT("type"), "cc-congestion");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->cc_congestion.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->cc_congestion.at);
    json_write_pair_c(out_, STR_LIT("max-lost-pn"), event->cc_congestion.max_lost_pn);
    json_write_pair_c(out_, STR_LIT("inflight"), event->cc_congestion.inflight);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->cc_congestion.cwnd);
    break;
  }
  case 24: { // quicly:ack_send
    json_write_pair_n(out_, STR_LIT("type"), "ack-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ack_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ack_send.at);
    json_write_pair_c(out_, STR_LIT("largest-acked"), event->ack_send.largest_acked);
    json_write_pair_c(out_, STR_LIT("ack-delay"), event->ack_send.ack_delay);
    break;
  }
  case 25: { // quicly:ping_send
    json_write_pair_n(out_, STR_LIT("type"), "ping-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ping_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ping_send.at);
    break;
  }
  case 26: { // quicly:ping_receive
    json_write_pair_n(out_, STR_LIT("type"), "ping-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ping_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ping_receive.at);
    break;
  }
  case 27: { // quicly:transport_close_send
    json_write_pair_n(out_, STR_LIT("type"), "transport-close-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->transport_close_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->transport_close_send.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->transport_close_send.error_code);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->transport_close_send.frame_type);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->transport_close_send.reason_phrase);
    break;
  }
  case 28: { // quicly:transport_close_receive
    json_write_pair_n(out_, STR_LIT("type"), "transport-close-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->transport_close_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->transport_close_receive.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->transport_close_receive.error_code);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->transport_close_receive.frame_type);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->transport_close_receive.reason_phrase);
    break;
  }
  case 29: { // quicly:application_close_send
    json_write_pair_n(out_, STR_LIT("type"), "application-close-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->application_close_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->application_close_send.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->application_close_send.error_code);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->application_close_send.reason_phrase);
    break;
  }
  case 30: { // quicly:application_close_receive
    json_write_pair_n(out_, STR_LIT("type"), "application-close-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->application_close_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->application_close_receive.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->application_close_receive.error_code);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->application_close_receive.reason_phrase);
    break;
  }
  case 31: { // quicly:stream_send
    json_write_pair_n(out_, STR_LIT("type"), "stream-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_send.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_send.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_send.len);
    json_write_pair_c(out_, STR_LIT("is-fin"), event->stream_send.is_fin);
    break;
  }
  case 32: { // quicly:stream_receive
    json_write_pair_n(out_, STR_LIT("type"), "stream-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_receive.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_receive.len);
    break;
  }
  case 33: { // quicly:stream_acked
    json_write_pair_n(out_, STR_LIT("type"), "stream-acked");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_acked.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_acked.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_acked.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_acked.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_acked.len);
    break;
  }
  case 34: { // quicly:stream_lost
    json_write_pair_n(out_, STR_LIT("type"), "stream-lost");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_lost.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_lost.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_lost.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_lost.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_lost.len);
    break;
  }
  case 35: { // quicly:max_data_send
    json_write_pair_n(out_, STR_LIT("type"), "max-data-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_data_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_data_send.at);
    json_write_pair_c(out_, STR_LIT("limit"), event->max_data_send.limit);
    break;
  }
  case 36: { // quicly:max_data_receive
    json_write_pair_n(out_, STR_LIT("type"), "max-data-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_data_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_data_receive.at);
    json_write_pair_c(out_, STR_LIT("limit"), event->max_data_receive.limit);
    break;
  }
  case 37: { // quicly:max_streams_send
    json_write_pair_n(out_, STR_LIT("type"), "max-streams-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_streams_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_streams_send.at);
    json_write_pair_c(out_, STR_LIT("limit"), event->max_streams_send.limit);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->max_streams_send.is_unidirectional);
    break;
  }
  case 38: { // quicly:max_streams_receive
    json_write_pair_n(out_, STR_LIT("type"), "max-streams-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_streams_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_streams_receive.at);
    json_write_pair_c(out_, STR_LIT("limit"), event->max_streams_receive.limit);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->max_streams_receive.is_unidirectional);
    break;
  }
  case 39: { // quicly:max_stream_data_send
    json_write_pair_n(out_, STR_LIT("type"), "max-stream-data-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_stream_data_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_stream_data_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->max_stream_data_send.stream_id);
    json_write_pair_c(out_, STR_LIT("limit"), event->max_stream_data_send.limit);
    break;
  }
  case 40: { // quicly:max_stream_data_receive
    json_write_pair_n(out_, STR_LIT("type"), "max-stream-data-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_stream_data_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_stream_data_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->max_stream_data_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("limit"), event->max_stream_data_receive.limit);
    break;
  }
  case 41: { // quicly:new_token_send
    json_write_pair_n(out_, STR_LIT("type"), "new-token-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_token_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_token_send.at);
    json_write_pair_c(out_, STR_LIT("token"), event->new_token_send.token, (event->new_token_send.token_len < STR_LEN ? event->new_token_send.token_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("token-len"), event->new_token_send.token_len);
    json_write_pair_c(out_, STR_LIT("generation"), event->new_token_send.generation);
    break;
  }
  case 42: { // quicly:new_token_acked
    json_write_pair_n(out_, STR_LIT("type"), "new-token-acked");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_token_acked.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_token_acked.at);
    json_write_pair_c(out_, STR_LIT("generation"), event->new_token_acked.generation);
    break;
  }
  case 43: { // quicly:new_token_receive
    json_write_pair_n(out_, STR_LIT("type"), "new-token-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_token_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_token_receive.at);
    json_write_pair_c(out_, STR_LIT("token"), event->new_token_receive.token, (event->new_token_receive.token_len < STR_LEN ? event->new_token_receive.token_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("token-len"), event->new_token_receive.token_len);
    break;
  }
  case 44: { // quicly:handshake_done_send
    json_write_pair_n(out_, STR_LIT("type"), "handshake-done-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->handshake_done_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->handshake_done_send.at);
    break;
  }
  case 45: { // quicly:handshake_done_receive
    json_write_pair_n(out_, STR_LIT("type"), "handshake-done-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->handshake_done_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->handshake_done_receive.at);
    break;
  }
  case 46: { // quicly:streams_blocked_send
    json_write_pair_n(out_, STR_LIT("type"), "streams-blocked-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->streams_blocked_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->streams_blocked_send.at);
    json_write_pair_c(out_, STR_LIT("limit"), event->streams_blocked_send.limit);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->streams_blocked_send.is_unidirectional);
    break;
  }
  case 47: { // quicly:streams_blocked_receive
    json_write_pair_n(out_, STR_LIT("type"), "streams-blocked-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->streams_blocked_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->streams_blocked_receive.at);
    json_write_pair_c(out_, STR_LIT("limit"), event->streams_blocked_receive.limit);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->streams_blocked_receive.is_unidirectional);
    break;
  }
  case 48: { // quicly:new_connection_id_send
    json_write_pair_n(out_, STR_LIT("type"), "new-connection-id-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_connection_id_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_connection_id_send.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->new_connection_id_send.sequence);
    json_write_pair_c(out_, STR_LIT("retire-prior-to"), event->new_connection_id_send.retire_prior_to);
    json_write_pair_c(out_, STR_LIT("cid"), event->new_connection_id_send.cid);
    json_write_pair_c(out_, STR_LIT("stateless-reset-token"), event->new_connection_id_send.stateless_reset_token);
    break;
  }
  case 49: { // quicly:new_connection_id_receive
    json_write_pair_n(out_, STR_LIT("type"), "new-connection-id-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_connection_id_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_connection_id_receive.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->new_connection_id_receive.sequence);
    json_write_pair_c(out_, STR_LIT("retire-prior-to"), event->new_connection_id_receive.retire_prior_to);
    json_write_pair_c(out_, STR_LIT("cid"), event->new_connection_id_receive.cid);
    json_write_pair_c(out_, STR_LIT("stateless-reset-token"), event->new_connection_id_receive.stateless_reset_token);
    break;
  }
  case 50: { // quicly:retire_connection_id_send
    json_write_pair_n(out_, STR_LIT("type"), "retire-connection-id-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->retire_connection_id_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->retire_connection_id_send.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->retire_connection_id_send.sequence);
    break;
  }
  case 51: { // quicly:retire_connection_id_receive
    json_write_pair_n(out_, STR_LIT("type"), "retire-connection-id-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->retire_connection_id_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->retire_connection_id_receive.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->retire_connection_id_receive.sequence);
    break;
  }
  case 52: { // quicly:data_blocked_send
    json_write_pair_n(out_, STR_LIT("type"), "data-blocked-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->data_blocked_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->data_blocked_send.at);
    json_write_pair_c(out_, STR_LIT("off"), event->data_blocked_send.off);
    break;
  }
  case 53: { // quicly:data_blocked_receive
    json_write_pair_n(out_, STR_LIT("type"), "data-blocked-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->data_blocked_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->data_blocked_receive.at);
    json_write_pair_c(out_, STR_LIT("off"), event->data_blocked_receive.off);
    break;
  }
  case 54: { // quicly:stream_data_blocked_send
    json_write_pair_n(out_, STR_LIT("type"), "stream-data-blocked-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_data_blocked_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_data_blocked_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_data_blocked_send.stream_id);
    json_write_pair_c(out_, STR_LIT("limit"), event->stream_data_blocked_send.limit);
    break;
  }
  case 55: { // quicly:stream_data_blocked_receive
    json_write_pair_n(out_, STR_LIT("type"), "stream-data-blocked-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_data_blocked_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_data_blocked_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_data_blocked_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("limit"), event->stream_data_blocked_receive.limit);
    break;
  }
  case 56: { // quicly:datagram_send
    json_write_pair_n(out_, STR_LIT("type"), "datagram-send");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->datagram_send.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->datagram_send.at);
    json_write_pair_c(out_, STR_LIT("payload"), event->datagram_send.payload, (event->datagram_send.payload_len < STR_LEN ? event->datagram_send.payload_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("payload-len"), event->datagram_send.payload_len);
    break;
  }
  case 57: { // quicly:datagram_receive
    json_write_pair_n(out_, STR_LIT("type"), "datagram-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->datagram_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->datagram_receive.at);
    json_write_pair_c(out_, STR_LIT("payload"), event->datagram_receive.payload, (event->datagram_receive.payload_len < STR_LEN ? event->datagram_receive.payload_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("payload-len"), event->datagram_receive.payload_len);
    break;
  }
  case 58: { // quicly:ack_frequency_receive
    json_write_pair_n(out_, STR_LIT("type"), "ack-frequency-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ack_frequency_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ack_frequency_receive.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->ack_frequency_receive.sequence);
    json_write_pair_c(out_, STR_LIT("packet-tolerance"), event->ack_frequency_receive.packet_tolerance);
    json_write_pair_c(out_, STR_LIT("max-ack-delay"), event->ack_frequency_receive.max_ack_delay);
    json_write_pair_c(out_, STR_LIT("ignore-order"), event->ack_frequency_receive.ignore_order);
    break;
  }
  case 59: { // quicly:quictrace_sent
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-sent");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_sent.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_sent.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->quictrace_sent.pn);
    json_write_pair_c(out_, STR_LIT("len"), event->quictrace_sent.len);
    json_write_pair_c(out_, STR_LIT("packet-type"), event->quictrace_sent.packet_type);
    break;
  }
  case 60: { // quicly:quictrace_recv
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-recv");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_recv.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_recv.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->quictrace_recv.pn);
    break;
  }
  case 61: { // quicly:quictrace_send_stream
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-send-stream");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_send_stream.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_send_stream.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->quictrace_send_stream.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->quictrace_send_stream.off);
    json_write_pair_c(out_, STR_LIT("len"), event->quictrace_send_stream.len);
    json_write_pair_c(out_, STR_LIT("fin"), event->quictrace_send_stream.fin);
    break;
  }
  case 62: { // quicly:quictrace_recv_stream
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-recv-stream");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_recv_stream.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_recv_stream.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->quictrace_recv_stream.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->quictrace_recv_stream.off);
    json_write_pair_c(out_, STR_LIT("len"), event->quictrace_recv_stream.len);
    json_write_pair_c(out_, STR_LIT("fin"), event->quictrace_recv_stream.fin);
    break;
  }
  case 63: { // quicly:quictrace_recv_ack
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-recv-ack");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_recv_ack.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_recv_ack.at);
    json_write_pair_c(out_, STR_LIT("ack-block-begin"), event->quictrace_recv_ack.ack_block_begin);
    json_write_pair_c(out_, STR_LIT("ack-block-end"), event->quictrace_recv_ack.ack_block_end);
    break;
  }
  case 64: { // quicly:quictrace_recv_ack_delay
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-recv-ack-delay");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_recv_ack_delay.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_recv_ack_delay.at);
    json_write_pair_c(out_, STR_LIT("ack-delay"), event->quictrace_recv_ack_delay.ack_delay);
    break;
  }
  case 65: { // quicly:quictrace_lost
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-lost");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_lost.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_lost.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->quictrace_lost.pn);
    break;
  }
  case 66: { // quicly:quictrace_cc_ack
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-cc-ack");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_cc_ack.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_cc_ack.at);
    json_write_pair_c(out_, STR_LIT("min-rtt"), event->quictrace_cc_ack.minimum);
    json_write_pair_c(out_, STR_LIT("smoothed-rtt"), event->quictrace_cc_ack.smoothed);
    json_write_pair_c(out_, STR_LIT("variance-rtt"), event->quictrace_cc_ack.variance);
    json_write_pair_c(out_, STR_LIT("latest-rtt"), event->quictrace_cc_ack.latest);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->quictrace_cc_ack.cwnd);
    json_write_pair_c(out_, STR_LIT("inflight"), event->quictrace_cc_ack.inflight);
    break;
  }
  case 67: { // quicly:quictrace_cc_lost
    json_write_pair_n(out_, STR_LIT("type"), "quictrace-cc-lost");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_cc_lost.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_cc_lost.at);
    json_write_pair_c(out_, STR_LIT("min-rtt"), event->quictrace_cc_lost.minimum);
    json_write_pair_c(out_, STR_LIT("smoothed-rtt"), event->quictrace_cc_lost.smoothed);
    json_write_pair_c(out_, STR_LIT("variance-rtt"), event->quictrace_cc_lost.variance);
    json_write_pair_c(out_, STR_LIT("latest-rtt"), event->quictrace_cc_lost.latest);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->quictrace_cc_lost.cwnd);
    json_write_pair_c(out_, STR_LIT("inflight"), event->quictrace_cc_lost.inflight);
    break;
  }
  case 68: { // quicly:stream_on_open
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-open");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_open.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_open.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_open.stream_id);
    break;
  }
  case 69: { // quicly:stream_on_destroy
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-destroy");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_destroy.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_destroy.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_destroy.stream_id);
    json_write_pair_c(out_, STR_LIT("err"), event->stream_on_destroy.err);
    break;
  }
  case 70: { // quicly:stream_on_send_shift
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-send-shift");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_send_shift.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_send_shift.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_send_shift.stream_id);
    json_write_pair_c(out_, STR_LIT("delta"), event->stream_on_send_shift.delta);
    break;
  }
  case 71: { // quicly:stream_on_send_emit
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-send-emit");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_send_emit.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_send_emit.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_send_emit.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_on_send_emit.off);
    json_write_pair_c(out_, STR_LIT("capacity"), event->stream_on_send_emit.capacity);
    break;
  }
  case 72: { // quicly:stream_on_send_stop
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-send-stop");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_send_stop.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_send_stop.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_send_stop.stream_id);
    json_write_pair_c(out_, STR_LIT("err"), event->stream_on_send_stop.err);
    break;
  }
  case 73: { // quicly:stream_on_receive
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_receive.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_on_receive.off);
    json_write_pair_c(out_, STR_LIT("src"), event->stream_on_receive.src, (event->stream_on_receive.src_len < STR_LEN ? event->stream_on_receive.src_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("src-len"), event->stream_on_receive.src_len);
    break;
  }
  case 74: { // quicly:stream_on_receive_reset
    json_write_pair_n(out_, STR_LIT("type"), "stream-on-receive-reset");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_receive_reset.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_receive_reset.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_receive_reset.stream_id);
    json_write_pair_c(out_, STR_LIT("err"), event->stream_on_receive_reset.err);
    break;
  }
  case 76: { // quicly:conn_stats
    json_write_pair_n(out_, STR_LIT("type"), "conn-stats");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->conn_stats.master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->conn_stats.at);
    json_write_pair_c(out_, STR_LIT("size"), event->conn_stats.size);
    break;
  }
  case 77: { // h2o:receive_request
    json_write_pair_n(out_, STR_LIT("type"), "receive-request");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->receive_request.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->receive_request.req_id);
    json_write_pair_c(out_, STR_LIT("http-version"), event->receive_request.http_version);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 78: { // h2o:receive_request_header
    json_write_pair_n(out_, STR_LIT("type"), "receive-request-header");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->receive_request_header.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->receive_request_header.req_id);
    json_write_pair_c(out_, STR_LIT("name"), event->receive_request_header.name);
    json_write_pair_c(out_, STR_LIT("name-len"), event->receive_request_header.name_len);
    json_write_pair_c(out_, STR_LIT("value"), event->receive_request_header.value);
    json_write_pair_c(out_, STR_LIT("value-len"), event->receive_request_header.value_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 79: { // h2o:send_response
    json_write_pair_n(out_, STR_LIT("type"), "send-response");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->send_response.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->send_response.req_id);
    json_write_pair_c(out_, STR_LIT("status"), event->send_response.status);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 80: { // h2o:send_response_header
    json_write_pair_n(out_, STR_LIT("type"), "send-response-header");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->send_response_header.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->send_response_header.req_id);
    json_write_pair_c(out_, STR_LIT("name"), event->send_response_header.name);
    json_write_pair_c(out_, STR_LIT("name-len"), event->send_response_header.name_len);
    json_write_pair_c(out_, STR_LIT("value"), event->send_response_header.value);
    json_write_pair_c(out_, STR_LIT("value-len"), event->send_response_header.value_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 81: { // h2o:h1_accept
    json_write_pair_n(out_, STR_LIT("type"), "h1-accept");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h1_accept.conn_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 82: { // h2o:h1_close
    json_write_pair_n(out_, STR_LIT("type"), "h1-close");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h1_close.conn_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 83: { // h2o:h2_unknown_frame_type
    json_write_pair_n(out_, STR_LIT("type"), "h2-unknown-frame-type");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h2_unknown_frame_type.conn_id);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->h2_unknown_frame_type.frame_type);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 84: { // h2o:h3s_accept
    json_write_pair_n(out_, STR_LIT("type"), "h3s-accept");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h3s_accept.conn_id);
    json_write_pair_c(out_, STR_LIT("conn"), event->h3s_accept.master_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 85: { // h2o:h3s_destroy
    json_write_pair_n(out_, STR_LIT("type"), "h3s-destroy");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h3s_destroy.conn_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 86: { // h2o:h3s_stream_set_state
    json_write_pair_n(out_, STR_LIT("type"), "h3s-stream-set-state");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h3s_stream_set_state.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->h3s_stream_set_state.req_id);
    json_write_pair_c(out_, STR_LIT("state"), event->h3s_stream_set_state.state);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 87: { // h2o:h3_frame_receive
    json_write_pair_n(out_, STR_LIT("type"), "h3-frame-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->h3_frame_receive.frame_type);
    json_write_pair_c(out_, STR_LIT("bytes"), event->h3_frame_receive.bytes, (event->h3_frame_receive.bytes_len < STR_LEN ? event->h3_frame_receive.bytes_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_frame_receive.bytes_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 88: { // h2o:h3_packet_receive
    json_write_pair_n(out_, STR_LIT("type"), "h3-packet-receive");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("dest"), event->h3_packet_receive.dest);
    json_write_pair_c(out_, STR_LIT("src"), event->h3_packet_receive.src);
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_packet_receive.bytes_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 89: { // h2o:h3_packet_forward
    json_write_pair_n(out_, STR_LIT("type"), "h3-packet-forward");
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("dest"), event->h3_packet_forward.dest);
    json_write_pair_c(out_, STR_LIT("src"), event->h3_packet_forward.src);
    json_write_pair_c(out_, STR_LIT("num-packets"), event->h3_packet_forward.num_packets);
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_packet_forward.num_bytes);
    json_write_pair_c(out_, STR_LIT("fd"), event->h3_packet_forward.fd);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }

  default:
    std::abort();
  }

  fprintf(out_, "}\n");
}


std::string h2o_raw_tracer::bpf_text() {
  // language=c
  return gen_bpf_header() + R"(

#include <linux/sched.h>

#define STR_LEN 64

typedef union h2olog_address_t {
  uint8_t sa[sizeof_sockaddr];
  uint8_t sin[sizeof_sockaddr_in];
  uint8_t sin6[sizeof_sockaddr_in6];
} h2olog_address_t;;


struct event_t {
  uint8_t id;

  union {
    struct { // quicly:connect
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      char dcid[STR_LEN];
    } accept;
    struct { // quicly:free
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[1];
      size_t bytes_len;
    } receive;
    struct { // quicly:version_switch
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_decrypt
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      size_t decrypted_len;
    } crypto_decrypt;
    struct { // quicly:crypto_handshake
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t phase;
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_prepare
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_commit
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      int ack_only;
    } packet_commit;
    struct { // quicly:packet_acked
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      int is_late_ack;
    } packet_acked;
    struct { // quicly:packet_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
    } packet_lost;
    struct { // quicly:pto
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:ack_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t largest_acked;
      uint64_t ack_delay;
    } ack_send;
    struct { // quicly:ping_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } ping_send;
    struct { // quicly:ping_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } ping_receive;
    struct { // quicly:transport_close_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:max_data_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
    } max_data_send;
    struct { // quicly:max_data_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
    } max_data_receive;
    struct { // quicly:max_streams_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t limit;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:new_connection_id_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_send;
    struct { // quicly:new_connection_id_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_receive;
    struct { // quicly:retire_connection_id_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_send;
    struct { // quicly:retire_connection_id_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_receive;
    struct { // quicly:data_blocked_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_send;
    struct { // quicly:data_blocked_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_send;
    struct { // quicly:stream_data_blocked_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_receive;
    struct { // quicly:datagram_send
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t payload[STR_LEN];
      size_t payload_len;
    } datagram_send;
    struct { // quicly:datagram_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint8_t payload[STR_LEN];
      size_t payload_len;
    } datagram_receive;
    struct { // quicly:ack_frequency_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t packet_tolerance;
      uint64_t max_ack_delay;
      int ignore_order;
    } ack_frequency_receive;
    struct { // quicly:quictrace_sent
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
    } quictrace_sent;
    struct { // quicly:quictrace_recv
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_recv;
    struct { // quicly:quictrace_send_stream
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_recv_ack
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } quictrace_recv_ack;
    struct { // quicly:quictrace_recv_ack_delay
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      int64_t ack_delay;
    } quictrace_recv_ack_delay;
    struct { // quicly:quictrace_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_lost;
    struct { // quicly:quictrace_cc_ack
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum minimum;
      typeof_quicly_rtt_t__smoothed smoothed;
      typeof_quicly_rtt_t__variance variance;
      typeof_quicly_rtt_t__latest latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum minimum;
      typeof_quicly_rtt_t__smoothed smoothed;
      typeof_quicly_rtt_t__variance variance;
      typeof_quicly_rtt_t__latest latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // quicly:stream_on_open
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
    } stream_on_open;
    struct { // quicly:stream_on_destroy
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      int err;
    } stream_on_destroy;
    struct { // quicly:stream_on_send_shift
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      size_t delta;
    } stream_on_send_shift;
    struct { // quicly:stream_on_send_emit
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      size_t off;
      size_t capacity;
    } stream_on_send_emit;
    struct { // quicly:stream_on_send_stop
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      int err;
    } stream_on_send_stop;
    struct { // quicly:stream_on_receive
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      size_t off;
      uint8_t src[STR_LEN];
      size_t src_len;
    } stream_on_receive;
    struct { // quicly:stream_on_receive_reset
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_id;
      int err;
    } stream_on_receive_reset;
    struct { // quicly:conn_stats
      typeof_st_quicly_conn_t__master_id master_id;
      int64_t at;
      size_t size;
    } conn_stats;
    struct { // h2o:receive_request
      uint64_t conn_id;
      uint64_t req_id;
      int http_version;
    } receive_request;
    struct { // h2o:receive_request_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
    } receive_request_header;
    struct { // h2o:send_response
      uint64_t conn_id;
      uint64_t req_id;
      int status;
    } send_response;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
    } send_response_header;
    struct { // h2o:h1_accept
      uint64_t conn_id;
    } h1_accept;
    struct { // h2o:h1_close
      uint64_t conn_id;
    } h1_close;
    struct { // h2o:h2_unknown_frame_type
      uint64_t conn_id;
      uint8_t frame_type;
    } h2_unknown_frame_type;
    struct { // h2o:h3s_accept
      uint64_t conn_id;
      typeof_st_quicly_conn_t__master_id master_id;
    } h3s_accept;
    struct { // h2o:h3s_destroy
      uint64_t conn_id;
    } h3s_destroy;
    struct { // h2o:h3s_stream_set_state
      uint64_t conn_id;
      uint64_t req_id;
      unsigned state;
    } h3s_stream_set_state;
    struct { // h2o:h3_frame_receive
      uint64_t frame_type;
      uint8_t bytes[STR_LEN];
      size_t bytes_len;
    } h3_frame_receive;
    struct { // h2o:h3_packet_receive
      h2olog_address_t dest;
      h2olog_address_t src;
      size_t bytes_len;
    } h3_packet_receive;
    struct { // h2o:h3_packet_forward
      h2olog_address_t dest;
      h2olog_address_t src;
      size_t num_packets;
      size_t num_bytes;
      int fd;
    } h3_packet_forward;

    };
  };
  
BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);

// tracepoint sched:sched_process_exit
int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  pid_t h2o_pid = task->tgid;
  pid_t h2o_tid = task->pid;
  if (!(h2o_pid == H2OLOG_H2O_PID && h2o_tid == H2OLOG_H2O_PID)) {
    return 0;
  }
  struct event_t ev = { .id = 1 };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

// quicly:connect
int trace_quicly__connect(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 2 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.connect.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.connect.at);
  // uint32_t version
  bpf_usdt_readarg(3, ctx, &event.connect.version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__connect\n");

  return 0;
}
// quicly:accept
int trace_quicly__accept(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 3 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.accept.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.accept.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.accept.dcid, sizeof(event.accept.dcid), buf);
  // struct st_quicly_address_token_plaintext_t * address_token
  // (no fields in st_quicly_address_token_plaintext_t)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__accept\n");

  return 0;
}
// quicly:free
int trace_quicly__free(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 4 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.free.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.free.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__free\n");

  return 0;
}
// quicly:send
int trace_quicly__send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 5 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.send.at);
  // int state
  bpf_usdt_readarg(3, ctx, &event.send.state);
  // const char * dcid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.send.dcid, sizeof(event.send.dcid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__send\n");

  return 0;
}
// quicly:receive
int trace_quicly__receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 6 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.receive.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.receive.dcid, sizeof(event.receive.dcid), buf);
  // const void * bytes
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.receive.bytes, sizeof(event.receive.bytes), buf);
  // size_t bytes_len
  bpf_usdt_readarg(5, ctx, &event.receive.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__receive\n");

  return 0;
}
// quicly:version_switch
int trace_quicly__version_switch(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 7 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.version_switch.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.version_switch.at);
  // uint32_t new_version
  bpf_usdt_readarg(3, ctx, &event.version_switch.new_version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__version_switch\n");

  return 0;
}
// quicly:idle_timeout
int trace_quicly__idle_timeout(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 8 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.idle_timeout.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.idle_timeout.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__idle_timeout\n");

  return 0;
}
// quicly:stateless_reset_receive
int trace_quicly__stateless_reset_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 9 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stateless_reset_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stateless_reset_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stateless_reset_receive\n");

  return 0;
}
// quicly:crypto_decrypt
int trace_quicly__crypto_decrypt(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 10 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_decrypt.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_decrypt.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.crypto_decrypt.pn);
  // const void * decrypted (ignored)
  // size_t decrypted_len
  bpf_usdt_readarg(5, ctx, &event.crypto_decrypt.decrypted_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_decrypt\n");

  return 0;
}
// quicly:crypto_handshake
int trace_quicly__crypto_handshake(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 11 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_handshake.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_handshake.at);
  // int ret
  bpf_usdt_readarg(3, ctx, &event.crypto_handshake.ret);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_handshake\n");

  return 0;
}
// quicly:crypto_update_secret
int trace_quicly__crypto_update_secret(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 12 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_update_secret.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_update_secret.at);
  // int is_enc
  bpf_usdt_readarg(3, ctx, &event.crypto_update_secret.is_enc);
  // uint8_t epoch
  bpf_usdt_readarg(4, ctx, &event.crypto_update_secret.epoch);
  // const char * label
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.crypto_update_secret.label, sizeof(event.crypto_update_secret.label), buf);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_update_secret\n");

  return 0;
}
// quicly:crypto_send_key_update
int trace_quicly__crypto_send_key_update(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 13 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_send_key_update.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_send_key_update\n");

  return 0;
}
// quicly:crypto_send_key_update_confirmed
int trace_quicly__crypto_send_key_update_confirmed(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 14 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_send_key_update_confirmed.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update_confirmed.at);
  // uint64_t next_pn
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update_confirmed.next_pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_send_key_update_confirmed\n");

  return 0;
}
// quicly:crypto_receive_key_update
int trace_quicly__crypto_receive_key_update(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 15 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_receive_key_update.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_receive_key_update\n");

  return 0;
}
// quicly:crypto_receive_key_update_prepare
int trace_quicly__crypto_receive_key_update_prepare(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 16 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_receive_key_update_prepare.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update_prepare.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update_prepare.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_receive_key_update_prepare\n");

  return 0;
}
// quicly:packet_prepare
int trace_quicly__packet_prepare(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 17 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_prepare.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_prepare.at);
  // uint8_t first_octet
  bpf_usdt_readarg(3, ctx, &event.packet_prepare.first_octet);
  // const char * dcid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.packet_prepare.dcid, sizeof(event.packet_prepare.dcid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_prepare\n");

  return 0;
}
// quicly:packet_commit
int trace_quicly__packet_commit(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 18 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_commit.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_commit.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_commit.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.packet_commit.len);
  // int ack_only
  bpf_usdt_readarg(5, ctx, &event.packet_commit.ack_only);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_commit\n");

  return 0;
}
// quicly:packet_acked
int trace_quicly__packet_acked(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 19 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_acked.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_acked.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_acked.pn);
  // int is_late_ack
  bpf_usdt_readarg(4, ctx, &event.packet_acked.is_late_ack);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_acked\n");

  return 0;
}
// quicly:packet_lost
int trace_quicly__packet_lost(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 20 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_lost.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_lost.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_lost\n");

  return 0;
}
// quicly:pto
int trace_quicly__pto(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 21 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.pto.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.pto.at);
  // size_t inflight
  bpf_usdt_readarg(3, ctx, &event.pto.inflight);
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.pto.cwnd);
  // int8_t pto_count
  bpf_usdt_readarg(5, ctx, &event.pto.pto_count);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__pto\n");

  return 0;
}
// quicly:cc_ack_received
int trace_quicly__cc_ack_received(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 22 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.cc_ack_received.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.cc_ack_received.at);
  // uint64_t largest_acked
  bpf_usdt_readarg(3, ctx, &event.cc_ack_received.largest_acked);
  // size_t bytes_acked
  bpf_usdt_readarg(4, ctx, &event.cc_ack_received.bytes_acked);
  // uint32_t cwnd
  bpf_usdt_readarg(5, ctx, &event.cc_ack_received.cwnd);
  // size_t inflight
  bpf_usdt_readarg(6, ctx, &event.cc_ack_received.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__cc_ack_received\n");

  return 0;
}
// quicly:cc_congestion
int trace_quicly__cc_congestion(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 23 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.cc_congestion.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.cc_congestion.at);
  // uint64_t max_lost_pn
  bpf_usdt_readarg(3, ctx, &event.cc_congestion.max_lost_pn);
  // size_t inflight
  bpf_usdt_readarg(4, ctx, &event.cc_congestion.inflight);
  // uint32_t cwnd
  bpf_usdt_readarg(5, ctx, &event.cc_congestion.cwnd);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__cc_congestion\n");

  return 0;
}
// quicly:ack_send
int trace_quicly__ack_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 24 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ack_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ack_send.at);
  // uint64_t largest_acked
  bpf_usdt_readarg(3, ctx, &event.ack_send.largest_acked);
  // uint64_t ack_delay
  bpf_usdt_readarg(4, ctx, &event.ack_send.ack_delay);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ack_send\n");

  return 0;
}
// quicly:ping_send
int trace_quicly__ping_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 25 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ping_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ping_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ping_send\n");

  return 0;
}
// quicly:ping_receive
int trace_quicly__ping_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 26 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ping_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ping_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ping_receive\n");

  return 0;
}
// quicly:transport_close_send
int trace_quicly__transport_close_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 27 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.transport_close_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.transport_close_send.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.transport_close_send.error_code);
  // uint64_t frame_type
  bpf_usdt_readarg(4, ctx, &event.transport_close_send.frame_type);
  // const char * reason_phrase
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.transport_close_send.reason_phrase, sizeof(event.transport_close_send.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__transport_close_send\n");

  return 0;
}
// quicly:transport_close_receive
int trace_quicly__transport_close_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 28 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.transport_close_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.transport_close_receive.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.transport_close_receive.error_code);
  // uint64_t frame_type
  bpf_usdt_readarg(4, ctx, &event.transport_close_receive.frame_type);
  // const char * reason_phrase
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.transport_close_receive.reason_phrase, sizeof(event.transport_close_receive.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__transport_close_receive\n");

  return 0;
}
// quicly:application_close_send
int trace_quicly__application_close_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 29 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.application_close_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.application_close_send.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.application_close_send.error_code);
  // const char * reason_phrase
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.application_close_send.reason_phrase, sizeof(event.application_close_send.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__application_close_send\n");

  return 0;
}
// quicly:application_close_receive
int trace_quicly__application_close_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 30 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.application_close_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.application_close_receive.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.application_close_receive.error_code);
  // const char * reason_phrase
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.application_close_receive.reason_phrase, sizeof(event.application_close_receive.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__application_close_receive\n");

  return 0;
}
// quicly:stream_send
int trace_quicly__stream_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 31 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_send.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_send.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_send.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_send.len);
  // int is_fin
  bpf_usdt_readarg(6, ctx, &event.stream_send.is_fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_send\n");

  return 0;
}
// quicly:stream_receive
int trace_quicly__stream_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 32 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_receive.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_receive.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_receive.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_receive.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_receive\n");

  return 0;
}
// quicly:stream_acked
int trace_quicly__stream_acked(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 33 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_acked.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_acked.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_acked.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_acked.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_acked.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_acked\n");

  return 0;
}
// quicly:stream_lost
int trace_quicly__stream_lost(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 34 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_lost.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_lost.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_lost.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_lost.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_lost.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_lost\n");

  return 0;
}
// quicly:max_data_send
int trace_quicly__max_data_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 35 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_data_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_data_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_data_send\n");

  return 0;
}
// quicly:max_data_receive
int trace_quicly__max_data_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 36 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_data_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_data_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_data_receive\n");

  return 0;
}
// quicly:max_streams_send
int trace_quicly__max_streams_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 37 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_streams_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_streams_send.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_streams_send\n");

  return 0;
}
// quicly:max_streams_receive
int trace_quicly__max_streams_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 38 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_streams_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_streams_receive.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_streams_receive\n");

  return 0;
}
// quicly:max_stream_data_send
int trace_quicly__max_stream_data_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 39 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_stream_data_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_send.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.max_stream_data_send.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_stream_data_send\n");

  return 0;
}
// quicly:max_stream_data_receive
int trace_quicly__max_stream_data_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 40 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_stream_data_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.max_stream_data_receive.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_stream_data_receive\n");

  return 0;
}
// quicly:new_token_send
int trace_quicly__new_token_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 41 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_token_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_send.at);
  // uint8_t * token
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.new_token_send.token, sizeof(event.new_token_send.token), buf);
  // size_t token_len
  bpf_usdt_readarg(4, ctx, &event.new_token_send.token_len);
  // uint64_t generation
  bpf_usdt_readarg(5, ctx, &event.new_token_send.generation);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__new_token_send\n");

  return 0;
}
// quicly:new_token_acked
int trace_quicly__new_token_acked(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 42 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_token_acked.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_acked.at);
  // uint64_t generation
  bpf_usdt_readarg(3, ctx, &event.new_token_acked.generation);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__new_token_acked\n");

  return 0;
}
// quicly:new_token_receive
int trace_quicly__new_token_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 43 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_token_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_receive.at);
  // uint8_t * token
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.new_token_receive.token, sizeof(event.new_token_receive.token), buf);
  // size_t token_len
  bpf_usdt_readarg(4, ctx, &event.new_token_receive.token_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__new_token_receive\n");

  return 0;
}
// quicly:handshake_done_send
int trace_quicly__handshake_done_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 44 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.handshake_done_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__handshake_done_send\n");

  return 0;
}
// quicly:handshake_done_receive
int trace_quicly__handshake_done_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 45 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.handshake_done_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__handshake_done_receive\n");

  return 0;
}
// quicly:streams_blocked_send
int trace_quicly__streams_blocked_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 46 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.streams_blocked_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_send.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__streams_blocked_send\n");

  return 0;
}
// quicly:streams_blocked_receive
int trace_quicly__streams_blocked_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 47 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.streams_blocked_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_receive.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__streams_blocked_receive\n");

  return 0;
}
// quicly:new_connection_id_send
int trace_quicly__new_connection_id_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 48 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_connection_id_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_connection_id_send.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.new_connection_id_send.sequence);
  // uint64_t retire_prior_to
  bpf_usdt_readarg(4, ctx, &event.new_connection_id_send.retire_prior_to);
  // const char * cid
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_send.cid, sizeof(event.new_connection_id_send.cid), buf);
  // const char * stateless_reset_token
  bpf_usdt_readarg(6, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_send.stateless_reset_token, sizeof(event.new_connection_id_send.stateless_reset_token), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__new_connection_id_send\n");

  return 0;
}
// quicly:new_connection_id_receive
int trace_quicly__new_connection_id_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 49 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_connection_id_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_connection_id_receive.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.new_connection_id_receive.sequence);
  // uint64_t retire_prior_to
  bpf_usdt_readarg(4, ctx, &event.new_connection_id_receive.retire_prior_to);
  // const char * cid
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_receive.cid, sizeof(event.new_connection_id_receive.cid), buf);
  // const char * stateless_reset_token
  bpf_usdt_readarg(6, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_receive.stateless_reset_token, sizeof(event.new_connection_id_receive.stateless_reset_token), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__new_connection_id_receive\n");

  return 0;
}
// quicly:retire_connection_id_send
int trace_quicly__retire_connection_id_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 50 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.retire_connection_id_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.retire_connection_id_send.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.retire_connection_id_send.sequence);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__retire_connection_id_send\n");

  return 0;
}
// quicly:retire_connection_id_receive
int trace_quicly__retire_connection_id_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 51 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.retire_connection_id_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.retire_connection_id_receive.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.retire_connection_id_receive.sequence);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__retire_connection_id_receive\n");

  return 0;
}
// quicly:data_blocked_send
int trace_quicly__data_blocked_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 52 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.data_blocked_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.data_blocked_send.at);
  // uint64_t off
  bpf_usdt_readarg(3, ctx, &event.data_blocked_send.off);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__data_blocked_send\n");

  return 0;
}
// quicly:data_blocked_receive
int trace_quicly__data_blocked_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 53 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.data_blocked_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.data_blocked_receive.at);
  // uint64_t off
  bpf_usdt_readarg(3, ctx, &event.data_blocked_receive.off);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__data_blocked_receive\n");

  return 0;
}
// quicly:stream_data_blocked_send
int trace_quicly__stream_data_blocked_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 54 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_data_blocked_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_data_blocked_send.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_data_blocked_send.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.stream_data_blocked_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_data_blocked_send\n");

  return 0;
}
// quicly:stream_data_blocked_receive
int trace_quicly__stream_data_blocked_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 55 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_data_blocked_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_data_blocked_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_data_blocked_receive.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.stream_data_blocked_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_data_blocked_receive\n");

  return 0;
}
// quicly:datagram_send
int trace_quicly__datagram_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 56 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.datagram_send.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.datagram_send.at);
  // const void * payload
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.datagram_send.payload, sizeof(event.datagram_send.payload), buf);
  // size_t payload_len
  bpf_usdt_readarg(4, ctx, &event.datagram_send.payload_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__datagram_send\n");

  return 0;
}
// quicly:datagram_receive
int trace_quicly__datagram_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 57 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.datagram_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.datagram_receive.at);
  // const void * payload
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.datagram_receive.payload, sizeof(event.datagram_receive.payload), buf);
  // size_t payload_len
  bpf_usdt_readarg(4, ctx, &event.datagram_receive.payload_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__datagram_receive\n");

  return 0;
}
// quicly:ack_frequency_receive
int trace_quicly__ack_frequency_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 58 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ack_frequency_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ack_frequency_receive.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.ack_frequency_receive.sequence);
  // uint64_t packet_tolerance
  bpf_usdt_readarg(4, ctx, &event.ack_frequency_receive.packet_tolerance);
  // uint64_t max_ack_delay
  bpf_usdt_readarg(5, ctx, &event.ack_frequency_receive.max_ack_delay);
  // int ignore_order
  bpf_usdt_readarg(6, ctx, &event.ack_frequency_receive.ignore_order);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ack_frequency_receive\n");

  return 0;
}
// quicly:quictrace_sent
int trace_quicly__quictrace_sent(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 59 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_sent.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_sent.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_sent.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.quictrace_sent.len);
  // uint8_t packet_type
  bpf_usdt_readarg(5, ctx, &event.quictrace_sent.packet_type);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_sent\n");

  return 0;
}
// quicly:quictrace_recv
int trace_quicly__quictrace_recv(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 60 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_recv.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_recv\n");

  return 0;
}
// quicly:quictrace_send_stream
int trace_quicly__quictrace_send_stream(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 61 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_send_stream.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_send_stream.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.quictrace_send_stream.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.quictrace_send_stream.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.quictrace_send_stream.len);
  // int fin
  bpf_usdt_readarg(6, ctx, &event.quictrace_send_stream.fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_send_stream\n");

  return 0;
}
// quicly:quictrace_recv_stream
int trace_quicly__quictrace_recv_stream(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 62 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_recv_stream.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_stream.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_stream.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.quictrace_recv_stream.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.quictrace_recv_stream.len);
  // int fin
  bpf_usdt_readarg(6, ctx, &event.quictrace_recv_stream.fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_recv_stream\n");

  return 0;
}
// quicly:quictrace_recv_ack
int trace_quicly__quictrace_recv_ack(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 63 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_recv_ack.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_ack.at);
  // uint64_t ack_block_begin
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_ack.ack_block_begin);
  // uint64_t ack_block_end
  bpf_usdt_readarg(4, ctx, &event.quictrace_recv_ack.ack_block_end);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_recv_ack\n");

  return 0;
}
// quicly:quictrace_recv_ack_delay
int trace_quicly__quictrace_recv_ack_delay(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 64 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_recv_ack_delay.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_ack_delay.at);
  // int64_t ack_delay
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_ack_delay.ack_delay);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_recv_ack_delay\n");

  return 0;
}
// quicly:quictrace_lost
int trace_quicly__quictrace_lost(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 65 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_lost.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_lost.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_lost\n");

  return 0;
}
// quicly:quictrace_cc_ack
int trace_quicly__quictrace_cc_ack(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 66 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_cc_ack.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_ack.at);
  // struct quicly_rtt_t * rtt
  uint8_t rtt[sizeof_quicly_rtt_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof_quicly_rtt_t, buf);
  event.quictrace_cc_ack.minimum = get_quicly_rtt_t__minimum(rtt);
  event.quictrace_cc_ack.smoothed = get_quicly_rtt_t__smoothed(rtt);
  event.quictrace_cc_ack.variance = get_quicly_rtt_t__variance(rtt);
  event.quictrace_cc_ack.latest = get_quicly_rtt_t__latest(rtt);
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.quictrace_cc_ack.cwnd);
  // size_t inflight
  bpf_usdt_readarg(5, ctx, &event.quictrace_cc_ack.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_cc_ack\n");

  return 0;
}
// quicly:quictrace_cc_lost
int trace_quicly__quictrace_cc_lost(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 67 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_cc_lost.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_lost.at);
  // struct quicly_rtt_t * rtt
  uint8_t rtt[sizeof_quicly_rtt_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof_quicly_rtt_t, buf);
  event.quictrace_cc_lost.minimum = get_quicly_rtt_t__minimum(rtt);
  event.quictrace_cc_lost.smoothed = get_quicly_rtt_t__smoothed(rtt);
  event.quictrace_cc_lost.variance = get_quicly_rtt_t__variance(rtt);
  event.quictrace_cc_lost.latest = get_quicly_rtt_t__latest(rtt);
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.quictrace_cc_lost.cwnd);
  // size_t inflight
  bpf_usdt_readarg(5, ctx, &event.quictrace_cc_lost.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__quictrace_cc_lost\n");

  return 0;
}
// quicly:stream_on_open
int trace_quicly__stream_on_open(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 68 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_open.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_open.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_open.stream_id = get_st_quicly_stream_t__stream_id(stream);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_open\n");

  return 0;
}
// quicly:stream_on_destroy
int trace_quicly__stream_on_destroy(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 69 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_destroy.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_destroy.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_destroy.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // int err
  bpf_usdt_readarg(4, ctx, &event.stream_on_destroy.err);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_destroy\n");

  return 0;
}
// quicly:stream_on_send_shift
int trace_quicly__stream_on_send_shift(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 70 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_send_shift.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_send_shift.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_send_shift.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // size_t delta
  bpf_usdt_readarg(4, ctx, &event.stream_on_send_shift.delta);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_send_shift\n");

  return 0;
}
// quicly:stream_on_send_emit
int trace_quicly__stream_on_send_emit(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 71 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_send_emit.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_send_emit.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_send_emit.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // size_t off
  bpf_usdt_readarg(4, ctx, &event.stream_on_send_emit.off);
  // size_t capacity
  bpf_usdt_readarg(5, ctx, &event.stream_on_send_emit.capacity);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_send_emit\n");

  return 0;
}
// quicly:stream_on_send_stop
int trace_quicly__stream_on_send_stop(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 72 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_send_stop.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_send_stop.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_send_stop.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // int err
  bpf_usdt_readarg(4, ctx, &event.stream_on_send_stop.err);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_send_stop\n");

  return 0;
}
// quicly:stream_on_receive
int trace_quicly__stream_on_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 73 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_receive.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_receive.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_receive.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // size_t off
  bpf_usdt_readarg(4, ctx, &event.stream_on_receive.off);
  // const void * src
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.stream_on_receive.src, sizeof(event.stream_on_receive.src), buf);
  // size_t src_len
  bpf_usdt_readarg(6, ctx, &event.stream_on_receive.src_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_receive\n");

  return 0;
}
// quicly:stream_on_receive_reset
int trace_quicly__stream_on_receive_reset(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 74 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_receive_reset.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_receive_reset.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_receive_reset.stream_id = get_st_quicly_stream_t__stream_id(stream);
  // int err
  bpf_usdt_readarg(4, ctx, &event.stream_on_receive_reset.err);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_receive_reset\n");

  return 0;
}
// quicly:conn_stats
int trace_quicly__conn_stats(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 76 };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.conn_stats.master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.conn_stats.at);
  // struct st_quicly_stats_t * stats
  // (no fields in st_quicly_stats_t)
  // size_t size
  bpf_usdt_readarg(4, ctx, &event.conn_stats.size);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__conn_stats\n");

  return 0;
}
// h2o:receive_request
int trace_h2o__receive_request(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 77 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.receive_request.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.receive_request.req_id);
  // int http_version
  bpf_usdt_readarg(3, ctx, &event.receive_request.http_version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__receive_request\n");

  return 0;
}
// h2o:receive_request_header
int trace_h2o__receive_request_header(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 78 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.receive_request_header.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.receive_request_header.req_id);
  // const char * name
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.receive_request_header.name, sizeof(event.receive_request_header.name), buf);
  // size_t name_len
  bpf_usdt_readarg(4, ctx, &event.receive_request_header.name_len);
  // const char * value
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.receive_request_header.value, sizeof(event.receive_request_header.value), buf);
  // size_t value_len
  bpf_usdt_readarg(6, ctx, &event.receive_request_header.value_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__receive_request_header\n");

  return 0;
}
// h2o:send_response
int trace_h2o__send_response(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 79 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.send_response.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.send_response.req_id);
  // int status
  bpf_usdt_readarg(3, ctx, &event.send_response.status);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__send_response\n");

  return 0;
}
// h2o:send_response_header
int trace_h2o__send_response_header(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 80 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.send_response_header.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.send_response_header.req_id);
  // const char * name
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.send_response_header.name, sizeof(event.send_response_header.name), buf);
  // size_t name_len
  bpf_usdt_readarg(4, ctx, &event.send_response_header.name_len);
  // const char * value
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.send_response_header.value, sizeof(event.send_response_header.value), buf);
  // size_t value_len
  bpf_usdt_readarg(6, ctx, &event.send_response_header.value_len);

#ifdef CHECK_ALLOWED_RES_HEADER_NAME
  if (!CHECK_ALLOWED_RES_HEADER_NAME(event.send_response_header.name, event.send_response_header.name_len))
    return 0;
#endif

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__send_response_header\n");

  return 0;
}
// h2o:h1_accept
int trace_h2o__h1_accept(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 81 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h1_accept.conn_id);
  // struct st_h2o_socket_t * sock
  // (no fields in st_h2o_socket_t)
  // struct st_h2o_conn_t * conn
  // (no fields in st_h2o_conn_t)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h1_accept\n");

  return 0;
}
// h2o:h1_close
int trace_h2o__h1_close(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 82 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h1_close.conn_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h1_close\n");

  return 0;
}
// h2o:h2_unknown_frame_type
int trace_h2o__h2_unknown_frame_type(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 83 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h2_unknown_frame_type.conn_id);
  // uint8_t frame_type
  bpf_usdt_readarg(2, ctx, &event.h2_unknown_frame_type.frame_type);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h2_unknown_frame_type\n");

  return 0;
}
// h2o:h3s_accept
int trace_h2o__h3s_accept(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 84 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3s_accept.conn_id);
  // struct st_h2o_conn_t * conn
  // (no fields in st_h2o_conn_t)
  // struct st_quicly_conn_t * quic
  uint8_t quic[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&quic, sizeof_st_quicly_conn_t, buf);
  event.h3s_accept.master_id = get_st_quicly_conn_t__master_id(quic);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3s_accept\n");

  return 0;
}
// h2o:h3s_destroy
int trace_h2o__h3s_destroy(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 85 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3s_destroy.conn_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3s_destroy\n");

  return 0;
}
// h2o:h3s_stream_set_state
int trace_h2o__h3s_stream_set_state(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 86 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3s_stream_set_state.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.h3s_stream_set_state.req_id);
  // unsigned state
  bpf_usdt_readarg(3, ctx, &event.h3s_stream_set_state.state);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3s_stream_set_state\n");

  return 0;
}
// h2o:h3_frame_receive
int trace_h2o__h3_frame_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 87 };

  // uint64_t frame_type
  bpf_usdt_readarg(1, ctx, &event.h3_frame_receive.frame_type);
  // const void * bytes
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.h3_frame_receive.bytes, sizeof(event.h3_frame_receive.bytes), buf);
  // size_t bytes_len
  bpf_usdt_readarg(3, ctx, &event.h3_frame_receive.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_frame_receive\n");

  return 0;
}
// h2o:h3_packet_receive
int trace_h2o__h3_packet_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 88 };

  // struct sockaddr * dest
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&event.h3_packet_receive.dest, sizeof_sockaddr, buf);
  if (get_sockaddr__sa_family(&event.h3_packet_receive.dest) == AF_INET) {
    bpf_probe_read(&event.h3_packet_receive.dest, sizeof_sockaddr_in, buf);
  } else if (get_sockaddr__sa_family(&event.h3_packet_receive.dest) == AF_INET6) {
    bpf_probe_read(&event.h3_packet_receive.dest, sizeof_sockaddr_in6, buf);
  }
  // struct sockaddr * src
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.h3_packet_receive.src, sizeof_sockaddr, buf);
  if (get_sockaddr__sa_family(&event.h3_packet_receive.src) == AF_INET) {
    bpf_probe_read(&event.h3_packet_receive.src, sizeof_sockaddr_in, buf);
  } else if (get_sockaddr__sa_family(&event.h3_packet_receive.src) == AF_INET6) {
    bpf_probe_read(&event.h3_packet_receive.src, sizeof_sockaddr_in6, buf);
  }
  // const void * bytes (ignored)
  // size_t bytes_len
  bpf_usdt_readarg(4, ctx, &event.h3_packet_receive.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_packet_receive\n");

  return 0;
}
// h2o:h3_packet_forward
int trace_h2o__h3_packet_forward(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct event_t event = { .id = 89 };

  // struct sockaddr * dest
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&event.h3_packet_forward.dest, sizeof_sockaddr, buf);
  if (get_sockaddr__sa_family(&event.h3_packet_forward.dest) == AF_INET) {
    bpf_probe_read(&event.h3_packet_forward.dest, sizeof_sockaddr_in, buf);
  } else if (get_sockaddr__sa_family(&event.h3_packet_forward.dest) == AF_INET6) {
    bpf_probe_read(&event.h3_packet_forward.dest, sizeof_sockaddr_in6, buf);
  }
  // struct sockaddr * src
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.h3_packet_forward.src, sizeof_sockaddr, buf);
  if (get_sockaddr__sa_family(&event.h3_packet_forward.src) == AF_INET) {
    bpf_probe_read(&event.h3_packet_forward.src, sizeof_sockaddr_in, buf);
  } else if (get_sockaddr__sa_family(&event.h3_packet_forward.src) == AF_INET6) {
    bpf_probe_read(&event.h3_packet_forward.src, sizeof_sockaddr_in6, buf);
  }
  // size_t num_packets
  bpf_usdt_readarg(3, ctx, &event.h3_packet_forward.num_packets);
  // size_t num_bytes
  bpf_usdt_readarg(4, ctx, &event.h3_packet_forward.num_bytes);
  // int fd
  bpf_usdt_readarg(5, ctx, &event.h3_packet_forward.fd);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_packet_forward\n");

  return 0;
}

)";
}

