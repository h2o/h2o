// Generated code. Do not edit it here!

extern "C" {
#include <sys/time.h>
#include "quicly.h"
#include "h2o/ebpf.h"
}

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <algorithm>

#include "h2olog.h"
#include "json.h"

#include "raw_tracer.cc.h"

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

  bpf += "#define sizeof_st_h2o_ebpf_map_key_t " + std::to_string(std::min<size_t>(sizeof(struct st_h2o_ebpf_map_key_t), 100)) + "\n";

  bpf += "#define sizeof_sockaddr " + std::to_string(std::min<size_t>(sizeof(struct sockaddr), 100)) + "\n";

  bpf += "#define sizeof_sockaddr_in " + std::to_string(std::min<size_t>(sizeof(struct sockaddr_in), 100)) + "\n";

  bpf += "#define sizeof_sockaddr_in6 " + std::to_string(std::min<size_t>(sizeof(struct sockaddr_in6), 100)) + "\n";

  bpf += GEN_FIELD_INFO(struct sockaddr, sa_family, "sockaddr__sa_family");
  bpf += "#define AF_INET  " + std::to_string(AF_INET) + "\n";
  bpf += "#define AF_INET6 " + std::to_string(AF_INET6) + "\n";

  return bpf;
}


enum h2olog_event_id_t {
  H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT,
  H2OLOG_EVENT_ID_QUICLY_CONNECT,
  H2OLOG_EVENT_ID_QUICLY_ACCEPT,
  H2OLOG_EVENT_ID_QUICLY_FREE,
  H2OLOG_EVENT_ID_QUICLY_SEND,
  H2OLOG_EVENT_ID_QUICLY_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_VERSION_SWITCH,
  H2OLOG_EVENT_ID_QUICLY_IDLE_TIMEOUT,
  H2OLOG_EVENT_ID_QUICLY_STATELESS_RESET_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_HANDSHAKE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_UPDATE_SECRET,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE_CONFIRMED,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE_PREPARE,
  H2OLOG_EVENT_ID_QUICLY_PACKET_SENT,
  H2OLOG_EVENT_ID_QUICLY_PACKET_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_PACKET_PREPARE,
  H2OLOG_EVENT_ID_QUICLY_PACKET_ACKED,
  H2OLOG_EVENT_ID_QUICLY_PACKET_LOST,
  H2OLOG_EVENT_ID_QUICLY_PACKET_DECRYPTION_FAILED,
  H2OLOG_EVENT_ID_QUICLY_PTO,
  H2OLOG_EVENT_ID_QUICLY_CC_ACK_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_CC_CONGESTION,
  H2OLOG_EVENT_ID_QUICLY_ACK_BLOCK_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_ACK_DELAY_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_ACK_SEND,
  H2OLOG_EVENT_ID_QUICLY_PING_SEND,
  H2OLOG_EVENT_ID_QUICLY_PING_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_SEND,
  H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_SEND,
  H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_SEND,
  H2OLOG_EVENT_ID_QUICLY_STREAM_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ACKED,
  H2OLOG_EVENT_ID_QUICLY_STREAM_LOST,
  H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_SEND,
  H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_SEND,
  H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_MAX_DATA_SEND,
  H2OLOG_EVENT_ID_QUICLY_MAX_DATA_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_SEND,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_SEND,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_SEND,
  H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_ACKED,
  H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_SEND,
  H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_SEND,
  H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_SEND,
  H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_SEND,
  H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_SEND,
  H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_SEND,
  H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_DATAGRAM_SEND,
  H2OLOG_EVENT_ID_QUICLY_DATAGRAM_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_ACK_FREQUENCY_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_SEND_STREAM,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_RECV_STREAM,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_ACK,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_LOST,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_OPEN,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_DESTROY,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_SHIFT,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_EMIT,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_STOP,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE_RESET,
  H2OLOG_EVENT_ID_QUICLY_CONN_STATS,
  H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS,
  H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_SNI,
  H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST,
  H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST_HEADER,
  H2OLOG_EVENT_ID_H2O_SEND_RESPONSE,
  H2OLOG_EVENT_ID_H2O_SEND_RESPONSE_HEADER,
  H2OLOG_EVENT_ID_H2O_H1_ACCEPT,
  H2OLOG_EVENT_ID_H2O_H1_CLOSE,
  H2OLOG_EVENT_ID_H2O_H2_UNKNOWN_FRAME_TYPE,
  H2OLOG_EVENT_ID_H2O_H3S_ACCEPT,
  H2OLOG_EVENT_ID_H2O_H3S_DESTROY,
  H2OLOG_EVENT_ID_H2O_H3S_STREAM_SET_STATE,
  H2OLOG_EVENT_ID_H2O_H3_FRAME_RECEIVE,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_RECEIVE,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_NODE_IGNORE,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_THREAD_IGNORE,
  H2OLOG_EVENT_ID_H2O_H3_FORWARDED_PACKET_RECEIVE,
  H2OLOG_EVENT_ID_H2O_H3C_TUNNEL_CREATE,
  H2OLOG_EVENT_ID_H2O_TUNNEL_ON_DESTROY,
  H2OLOG_EVENT_ID_H2O_TUNNEL_ON_READ,
  H2OLOG_EVENT_ID_H2O_TUNNEL_PROCEED_READ,
  H2OLOG_EVENT_ID_H2O_TUNNEL_WRITE,
  H2OLOG_EVENT_ID_H2O_TUNNEL_ON_WRITE_COMPLETE,
  H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_CREATE,
  H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_START,
};


struct h2olog_event_t {
  enum h2olog_event_id_t id;
  uint32_t tid;

  union {
    struct { // quicly:connect
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      char dcid[STR_LEN];
      struct st_quicly_address_token_plaintext_t * address_token;
    } accept;
    struct { // quicly:free
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[STR_LEN];
      size_t bytes_len;
    } receive;
    struct { // quicly:version_switch
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_handshake
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
      char secret[STR_LEN]; // appdata
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN]; // appdata
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN]; // appdata
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN]; // appdata
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_sent
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
      int ack_only;
    } packet_sent;
    struct { // quicly:packet_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      uint8_t decrypted[STR_LEN]; // appdata
      size_t decrypted_len;
      uint8_t packet_type;
    } packet_received;
    struct { // quicly:packet_prepare
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_acked
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      int is_late_ack;
    } packet_acked;
    struct { // quicly:packet_lost
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      uint8_t packet_type;
    } packet_lost;
    struct { // quicly:packet_decryption_failed
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
    } packet_decryption_failed;
    struct { // quicly:pto
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:ack_block_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } ack_block_received;
    struct { // quicly:ack_delay_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t ack_delay;
    } ack_delay_received;
    struct { // quicly:ack_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t largest_acked;
      uint64_t ack_delay;
    } ack_send;
    struct { // quicly:ping_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } ping_send;
    struct { // quicly:ping_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } ping_receive;
    struct { // quicly:transport_close_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:reset_stream_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
      uint64_t final_size;
    } reset_stream_send;
    struct { // quicly:reset_stream_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
      uint64_t final_size;
    } reset_stream_receive;
    struct { // quicly:stop_sending_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
    } stop_sending_send;
    struct { // quicly:stop_sending_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
    } stop_sending_receive;
    struct { // quicly:max_data_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
    } max_data_send;
    struct { // quicly:max_data_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
    } max_data_receive;
    struct { // quicly:max_streams_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t maximum;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t maximum;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:new_connection_id_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_send;
    struct { // quicly:new_connection_id_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_receive;
    struct { // quicly:retire_connection_id_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_send;
    struct { // quicly:retire_connection_id_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_receive;
    struct { // quicly:data_blocked_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_send;
    struct { // quicly:data_blocked_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t maximum;
    } stream_data_blocked_send;
    struct { // quicly:stream_data_blocked_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t maximum;
    } stream_data_blocked_receive;
    struct { // quicly:datagram_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t payload[STR_LEN]; // appdata
      size_t payload_len;
    } datagram_send;
    struct { // quicly:datagram_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t payload[STR_LEN]; // appdata
      size_t payload_len;
    } datagram_receive;
    struct { // quicly:ack_frequency_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t packet_tolerance;
      uint64_t max_ack_delay;
      int ignore_order;
    } ack_frequency_receive;
    struct { // quicly:quictrace_send_stream
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_cc_ack
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum rtt_minimum;
      typeof_quicly_rtt_t__smoothed rtt_smoothed;
      typeof_quicly_rtt_t__variance rtt_variance;
      typeof_quicly_rtt_t__latest rtt_latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum rtt_minimum;
      typeof_quicly_rtt_t__smoothed rtt_smoothed;
      typeof_quicly_rtt_t__variance rtt_variance;
      typeof_quicly_rtt_t__latest rtt_latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // quicly:stream_on_open
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
    } stream_on_open;
    struct { // quicly:stream_on_destroy
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      int err;
    } stream_on_destroy;
    struct { // quicly:stream_on_send_shift
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      size_t delta;
    } stream_on_send_shift;
    struct { // quicly:stream_on_send_emit
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      size_t off;
      size_t capacity;
    } stream_on_send_emit;
    struct { // quicly:stream_on_send_stop
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      int err;
    } stream_on_send_stop;
    struct { // quicly:stream_on_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      size_t off;
      uint8_t src[STR_LEN]; // appdata
      size_t src_len;
    } stream_on_receive;
    struct { // quicly:stream_on_receive_reset
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      int err;
    } stream_on_receive_reset;
    struct { // quicly:conn_stats
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      struct st_quicly_stats_t * stats;
      size_t size;
    } conn_stats;
    struct { // h2o:_private_socket_lookup_flags
      pid_t tid;
      uint64_t original_flags;
      struct st_h2o_ebpf_map_key_t info;
    } _private_socket_lookup_flags;
    struct { // h2o:_private_socket_lookup_flags_sni
      pid_t tid;
      uint64_t original_flags;
      char server_name[STR_LEN];
      size_t server_name_len;
    } _private_socket_lookup_flags_sni;
    struct { // h2o:receive_request
      uint64_t conn_id;
      uint64_t req_id;
      int http_version;
    } receive_request;
    struct { // h2o:receive_request_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN]; // appdata
      size_t name_len;
      char value[STR_LEN]; // appdata
      size_t value_len;
    } receive_request_header;
    struct { // h2o:send_response
      uint64_t conn_id;
      uint64_t req_id;
      int status;
      struct st_h2o_tunnel_t * tunnel;
    } send_response;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN]; // appdata
      size_t name_len;
      char value[STR_LEN]; // appdata
      size_t value_len;
    } send_response_header;
    struct { // h2o:h1_accept
      uint64_t conn_id;
      struct st_h2o_socket_t * sock;
      struct st_h2o_conn_t * conn;
      char conn_uuid[STR_LEN];
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
      struct st_h2o_conn_t * conn;
      typeof_st_quicly_conn_t__master_id quic_master_id;
      char conn_uuid[STR_LEN];
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
      uint8_t bytes[STR_LEN]; // appdata
      size_t bytes_len;
    } h3_frame_receive;
    struct { // h2o:h3_packet_receive
      quicly_address_t dest;
      quicly_address_t src;
      uint8_t bytes[STR_LEN];
      size_t bytes_len;
    } h3_packet_receive;
    struct { // h2o:h3_packet_forward
      quicly_address_t dest;
      quicly_address_t src;
      size_t num_packets;
      size_t num_bytes;
      int fd;
    } h3_packet_forward;
    struct { // h2o:h3_packet_forward_to_node_ignore
      uint64_t node_id;
    } h3_packet_forward_to_node_ignore;
    struct { // h2o:h3_packet_forward_to_thread_ignore
      uint32_t thread_id;
    } h3_packet_forward_to_thread_ignore;
    struct { // h2o:h3_forwarded_packet_receive
      quicly_address_t dest;
      quicly_address_t src;
      size_t num_bytes;
    } h3_forwarded_packet_receive;
    struct { // h2o:h3c_tunnel_create
      struct st_h2o_tunnel_t * tunnel;
    } h3c_tunnel_create;
    struct { // h2o:tunnel_on_destroy
      struct st_h2o_tunnel_t * tunnel;
    } tunnel_on_destroy;
    struct { // h2o:tunnel_on_read
      struct st_h2o_tunnel_t * tunnel;
      char err[STR_LEN];
      uint8_t bytes[STR_LEN]; // appdata
      size_t bytes_len;
    } tunnel_on_read;
    struct { // h2o:tunnel_proceed_read
      struct st_h2o_tunnel_t * tunnel;
    } tunnel_proceed_read;
    struct { // h2o:tunnel_write
      struct st_h2o_tunnel_t * tunnel;
      uint8_t bytes[STR_LEN]; // appdata
      size_t bytes_len;
    } tunnel_write;
    struct { // h2o:tunnel_on_write_complete
      struct st_h2o_tunnel_t * tunnel;
      char err[STR_LEN];
    } tunnel_on_write_complete;
    struct { // h2o:socket_tunnel_create
      struct st_h2o_tunnel_t * tunnel;
    } socket_tunnel_create;
    struct { // h2o:socket_tunnel_start
      struct st_h2o_tunnel_t * tunnel;
      size_t bytes_to_consume;
    } socket_tunnel_start;

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
    h2o_tracer::usdt("quicly", "crypto_handshake", "trace_quicly__crypto_handshake"),
    h2o_tracer::usdt("quicly", "crypto_update_secret", "trace_quicly__crypto_update_secret"),
    h2o_tracer::usdt("quicly", "crypto_send_key_update", "trace_quicly__crypto_send_key_update"),
    h2o_tracer::usdt("quicly", "crypto_send_key_update_confirmed", "trace_quicly__crypto_send_key_update_confirmed"),
    h2o_tracer::usdt("quicly", "crypto_receive_key_update", "trace_quicly__crypto_receive_key_update"),
    h2o_tracer::usdt("quicly", "crypto_receive_key_update_prepare", "trace_quicly__crypto_receive_key_update_prepare"),
    h2o_tracer::usdt("quicly", "packet_sent", "trace_quicly__packet_sent"),
    h2o_tracer::usdt("quicly", "packet_received", "trace_quicly__packet_received"),
    h2o_tracer::usdt("quicly", "packet_prepare", "trace_quicly__packet_prepare"),
    h2o_tracer::usdt("quicly", "packet_acked", "trace_quicly__packet_acked"),
    h2o_tracer::usdt("quicly", "packet_lost", "trace_quicly__packet_lost"),
    h2o_tracer::usdt("quicly", "packet_decryption_failed", "trace_quicly__packet_decryption_failed"),
    h2o_tracer::usdt("quicly", "pto", "trace_quicly__pto"),
    h2o_tracer::usdt("quicly", "cc_ack_received", "trace_quicly__cc_ack_received"),
    h2o_tracer::usdt("quicly", "cc_congestion", "trace_quicly__cc_congestion"),
    h2o_tracer::usdt("quicly", "ack_block_received", "trace_quicly__ack_block_received"),
    h2o_tracer::usdt("quicly", "ack_delay_received", "trace_quicly__ack_delay_received"),
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
    h2o_tracer::usdt("quicly", "reset_stream_send", "trace_quicly__reset_stream_send"),
    h2o_tracer::usdt("quicly", "reset_stream_receive", "trace_quicly__reset_stream_receive"),
    h2o_tracer::usdt("quicly", "stop_sending_send", "trace_quicly__stop_sending_send"),
    h2o_tracer::usdt("quicly", "stop_sending_receive", "trace_quicly__stop_sending_receive"),
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
    h2o_tracer::usdt("quicly", "quictrace_send_stream", "trace_quicly__quictrace_send_stream"),
    h2o_tracer::usdt("quicly", "quictrace_recv_stream", "trace_quicly__quictrace_recv_stream"),
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
    h2o_tracer::usdt("h2o", "h3_packet_forward_to_node_ignore", "trace_h2o__h3_packet_forward_to_node_ignore"),
    h2o_tracer::usdt("h2o", "h3_packet_forward_to_thread_ignore", "trace_h2o__h3_packet_forward_to_thread_ignore"),
    h2o_tracer::usdt("h2o", "h3_forwarded_packet_receive", "trace_h2o__h3_forwarded_packet_receive"),
    h2o_tracer::usdt("h2o", "h3c_tunnel_create", "trace_h2o__h3c_tunnel_create"),
    h2o_tracer::usdt("h2o", "tunnel_on_destroy", "trace_h2o__tunnel_on_destroy"),
    h2o_tracer::usdt("h2o", "tunnel_on_read", "trace_h2o__tunnel_on_read"),
    h2o_tracer::usdt("h2o", "tunnel_proceed_read", "trace_h2o__tunnel_proceed_read"),
    h2o_tracer::usdt("h2o", "tunnel_write", "trace_h2o__tunnel_write"),
    h2o_tracer::usdt("h2o", "tunnel_on_write_complete", "trace_h2o__tunnel_on_write_complete"),
    h2o_tracer::usdt("h2o", "socket_tunnel_create", "trace_h2o__socket_tunnel_create"),
    h2o_tracer::usdt("h2o", "socket_tunnel_start", "trace_h2o__socket_tunnel_start"),

  });
}


void h2o_raw_tracer::do_handle_event(const void *data, int data_len) {
  const h2olog_event_t *event = static_cast<const h2olog_event_t*>(data);

  if (event->id == H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT) {
    exit(0);
  }

  // output JSON
  fprintf(out_, "{");

  switch (event->id) {
  case H2OLOG_EVENT_ID_QUICLY_CONNECT: { // quicly:connect
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("connect"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->connect.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->connect.at);
    json_write_pair_c(out_, STR_LIT("version"), event->connect.version);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_ACCEPT: { // quicly:accept
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("accept"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->accept.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->accept.at);
    json_write_pair_c(out_, STR_LIT("dcid"), event->accept.dcid, strlen(event->accept.dcid));
    json_write_pair_c(out_, STR_LIT("address-token"), event->accept.address_token);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_FREE: { // quicly:free
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("free"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->free.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->free.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_SEND: { // quicly:send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->send.at);
    json_write_pair_c(out_, STR_LIT("state"), event->send.state);
    json_write_pair_c(out_, STR_LIT("dcid"), event->send.dcid, strlen(event->send.dcid));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_RECEIVE: { // quicly:receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->receive.at);
    json_write_pair_c(out_, STR_LIT("dcid"), event->receive.dcid, strlen(event->receive.dcid));
    json_write_pair_c(out_, STR_LIT("bytes"), event->receive.bytes, (event->receive.bytes_len < STR_LEN ? event->receive.bytes_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->receive.bytes_len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_VERSION_SWITCH: { // quicly:version_switch
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("version-switch"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->version_switch.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->version_switch.at);
    json_write_pair_c(out_, STR_LIT("new-version"), event->version_switch.new_version);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_IDLE_TIMEOUT: { // quicly:idle_timeout
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("idle-timeout"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->idle_timeout.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->idle_timeout.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STATELESS_RESET_RECEIVE: { // quicly:stateless_reset_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stateless-reset-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stateless_reset_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stateless_reset_receive.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CRYPTO_HANDSHAKE: { // quicly:crypto_handshake
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("crypto-handshake"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_handshake.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_handshake.at);
    json_write_pair_c(out_, STR_LIT("ret"), event->crypto_handshake.ret);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CRYPTO_UPDATE_SECRET: { // quicly:crypto_update_secret
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("crypto-update-secret"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_update_secret.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_update_secret.at);
    json_write_pair_c(out_, STR_LIT("is-enc"), event->crypto_update_secret.is_enc);
    json_write_pair_c(out_, STR_LIT("epoch"), event->crypto_update_secret.epoch);
    json_write_pair_c(out_, STR_LIT("label"), event->crypto_update_secret.label, strlen(event->crypto_update_secret.label));
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("secret"), event->crypto_update_secret.secret, strlen(event->crypto_update_secret.secret));
    }
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE: { // quicly:crypto_send_key_update
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("crypto-send-key-update"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_send_key_update.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_send_key_update.at);
    json_write_pair_c(out_, STR_LIT("phase"), event->crypto_send_key_update.phase);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("secret"), event->crypto_send_key_update.secret, strlen(event->crypto_send_key_update.secret));
    }
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE_CONFIRMED: { // quicly:crypto_send_key_update_confirmed
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("crypto-send-key-update-confirmed"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_send_key_update_confirmed.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_send_key_update_confirmed.at);
    json_write_pair_c(out_, STR_LIT("next-pn"), event->crypto_send_key_update_confirmed.next_pn);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE: { // quicly:crypto_receive_key_update
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("crypto-receive-key-update"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_receive_key_update.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_receive_key_update.at);
    json_write_pair_c(out_, STR_LIT("phase"), event->crypto_receive_key_update.phase);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("secret"), event->crypto_receive_key_update.secret, strlen(event->crypto_receive_key_update.secret));
    }
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE_PREPARE: { // quicly:crypto_receive_key_update_prepare
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("crypto-receive-key-update-prepare"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->crypto_receive_key_update_prepare.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->crypto_receive_key_update_prepare.at);
    json_write_pair_c(out_, STR_LIT("phase"), event->crypto_receive_key_update_prepare.phase);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("secret"), event->crypto_receive_key_update_prepare.secret, strlen(event->crypto_receive_key_update_prepare.secret));
    }
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PACKET_SENT: { // quicly:packet_sent
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("packet-sent"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_sent.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_sent.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_sent.pn);
    json_write_pair_c(out_, STR_LIT("len"), event->packet_sent.len);
    json_write_pair_c(out_, STR_LIT("packet-type"), event->packet_sent.packet_type);
    json_write_pair_c(out_, STR_LIT("ack-only"), event->packet_sent.ack_only);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PACKET_RECEIVED: { // quicly:packet_received
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("packet-received"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_received.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_received.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_received.pn);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("decrypted"), event->packet_received.decrypted, (event->packet_received.decrypted_len < STR_LEN ? event->packet_received.decrypted_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("decrypted-len"), event->packet_received.decrypted_len);
    json_write_pair_c(out_, STR_LIT("packet-type"), event->packet_received.packet_type);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PACKET_PREPARE: { // quicly:packet_prepare
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("packet-prepare"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_prepare.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_prepare.at);
    json_write_pair_c(out_, STR_LIT("first-octet"), event->packet_prepare.first_octet);
    json_write_pair_c(out_, STR_LIT("dcid"), event->packet_prepare.dcid, strlen(event->packet_prepare.dcid));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PACKET_ACKED: { // quicly:packet_acked
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("packet-acked"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_acked.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_acked.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_acked.pn);
    json_write_pair_c(out_, STR_LIT("is-late-ack"), event->packet_acked.is_late_ack);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PACKET_LOST: { // quicly:packet_lost
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("packet-lost"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_lost.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_lost.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_lost.pn);
    json_write_pair_c(out_, STR_LIT("packet-type"), event->packet_lost.packet_type);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PACKET_DECRYPTION_FAILED: { // quicly:packet_decryption_failed
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("packet-decryption-failed"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->packet_decryption_failed.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->packet_decryption_failed.at);
    json_write_pair_c(out_, STR_LIT("pn"), event->packet_decryption_failed.pn);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PTO: { // quicly:pto
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("pto"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->pto.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->pto.at);
    json_write_pair_c(out_, STR_LIT("inflight"), event->pto.inflight);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->pto.cwnd);
    json_write_pair_c(out_, STR_LIT("pto-count"), event->pto.pto_count);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CC_ACK_RECEIVED: { // quicly:cc_ack_received
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("cc-ack-received"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->cc_ack_received.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->cc_ack_received.at);
    json_write_pair_c(out_, STR_LIT("largest-acked"), event->cc_ack_received.largest_acked);
    json_write_pair_c(out_, STR_LIT("bytes-acked"), event->cc_ack_received.bytes_acked);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->cc_ack_received.cwnd);
    json_write_pair_c(out_, STR_LIT("inflight"), event->cc_ack_received.inflight);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CC_CONGESTION: { // quicly:cc_congestion
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("cc-congestion"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->cc_congestion.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->cc_congestion.at);
    json_write_pair_c(out_, STR_LIT("max-lost-pn"), event->cc_congestion.max_lost_pn);
    json_write_pair_c(out_, STR_LIT("inflight"), event->cc_congestion.inflight);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->cc_congestion.cwnd);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_ACK_BLOCK_RECEIVED: { // quicly:ack_block_received
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("ack-block-received"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ack_block_received.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ack_block_received.at);
    json_write_pair_c(out_, STR_LIT("ack-block-begin"), event->ack_block_received.ack_block_begin);
    json_write_pair_c(out_, STR_LIT("ack-block-end"), event->ack_block_received.ack_block_end);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_ACK_DELAY_RECEIVED: { // quicly:ack_delay_received
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("ack-delay-received"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ack_delay_received.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ack_delay_received.at);
    json_write_pair_c(out_, STR_LIT("ack-delay"), event->ack_delay_received.ack_delay);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_ACK_SEND: { // quicly:ack_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("ack-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ack_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ack_send.at);
    json_write_pair_c(out_, STR_LIT("largest-acked"), event->ack_send.largest_acked);
    json_write_pair_c(out_, STR_LIT("ack-delay"), event->ack_send.ack_delay);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PING_SEND: { // quicly:ping_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("ping-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ping_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ping_send.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_PING_RECEIVE: { // quicly:ping_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("ping-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ping_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ping_receive.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_SEND: { // quicly:transport_close_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("transport-close-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->transport_close_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->transport_close_send.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->transport_close_send.error_code);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->transport_close_send.frame_type);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->transport_close_send.reason_phrase, strlen(event->transport_close_send.reason_phrase));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_RECEIVE: { // quicly:transport_close_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("transport-close-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->transport_close_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->transport_close_receive.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->transport_close_receive.error_code);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->transport_close_receive.frame_type);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->transport_close_receive.reason_phrase, strlen(event->transport_close_receive.reason_phrase));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_SEND: { // quicly:application_close_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("application-close-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->application_close_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->application_close_send.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->application_close_send.error_code);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->application_close_send.reason_phrase, strlen(event->application_close_send.reason_phrase));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_RECEIVE: { // quicly:application_close_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("application-close-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->application_close_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->application_close_receive.at);
    json_write_pair_c(out_, STR_LIT("error-code"), event->application_close_receive.error_code);
    json_write_pair_c(out_, STR_LIT("reason-phrase"), event->application_close_receive.reason_phrase, strlen(event->application_close_receive.reason_phrase));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_SEND: { // quicly:stream_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_send.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_send.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_send.len);
    json_write_pair_c(out_, STR_LIT("is-fin"), event->stream_send.is_fin);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_RECEIVE: { // quicly:stream_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_receive.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_receive.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_receive.len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ACKED: { // quicly:stream_acked
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-acked"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_acked.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_acked.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_acked.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_acked.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_acked.len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_LOST: { // quicly:stream_lost
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-lost"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_lost.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_lost.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_lost.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_lost.off);
    json_write_pair_c(out_, STR_LIT("len"), event->stream_lost.len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_SEND: { // quicly:reset_stream_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("reset-stream-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->reset_stream_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->reset_stream_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->reset_stream_send.stream_id);
    json_write_pair_c(out_, STR_LIT("error-code"), event->reset_stream_send.error_code);
    json_write_pair_c(out_, STR_LIT("final-size"), event->reset_stream_send.final_size);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_RECEIVE: { // quicly:reset_stream_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("reset-stream-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->reset_stream_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->reset_stream_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->reset_stream_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("error-code"), event->reset_stream_receive.error_code);
    json_write_pair_c(out_, STR_LIT("final-size"), event->reset_stream_receive.final_size);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_SEND: { // quicly:stop_sending_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stop-sending-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stop_sending_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stop_sending_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stop_sending_send.stream_id);
    json_write_pair_c(out_, STR_LIT("error-code"), event->stop_sending_send.error_code);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_RECEIVE: { // quicly:stop_sending_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stop-sending-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stop_sending_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stop_sending_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stop_sending_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("error-code"), event->stop_sending_receive.error_code);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_MAX_DATA_SEND: { // quicly:max_data_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("max-data-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_data_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_data_send.at);
    json_write_pair_c(out_, STR_LIT("maximum"), event->max_data_send.maximum);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_MAX_DATA_RECEIVE: { // quicly:max_data_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("max-data-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_data_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_data_receive.at);
    json_write_pair_c(out_, STR_LIT("maximum"), event->max_data_receive.maximum);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_SEND: { // quicly:max_streams_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("max-streams-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_streams_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_streams_send.at);
    json_write_pair_c(out_, STR_LIT("maximum"), event->max_streams_send.maximum);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->max_streams_send.is_unidirectional);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_RECEIVE: { // quicly:max_streams_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("max-streams-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_streams_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_streams_receive.at);
    json_write_pair_c(out_, STR_LIT("maximum"), event->max_streams_receive.maximum);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->max_streams_receive.is_unidirectional);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_SEND: { // quicly:max_stream_data_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("max-stream-data-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_stream_data_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_stream_data_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->max_stream_data_send.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("maximum"), event->max_stream_data_send.maximum);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_RECEIVE: { // quicly:max_stream_data_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("max-stream-data-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->max_stream_data_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->max_stream_data_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->max_stream_data_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("maximum"), event->max_stream_data_receive.maximum);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_SEND: { // quicly:new_token_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("new-token-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_token_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_token_send.at);
    json_write_pair_c(out_, STR_LIT("token"), event->new_token_send.token, (event->new_token_send.token_len < STR_LEN ? event->new_token_send.token_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("token-len"), event->new_token_send.token_len);
    json_write_pair_c(out_, STR_LIT("generation"), event->new_token_send.generation);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_ACKED: { // quicly:new_token_acked
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("new-token-acked"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_token_acked.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_token_acked.at);
    json_write_pair_c(out_, STR_LIT("generation"), event->new_token_acked.generation);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_RECEIVE: { // quicly:new_token_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("new-token-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_token_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_token_receive.at);
    json_write_pair_c(out_, STR_LIT("token"), event->new_token_receive.token, (event->new_token_receive.token_len < STR_LEN ? event->new_token_receive.token_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("token-len"), event->new_token_receive.token_len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_SEND: { // quicly:handshake_done_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("handshake-done-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->handshake_done_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->handshake_done_send.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_RECEIVE: { // quicly:handshake_done_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("handshake-done-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->handshake_done_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->handshake_done_receive.at);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_SEND: { // quicly:streams_blocked_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("streams-blocked-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->streams_blocked_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->streams_blocked_send.at);
    json_write_pair_c(out_, STR_LIT("maximum"), event->streams_blocked_send.maximum);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->streams_blocked_send.is_unidirectional);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_RECEIVE: { // quicly:streams_blocked_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("streams-blocked-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->streams_blocked_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->streams_blocked_receive.at);
    json_write_pair_c(out_, STR_LIT("maximum"), event->streams_blocked_receive.maximum);
    json_write_pair_c(out_, STR_LIT("is-unidirectional"), event->streams_blocked_receive.is_unidirectional);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_SEND: { // quicly:new_connection_id_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("new-connection-id-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_connection_id_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_connection_id_send.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->new_connection_id_send.sequence);
    json_write_pair_c(out_, STR_LIT("retire-prior-to"), event->new_connection_id_send.retire_prior_to);
    json_write_pair_c(out_, STR_LIT("cid"), event->new_connection_id_send.cid, strlen(event->new_connection_id_send.cid));
    json_write_pair_c(out_, STR_LIT("stateless-reset-token"), event->new_connection_id_send.stateless_reset_token, strlen(event->new_connection_id_send.stateless_reset_token));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_RECEIVE: { // quicly:new_connection_id_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("new-connection-id-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->new_connection_id_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->new_connection_id_receive.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->new_connection_id_receive.sequence);
    json_write_pair_c(out_, STR_LIT("retire-prior-to"), event->new_connection_id_receive.retire_prior_to);
    json_write_pair_c(out_, STR_LIT("cid"), event->new_connection_id_receive.cid, strlen(event->new_connection_id_receive.cid));
    json_write_pair_c(out_, STR_LIT("stateless-reset-token"), event->new_connection_id_receive.stateless_reset_token, strlen(event->new_connection_id_receive.stateless_reset_token));
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_SEND: { // quicly:retire_connection_id_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("retire-connection-id-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->retire_connection_id_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->retire_connection_id_send.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->retire_connection_id_send.sequence);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_RECEIVE: { // quicly:retire_connection_id_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("retire-connection-id-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->retire_connection_id_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->retire_connection_id_receive.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->retire_connection_id_receive.sequence);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_SEND: { // quicly:data_blocked_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("data-blocked-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->data_blocked_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->data_blocked_send.at);
    json_write_pair_c(out_, STR_LIT("off"), event->data_blocked_send.off);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_RECEIVE: { // quicly:data_blocked_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("data-blocked-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->data_blocked_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->data_blocked_receive.at);
    json_write_pair_c(out_, STR_LIT("off"), event->data_blocked_receive.off);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_SEND: { // quicly:stream_data_blocked_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-data-blocked-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_data_blocked_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_data_blocked_send.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_data_blocked_send.stream_id);
    json_write_pair_c(out_, STR_LIT("maximum"), event->stream_data_blocked_send.maximum);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_RECEIVE: { // quicly:stream_data_blocked_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-data-blocked-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_data_blocked_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_data_blocked_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_data_blocked_receive.stream_id);
    json_write_pair_c(out_, STR_LIT("maximum"), event->stream_data_blocked_receive.maximum);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_DATAGRAM_SEND: { // quicly:datagram_send
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("datagram-send"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->datagram_send.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->datagram_send.at);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("payload"), event->datagram_send.payload, (event->datagram_send.payload_len < STR_LEN ? event->datagram_send.payload_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("payload-len"), event->datagram_send.payload_len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_DATAGRAM_RECEIVE: { // quicly:datagram_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("datagram-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->datagram_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->datagram_receive.at);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("payload"), event->datagram_receive.payload, (event->datagram_receive.payload_len < STR_LEN ? event->datagram_receive.payload_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("payload-len"), event->datagram_receive.payload_len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_ACK_FREQUENCY_RECEIVE: { // quicly:ack_frequency_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("ack-frequency-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->ack_frequency_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->ack_frequency_receive.at);
    json_write_pair_c(out_, STR_LIT("sequence"), event->ack_frequency_receive.sequence);
    json_write_pair_c(out_, STR_LIT("packet-tolerance"), event->ack_frequency_receive.packet_tolerance);
    json_write_pair_c(out_, STR_LIT("max-ack-delay"), event->ack_frequency_receive.max_ack_delay);
    json_write_pair_c(out_, STR_LIT("ignore-order"), event->ack_frequency_receive.ignore_order);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_QUICTRACE_SEND_STREAM: { // quicly:quictrace_send_stream
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("quictrace-send-stream"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_send_stream.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_send_stream.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->quictrace_send_stream.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->quictrace_send_stream.off);
    json_write_pair_c(out_, STR_LIT("len"), event->quictrace_send_stream.len);
    json_write_pair_c(out_, STR_LIT("fin"), event->quictrace_send_stream.fin);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_QUICTRACE_RECV_STREAM: { // quicly:quictrace_recv_stream
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("quictrace-recv-stream"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_recv_stream.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_recv_stream.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->quictrace_recv_stream.stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->quictrace_recv_stream.off);
    json_write_pair_c(out_, STR_LIT("len"), event->quictrace_recv_stream.len);
    json_write_pair_c(out_, STR_LIT("fin"), event->quictrace_recv_stream.fin);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_ACK: { // quicly:quictrace_cc_ack
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("quictrace-cc-ack"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_cc_ack.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_cc_ack.at);
    json_write_pair_c(out_, STR_LIT("min-rtt"), event->quictrace_cc_ack.rtt_minimum);
    json_write_pair_c(out_, STR_LIT("smoothed-rtt"), event->quictrace_cc_ack.rtt_smoothed);
    json_write_pair_c(out_, STR_LIT("variance-rtt"), event->quictrace_cc_ack.rtt_variance);
    json_write_pair_c(out_, STR_LIT("latest-rtt"), event->quictrace_cc_ack.rtt_latest);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->quictrace_cc_ack.cwnd);
    json_write_pair_c(out_, STR_LIT("inflight"), event->quictrace_cc_ack.inflight);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_LOST: { // quicly:quictrace_cc_lost
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("quictrace-cc-lost"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->quictrace_cc_lost.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->quictrace_cc_lost.at);
    json_write_pair_c(out_, STR_LIT("min-rtt"), event->quictrace_cc_lost.rtt_minimum);
    json_write_pair_c(out_, STR_LIT("smoothed-rtt"), event->quictrace_cc_lost.rtt_smoothed);
    json_write_pair_c(out_, STR_LIT("variance-rtt"), event->quictrace_cc_lost.rtt_variance);
    json_write_pair_c(out_, STR_LIT("latest-rtt"), event->quictrace_cc_lost.rtt_latest);
    json_write_pair_c(out_, STR_LIT("cwnd"), event->quictrace_cc_lost.cwnd);
    json_write_pair_c(out_, STR_LIT("inflight"), event->quictrace_cc_lost.inflight);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_OPEN: { // quicly:stream_on_open
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-open"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_open.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_open.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_open.stream_stream_id);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_DESTROY: { // quicly:stream_on_destroy
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-destroy"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_destroy.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_destroy.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_destroy.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("err"), event->stream_on_destroy.err);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_SHIFT: { // quicly:stream_on_send_shift
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-send-shift"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_send_shift.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_send_shift.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_send_shift.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("delta"), event->stream_on_send_shift.delta);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_EMIT: { // quicly:stream_on_send_emit
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-send-emit"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_send_emit.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_send_emit.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_send_emit.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_on_send_emit.off);
    json_write_pair_c(out_, STR_LIT("capacity"), event->stream_on_send_emit.capacity);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_STOP: { // quicly:stream_on_send_stop
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-send-stop"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_send_stop.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_send_stop.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_send_stop.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("err"), event->stream_on_send_stop.err);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE: { // quicly:stream_on_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_receive.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_receive.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_receive.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("off"), event->stream_on_receive.off);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("src"), event->stream_on_receive.src, (event->stream_on_receive.src_len < STR_LEN ? event->stream_on_receive.src_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("src-len"), event->stream_on_receive.src_len);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE_RESET: { // quicly:stream_on_receive_reset
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("stream-on-receive-reset"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->stream_on_receive_reset.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->stream_on_receive_reset.at);
    json_write_pair_c(out_, STR_LIT("stream-id"), event->stream_on_receive_reset.stream_stream_id);
    json_write_pair_c(out_, STR_LIT("err"), event->stream_on_receive_reset.err);
    break;
  }
  case H2OLOG_EVENT_ID_QUICLY_CONN_STATS: { // quicly:conn_stats
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("conn-stats"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn"), event->conn_stats.conn_master_id);
    json_write_pair_c(out_, STR_LIT("time"), event->conn_stats.at);
    json_write_pair_c(out_, STR_LIT("stats"), event->conn_stats.stats);
    json_write_pair_c(out_, STR_LIT("size"), event->conn_stats.size);
    break;
  }
  case H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_SNI: { // h2o:_private_socket_lookup_flags_sni
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("-private-socket-lookup-flags-sni"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tid"), event->_private_socket_lookup_flags_sni.tid);
    json_write_pair_c(out_, STR_LIT("original-flags"), event->_private_socket_lookup_flags_sni.original_flags);
    json_write_pair_c(out_, STR_LIT("server-name"), event->_private_socket_lookup_flags_sni.server_name, (event->_private_socket_lookup_flags_sni.server_name_len < STR_LEN ? event->_private_socket_lookup_flags_sni.server_name_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("server-name-len"), event->_private_socket_lookup_flags_sni.server_name_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST: { // h2o:receive_request
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("receive-request"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->receive_request.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->receive_request.req_id);
    json_write_pair_c(out_, STR_LIT("http-version"), event->receive_request.http_version);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST_HEADER: { // h2o:receive_request_header
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("receive-request-header"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->receive_request_header.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->receive_request_header.req_id);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("name"), event->receive_request_header.name, (event->receive_request_header.name_len < STR_LEN ? event->receive_request_header.name_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("name-len"), event->receive_request_header.name_len);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("value"), event->receive_request_header.value, (event->receive_request_header.value_len < STR_LEN ? event->receive_request_header.value_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("value-len"), event->receive_request_header.value_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_SEND_RESPONSE: { // h2o:send_response
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("send-response"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->send_response.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->send_response.req_id);
    json_write_pair_c(out_, STR_LIT("status"), event->send_response.status);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->send_response.tunnel);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_SEND_RESPONSE_HEADER: { // h2o:send_response_header
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("send-response-header"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->send_response_header.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->send_response_header.req_id);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("name"), event->send_response_header.name, (event->send_response_header.name_len < STR_LEN ? event->send_response_header.name_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("name-len"), event->send_response_header.name_len);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("value"), event->send_response_header.value, (event->send_response_header.value_len < STR_LEN ? event->send_response_header.value_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("value-len"), event->send_response_header.value_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H1_ACCEPT: { // h2o:h1_accept
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h1-accept"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h1_accept.conn_id);
    json_write_pair_c(out_, STR_LIT("sock"), event->h1_accept.sock);
    json_write_pair_c(out_, STR_LIT("conn"), event->h1_accept.conn);
    json_write_pair_c(out_, STR_LIT("conn-uuid"), event->h1_accept.conn_uuid, strlen(event->h1_accept.conn_uuid));
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H1_CLOSE: { // h2o:h1_close
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h1-close"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h1_close.conn_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H2_UNKNOWN_FRAME_TYPE: { // h2o:h2_unknown_frame_type
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h2-unknown-frame-type"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h2_unknown_frame_type.conn_id);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->h2_unknown_frame_type.frame_type);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3S_ACCEPT: { // h2o:h3s_accept
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3s-accept"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h3s_accept.conn_id);
    json_write_pair_c(out_, STR_LIT("conn"), event->h3s_accept.conn);
    json_write_pair_c(out_, STR_LIT("quic-master-id"), event->h3s_accept.quic_master_id);
    json_write_pair_c(out_, STR_LIT("conn-uuid"), event->h3s_accept.conn_uuid, strlen(event->h3s_accept.conn_uuid));
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3S_DESTROY: { // h2o:h3s_destroy
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3s-destroy"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h3s_destroy.conn_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3S_STREAM_SET_STATE: { // h2o:h3s_stream_set_state
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3s-stream-set-state"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("conn-id"), event->h3s_stream_set_state.conn_id);
    json_write_pair_c(out_, STR_LIT("req-id"), event->h3s_stream_set_state.req_id);
    json_write_pair_c(out_, STR_LIT("state"), event->h3s_stream_set_state.state);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3_FRAME_RECEIVE: { // h2o:h3_frame_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3-frame-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("frame-type"), event->h3_frame_receive.frame_type);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("bytes"), event->h3_frame_receive.bytes, (event->h3_frame_receive.bytes_len < STR_LEN ? event->h3_frame_receive.bytes_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_frame_receive.bytes_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3_PACKET_RECEIVE: { // h2o:h3_packet_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3-packet-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("dest"), event->h3_packet_receive.dest);
    json_write_pair_c(out_, STR_LIT("src"), event->h3_packet_receive.src);
    json_write_pair_c(out_, STR_LIT("bytes"), event->h3_packet_receive.bytes, (event->h3_packet_receive.bytes_len < STR_LEN ? event->h3_packet_receive.bytes_len : STR_LEN));
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_packet_receive.bytes_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD: { // h2o:h3_packet_forward
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3-packet-forward"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("dest"), event->h3_packet_forward.dest);
    json_write_pair_c(out_, STR_LIT("src"), event->h3_packet_forward.src);
    json_write_pair_c(out_, STR_LIT("num-packets"), event->h3_packet_forward.num_packets);
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_packet_forward.num_bytes);
    json_write_pair_c(out_, STR_LIT("fd"), event->h3_packet_forward.fd);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_NODE_IGNORE: { // h2o:h3_packet_forward_to_node_ignore
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3-packet-forward-to-node-ignore"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("node-id"), event->h3_packet_forward_to_node_ignore.node_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_THREAD_IGNORE: { // h2o:h3_packet_forward_to_thread_ignore
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3-packet-forward-to-thread-ignore"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("thread-id"), event->h3_packet_forward_to_thread_ignore.thread_id);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3_FORWARDED_PACKET_RECEIVE: { // h2o:h3_forwarded_packet_receive
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3-forwarded-packet-receive"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("dest"), event->h3_forwarded_packet_receive.dest);
    json_write_pair_c(out_, STR_LIT("src"), event->h3_forwarded_packet_receive.src);
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->h3_forwarded_packet_receive.num_bytes);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_H3C_TUNNEL_CREATE: { // h2o:h3c_tunnel_create
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("h3c-tunnel-create"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->h3c_tunnel_create.tunnel);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_TUNNEL_ON_DESTROY: { // h2o:tunnel_on_destroy
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("tunnel-on-destroy"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->tunnel_on_destroy.tunnel);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_TUNNEL_ON_READ: { // h2o:tunnel_on_read
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("tunnel-on-read"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->tunnel_on_read.tunnel);
    json_write_pair_c(out_, STR_LIT("err"), event->tunnel_on_read.err, strlen(event->tunnel_on_read.err));
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("bytes"), event->tunnel_on_read.bytes, (event->tunnel_on_read.bytes_len < STR_LEN ? event->tunnel_on_read.bytes_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->tunnel_on_read.bytes_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_TUNNEL_PROCEED_READ: { // h2o:tunnel_proceed_read
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("tunnel-proceed-read"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->tunnel_proceed_read.tunnel);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_TUNNEL_WRITE: { // h2o:tunnel_write
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("tunnel-write"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->tunnel_write.tunnel);
    if (include_appdata_) {
      json_write_pair_c(out_, STR_LIT("bytes"), event->tunnel_write.bytes, (event->tunnel_write.bytes_len < STR_LEN ? event->tunnel_write.bytes_len : STR_LEN));
    }
    json_write_pair_c(out_, STR_LIT("bytes-len"), event->tunnel_write.bytes_len);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_TUNNEL_ON_WRITE_COMPLETE: { // h2o:tunnel_on_write_complete
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("tunnel-on-write-complete"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->tunnel_on_write_complete.tunnel);
    json_write_pair_c(out_, STR_LIT("err"), event->tunnel_on_write_complete.err, strlen(event->tunnel_on_write_complete.err));
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_CREATE: { // h2o:socket_tunnel_create
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("socket-tunnel-create"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->socket_tunnel_create.tunnel);
    json_write_pair_c(out_, STR_LIT("time"), time_milliseconds());
    break;
  }
  case H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_START: { // h2o:socket_tunnel_start
    json_write_pair_n(out_, STR_LIT("type"), STR_LIT("socket-tunnel-start"));
    json_write_pair_c(out_, STR_LIT("tid"), event->tid);
    json_write_pair_c(out_, STR_LIT("seq"), seq_);
    json_write_pair_c(out_, STR_LIT("tunnel"), event->socket_tunnel_start.tunnel);
    json_write_pair_c(out_, STR_LIT("bytes-to-consume"), event->socket_tunnel_start.bytes_to_consume);
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
#include <linux/limits.h>
#include "h2o/ebpf.h"

#define STR_LEN 64

typedef union quicly_address_t {
  uint8_t sa[sizeof_sockaddr];
  uint8_t sin[sizeof_sockaddr_in];
  uint8_t sin6[sizeof_sockaddr_in6];
} quicly_address_t;


enum h2olog_event_id_t {
  H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT,
  H2OLOG_EVENT_ID_QUICLY_CONNECT,
  H2OLOG_EVENT_ID_QUICLY_ACCEPT,
  H2OLOG_EVENT_ID_QUICLY_FREE,
  H2OLOG_EVENT_ID_QUICLY_SEND,
  H2OLOG_EVENT_ID_QUICLY_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_VERSION_SWITCH,
  H2OLOG_EVENT_ID_QUICLY_IDLE_TIMEOUT,
  H2OLOG_EVENT_ID_QUICLY_STATELESS_RESET_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_HANDSHAKE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_UPDATE_SECRET,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE_CONFIRMED,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE,
  H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE_PREPARE,
  H2OLOG_EVENT_ID_QUICLY_PACKET_SENT,
  H2OLOG_EVENT_ID_QUICLY_PACKET_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_PACKET_PREPARE,
  H2OLOG_EVENT_ID_QUICLY_PACKET_ACKED,
  H2OLOG_EVENT_ID_QUICLY_PACKET_LOST,
  H2OLOG_EVENT_ID_QUICLY_PACKET_DECRYPTION_FAILED,
  H2OLOG_EVENT_ID_QUICLY_PTO,
  H2OLOG_EVENT_ID_QUICLY_CC_ACK_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_CC_CONGESTION,
  H2OLOG_EVENT_ID_QUICLY_ACK_BLOCK_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_ACK_DELAY_RECEIVED,
  H2OLOG_EVENT_ID_QUICLY_ACK_SEND,
  H2OLOG_EVENT_ID_QUICLY_PING_SEND,
  H2OLOG_EVENT_ID_QUICLY_PING_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_SEND,
  H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_SEND,
  H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_SEND,
  H2OLOG_EVENT_ID_QUICLY_STREAM_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ACKED,
  H2OLOG_EVENT_ID_QUICLY_STREAM_LOST,
  H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_SEND,
  H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_SEND,
  H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_MAX_DATA_SEND,
  H2OLOG_EVENT_ID_QUICLY_MAX_DATA_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_SEND,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_SEND,
  H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_SEND,
  H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_ACKED,
  H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_SEND,
  H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_SEND,
  H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_SEND,
  H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_SEND,
  H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_SEND,
  H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_SEND,
  H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_DATAGRAM_SEND,
  H2OLOG_EVENT_ID_QUICLY_DATAGRAM_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_ACK_FREQUENCY_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_SEND_STREAM,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_RECV_STREAM,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_ACK,
  H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_LOST,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_OPEN,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_DESTROY,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_SHIFT,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_EMIT,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_STOP,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE,
  H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE_RESET,
  H2OLOG_EVENT_ID_QUICLY_CONN_STATS,
  H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS,
  H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_SNI,
  H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST,
  H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST_HEADER,
  H2OLOG_EVENT_ID_H2O_SEND_RESPONSE,
  H2OLOG_EVENT_ID_H2O_SEND_RESPONSE_HEADER,
  H2OLOG_EVENT_ID_H2O_H1_ACCEPT,
  H2OLOG_EVENT_ID_H2O_H1_CLOSE,
  H2OLOG_EVENT_ID_H2O_H2_UNKNOWN_FRAME_TYPE,
  H2OLOG_EVENT_ID_H2O_H3S_ACCEPT,
  H2OLOG_EVENT_ID_H2O_H3S_DESTROY,
  H2OLOG_EVENT_ID_H2O_H3S_STREAM_SET_STATE,
  H2OLOG_EVENT_ID_H2O_H3_FRAME_RECEIVE,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_RECEIVE,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_NODE_IGNORE,
  H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_THREAD_IGNORE,
  H2OLOG_EVENT_ID_H2O_H3_FORWARDED_PACKET_RECEIVE,
  H2OLOG_EVENT_ID_H2O_H3C_TUNNEL_CREATE,
  H2OLOG_EVENT_ID_H2O_TUNNEL_ON_DESTROY,
  H2OLOG_EVENT_ID_H2O_TUNNEL_ON_READ,
  H2OLOG_EVENT_ID_H2O_TUNNEL_PROCEED_READ,
  H2OLOG_EVENT_ID_H2O_TUNNEL_WRITE,
  H2OLOG_EVENT_ID_H2O_TUNNEL_ON_WRITE_COMPLETE,
  H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_CREATE,
  H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_START,
};


struct h2olog_event_t {
  enum h2olog_event_id_t id;
  uint32_t tid;

  union {
    struct { // quicly:connect
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      char dcid[STR_LEN];
      struct st_quicly_address_token_plaintext_t * address_token;
    } accept;
    struct { // quicly:free
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[STR_LEN];
      size_t bytes_len;
    } receive;
    struct { // quicly:version_switch
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_handshake
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
      char secret[STR_LEN]; // appdata
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN]; // appdata
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN]; // appdata
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN]; // appdata
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_sent
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
      int ack_only;
    } packet_sent;
    struct { // quicly:packet_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      uint8_t decrypted[STR_LEN]; // appdata
      size_t decrypted_len;
      uint8_t packet_type;
    } packet_received;
    struct { // quicly:packet_prepare
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_acked
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      int is_late_ack;
    } packet_acked;
    struct { // quicly:packet_lost
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
      uint8_t packet_type;
    } packet_lost;
    struct { // quicly:packet_decryption_failed
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t pn;
    } packet_decryption_failed;
    struct { // quicly:pto
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:ack_block_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } ack_block_received;
    struct { // quicly:ack_delay_received
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t ack_delay;
    } ack_delay_received;
    struct { // quicly:ack_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t largest_acked;
      uint64_t ack_delay;
    } ack_send;
    struct { // quicly:ping_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } ping_send;
    struct { // quicly:ping_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } ping_receive;
    struct { // quicly:transport_close_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:reset_stream_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
      uint64_t final_size;
    } reset_stream_send;
    struct { // quicly:reset_stream_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
      uint64_t final_size;
    } reset_stream_receive;
    struct { // quicly:stop_sending_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
    } stop_sending_send;
    struct { // quicly:stop_sending_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint16_t error_code;
    } stop_sending_receive;
    struct { // quicly:max_data_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
    } max_data_send;
    struct { // quicly:max_data_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
    } max_data_receive;
    struct { // quicly:max_streams_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t maximum;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t maximum;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t maximum;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:new_connection_id_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_send;
    struct { // quicly:new_connection_id_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_receive;
    struct { // quicly:retire_connection_id_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_send;
    struct { // quicly:retire_connection_id_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_receive;
    struct { // quicly:data_blocked_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_send;
    struct { // quicly:data_blocked_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t maximum;
    } stream_data_blocked_send;
    struct { // quicly:stream_data_blocked_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t maximum;
    } stream_data_blocked_receive;
    struct { // quicly:datagram_send
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t payload[STR_LEN]; // appdata
      size_t payload_len;
    } datagram_send;
    struct { // quicly:datagram_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint8_t payload[STR_LEN]; // appdata
      size_t payload_len;
    } datagram_receive;
    struct { // quicly:ack_frequency_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t packet_tolerance;
      uint64_t max_ack_delay;
      int ignore_order;
    } ack_frequency_receive;
    struct { // quicly:quictrace_send_stream
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_cc_ack
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum rtt_minimum;
      typeof_quicly_rtt_t__smoothed rtt_smoothed;
      typeof_quicly_rtt_t__variance rtt_variance;
      typeof_quicly_rtt_t__latest rtt_latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_quicly_rtt_t__minimum rtt_minimum;
      typeof_quicly_rtt_t__smoothed rtt_smoothed;
      typeof_quicly_rtt_t__variance rtt_variance;
      typeof_quicly_rtt_t__latest rtt_latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // quicly:stream_on_open
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
    } stream_on_open;
    struct { // quicly:stream_on_destroy
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      int err;
    } stream_on_destroy;
    struct { // quicly:stream_on_send_shift
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      size_t delta;
    } stream_on_send_shift;
    struct { // quicly:stream_on_send_emit
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      size_t off;
      size_t capacity;
    } stream_on_send_emit;
    struct { // quicly:stream_on_send_stop
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      int err;
    } stream_on_send_stop;
    struct { // quicly:stream_on_receive
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      size_t off;
      uint8_t src[STR_LEN]; // appdata
      size_t src_len;
    } stream_on_receive;
    struct { // quicly:stream_on_receive_reset
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      typeof_st_quicly_stream_t__stream_id stream_stream_id;
      int err;
    } stream_on_receive_reset;
    struct { // quicly:conn_stats
      typeof_st_quicly_conn_t__master_id conn_master_id;
      int64_t at;
      struct st_quicly_stats_t * stats;
      size_t size;
    } conn_stats;
    struct { // h2o:_private_socket_lookup_flags
      pid_t tid;
      uint64_t original_flags;
      struct st_h2o_ebpf_map_key_t info;
    } _private_socket_lookup_flags;
    struct { // h2o:_private_socket_lookup_flags_sni
      pid_t tid;
      uint64_t original_flags;
      char server_name[STR_LEN];
      size_t server_name_len;
    } _private_socket_lookup_flags_sni;
    struct { // h2o:receive_request
      uint64_t conn_id;
      uint64_t req_id;
      int http_version;
    } receive_request;
    struct { // h2o:receive_request_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN]; // appdata
      size_t name_len;
      char value[STR_LEN]; // appdata
      size_t value_len;
    } receive_request_header;
    struct { // h2o:send_response
      uint64_t conn_id;
      uint64_t req_id;
      int status;
      struct st_h2o_tunnel_t * tunnel;
    } send_response;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN]; // appdata
      size_t name_len;
      char value[STR_LEN]; // appdata
      size_t value_len;
    } send_response_header;
    struct { // h2o:h1_accept
      uint64_t conn_id;
      struct st_h2o_socket_t * sock;
      struct st_h2o_conn_t * conn;
      char conn_uuid[STR_LEN];
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
      struct st_h2o_conn_t * conn;
      typeof_st_quicly_conn_t__master_id quic_master_id;
      char conn_uuid[STR_LEN];
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
      uint8_t bytes[STR_LEN]; // appdata
      size_t bytes_len;
    } h3_frame_receive;
    struct { // h2o:h3_packet_receive
      quicly_address_t dest;
      quicly_address_t src;
      uint8_t bytes[STR_LEN];
      size_t bytes_len;
    } h3_packet_receive;
    struct { // h2o:h3_packet_forward
      quicly_address_t dest;
      quicly_address_t src;
      size_t num_packets;
      size_t num_bytes;
      int fd;
    } h3_packet_forward;
    struct { // h2o:h3_packet_forward_to_node_ignore
      uint64_t node_id;
    } h3_packet_forward_to_node_ignore;
    struct { // h2o:h3_packet_forward_to_thread_ignore
      uint32_t thread_id;
    } h3_packet_forward_to_thread_ignore;
    struct { // h2o:h3_forwarded_packet_receive
      quicly_address_t dest;
      quicly_address_t src;
      size_t num_bytes;
    } h3_forwarded_packet_receive;
    struct { // h2o:h3c_tunnel_create
      struct st_h2o_tunnel_t * tunnel;
    } h3c_tunnel_create;
    struct { // h2o:tunnel_on_destroy
      struct st_h2o_tunnel_t * tunnel;
    } tunnel_on_destroy;
    struct { // h2o:tunnel_on_read
      struct st_h2o_tunnel_t * tunnel;
      char err[STR_LEN];
      uint8_t bytes[STR_LEN]; // appdata
      size_t bytes_len;
    } tunnel_on_read;
    struct { // h2o:tunnel_proceed_read
      struct st_h2o_tunnel_t * tunnel;
    } tunnel_proceed_read;
    struct { // h2o:tunnel_write
      struct st_h2o_tunnel_t * tunnel;
      uint8_t bytes[STR_LEN]; // appdata
      size_t bytes_len;
    } tunnel_write;
    struct { // h2o:tunnel_on_write_complete
      struct st_h2o_tunnel_t * tunnel;
      char err[STR_LEN];
    } tunnel_on_write_complete;
    struct { // h2o:socket_tunnel_create
      struct st_h2o_tunnel_t * tunnel;
    } socket_tunnel_create;
    struct { // h2o:socket_tunnel_start
      struct st_h2o_tunnel_t * tunnel;
      size_t bytes_to_consume;
    } socket_tunnel_start;

  };
};

BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);

#if H2OLOG_SELECTIVE_TRACING
// A pinned BPF object to return a value to h2o.
// The table size must be larger than the number of threads in h2o.
BPF_TABLE_PINNED("lru_hash", pid_t, uint64_t, h2o_return, H2O_EBPF_RETURN_MAP_SIZE, H2O_EBPF_RETURN_MAP_PATH);
#endif

// tracepoint sched:sched_process_exit
int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  pid_t h2o_pid = task->tgid;
  pid_t h2o_tid = task->pid;
  if (!(h2o_pid == H2OLOG_H2O_PID && h2o_tid == H2OLOG_H2O_PID)) {
    return 0;
  }
  struct h2olog_event_t ev = { .id = H2OLOG_EVENT_ID_SCHED_SCHED_PROCESS_EXIT };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

// quicly:connect
int trace_quicly__connect(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CONNECT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.connect.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_ACCEPT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.accept.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.accept.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.accept.dcid, sizeof(event.accept.dcid), buf);
  // struct st_quicly_address_token_plaintext_t * address_token
  bpf_usdt_readarg(4, ctx, &event.accept.address_token);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__accept\n");

  return 0;
}
// quicly:free
int trace_quicly__free(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_FREE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.free.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.free.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__free\n");

  return 0;
}
// quicly:send
int trace_quicly__send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_VERSION_SWITCH, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.version_switch.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_IDLE_TIMEOUT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.idle_timeout.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.idle_timeout.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__idle_timeout\n");

  return 0;
}
// quicly:stateless_reset_receive
int trace_quicly__stateless_reset_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STATELESS_RESET_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stateless_reset_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stateless_reset_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stateless_reset_receive\n");

  return 0;
}
// quicly:crypto_handshake
int trace_quicly__crypto_handshake(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CRYPTO_HANDSHAKE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_handshake.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CRYPTO_UPDATE_SECRET, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_update_secret.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_update_secret.at);
  // int is_enc
  bpf_usdt_readarg(3, ctx, &event.crypto_update_secret.is_enc);
  // uint8_t epoch
  bpf_usdt_readarg(4, ctx, &event.crypto_update_secret.epoch);
  // const char * label
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.crypto_update_secret.label, sizeof(event.crypto_update_secret.label), buf);
  // const char * secret (appdata)
  bpf_usdt_readarg(6, ctx, &buf);
  bpf_probe_read(&event.crypto_update_secret.secret, sizeof(event.crypto_update_secret.secret), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_update_secret\n");

  return 0;
}
// quicly:crypto_send_key_update
int trace_quicly__crypto_send_key_update(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_send_key_update.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update.phase);
  // const char * secret (appdata)
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.crypto_send_key_update.secret, sizeof(event.crypto_send_key_update.secret), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_send_key_update\n");

  return 0;
}
// quicly:crypto_send_key_update_confirmed
int trace_quicly__crypto_send_key_update_confirmed(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CRYPTO_SEND_KEY_UPDATE_CONFIRMED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_send_key_update_confirmed.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_receive_key_update.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update.phase);
  // const char * secret (appdata)
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.crypto_receive_key_update.secret, sizeof(event.crypto_receive_key_update.secret), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_receive_key_update\n");

  return 0;
}
// quicly:crypto_receive_key_update_prepare
int trace_quicly__crypto_receive_key_update_prepare(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CRYPTO_RECEIVE_KEY_UPDATE_PREPARE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.crypto_receive_key_update_prepare.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update_prepare.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update_prepare.phase);
  // const char * secret (appdata)
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.crypto_receive_key_update_prepare.secret, sizeof(event.crypto_receive_key_update_prepare.secret), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__crypto_receive_key_update_prepare\n");

  return 0;
}
// quicly:packet_sent
int trace_quicly__packet_sent(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PACKET_SENT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_sent.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_sent.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_sent.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.packet_sent.len);
  // uint8_t packet_type
  bpf_usdt_readarg(5, ctx, &event.packet_sent.packet_type);
  // int ack_only
  bpf_usdt_readarg(6, ctx, &event.packet_sent.ack_only);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_sent\n");

  return 0;
}
// quicly:packet_received
int trace_quicly__packet_received(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PACKET_RECEIVED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_received.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_received.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_received.pn);
  // const void * decrypted (appdata)
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.packet_received.decrypted, sizeof(event.packet_received.decrypted), buf);
  // size_t decrypted_len
  bpf_usdt_readarg(5, ctx, &event.packet_received.decrypted_len);
  // uint8_t packet_type
  bpf_usdt_readarg(6, ctx, &event.packet_received.packet_type);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_received\n");

  return 0;
}
// quicly:packet_prepare
int trace_quicly__packet_prepare(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PACKET_PREPARE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_prepare.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
// quicly:packet_acked
int trace_quicly__packet_acked(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PACKET_ACKED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_acked.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PACKET_LOST, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_lost.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_lost.pn);
  // uint8_t packet_type
  bpf_usdt_readarg(4, ctx, &event.packet_lost.packet_type);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_lost\n");

  return 0;
}
// quicly:packet_decryption_failed
int trace_quicly__packet_decryption_failed(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PACKET_DECRYPTION_FAILED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.packet_decryption_failed.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_decryption_failed.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_decryption_failed.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__packet_decryption_failed\n");

  return 0;
}
// quicly:pto
int trace_quicly__pto(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PTO, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.pto.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CC_ACK_RECEIVED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.cc_ack_received.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CC_CONGESTION, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.cc_congestion.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
// quicly:ack_block_received
int trace_quicly__ack_block_received(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_ACK_BLOCK_RECEIVED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ack_block_received.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ack_block_received.at);
  // uint64_t ack_block_begin
  bpf_usdt_readarg(3, ctx, &event.ack_block_received.ack_block_begin);
  // uint64_t ack_block_end
  bpf_usdt_readarg(4, ctx, &event.ack_block_received.ack_block_end);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ack_block_received\n");

  return 0;
}
// quicly:ack_delay_received
int trace_quicly__ack_delay_received(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_ACK_DELAY_RECEIVED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ack_delay_received.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ack_delay_received.at);
  // int64_t ack_delay
  bpf_usdt_readarg(3, ctx, &event.ack_delay_received.ack_delay);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ack_delay_received\n");

  return 0;
}
// quicly:ack_send
int trace_quicly__ack_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_ACK_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ack_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PING_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ping_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ping_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ping_send\n");

  return 0;
}
// quicly:ping_receive
int trace_quicly__ping_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_PING_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ping_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ping_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__ping_receive\n");

  return 0;
}
// quicly:transport_close_send
int trace_quicly__transport_close_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.transport_close_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_TRANSPORT_CLOSE_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.transport_close_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.application_close_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_APPLICATION_CLOSE_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.application_close_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_send.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_send.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_receive.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_receive.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ACKED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_acked.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_LOST, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_lost.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
// quicly:reset_stream_send
int trace_quicly__reset_stream_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.reset_stream_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.reset_stream_send.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.reset_stream_send.stream_id);
  // uint16_t error_code
  bpf_usdt_readarg(4, ctx, &event.reset_stream_send.error_code);
  // uint64_t final_size
  bpf_usdt_readarg(5, ctx, &event.reset_stream_send.final_size);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__reset_stream_send\n");

  return 0;
}
// quicly:reset_stream_receive
int trace_quicly__reset_stream_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_RESET_STREAM_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.reset_stream_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.reset_stream_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.reset_stream_receive.stream_id);
  // uint16_t error_code
  bpf_usdt_readarg(4, ctx, &event.reset_stream_receive.error_code);
  // uint64_t final_size
  bpf_usdt_readarg(5, ctx, &event.reset_stream_receive.final_size);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__reset_stream_receive\n");

  return 0;
}
// quicly:stop_sending_send
int trace_quicly__stop_sending_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stop_sending_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stop_sending_send.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stop_sending_send.stream_id);
  // uint16_t error_code
  bpf_usdt_readarg(4, ctx, &event.stop_sending_send.error_code);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stop_sending_send\n");

  return 0;
}
// quicly:stop_sending_receive
int trace_quicly__stop_sending_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STOP_SENDING_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stop_sending_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stop_sending_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stop_sending_receive.stream_id);
  // uint16_t error_code
  bpf_usdt_readarg(4, ctx, &event.stop_sending_receive.error_code);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stop_sending_receive\n");

  return 0;
}
// quicly:max_data_send
int trace_quicly__max_data_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_MAX_DATA_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_data_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_send.at);
  // uint64_t maximum
  bpf_usdt_readarg(3, ctx, &event.max_data_send.maximum);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_data_send\n");

  return 0;
}
// quicly:max_data_receive
int trace_quicly__max_data_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_MAX_DATA_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_data_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_receive.at);
  // uint64_t maximum
  bpf_usdt_readarg(3, ctx, &event.max_data_receive.maximum);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_data_receive\n");

  return 0;
}
// quicly:max_streams_send
int trace_quicly__max_streams_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_streams_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_send.at);
  // uint64_t maximum
  bpf_usdt_readarg(3, ctx, &event.max_streams_send.maximum);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_streams_send\n");

  return 0;
}
// quicly:max_streams_receive
int trace_quicly__max_streams_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_MAX_STREAMS_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_streams_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_receive.at);
  // uint64_t maximum
  bpf_usdt_readarg(3, ctx, &event.max_streams_receive.maximum);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_streams_receive\n");

  return 0;
}
// quicly:max_stream_data_send
int trace_quicly__max_stream_data_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_stream_data_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_send.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.max_stream_data_send.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
  // uint64_t maximum
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_send.maximum);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_stream_data_send\n");

  return 0;
}
// quicly:max_stream_data_receive
int trace_quicly__max_stream_data_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_MAX_STREAM_DATA_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.max_stream_data_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.max_stream_data_receive.stream_id);
  // uint64_t maximum
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_receive.maximum);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__max_stream_data_receive\n");

  return 0;
}
// quicly:new_token_send
int trace_quicly__new_token_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_token_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_ACKED, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_token_acked.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_NEW_TOKEN_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_token_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.handshake_done_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__handshake_done_send\n");

  return 0;
}
// quicly:handshake_done_receive
int trace_quicly__handshake_done_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_HANDSHAKE_DONE_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.handshake_done_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__handshake_done_receive\n");

  return 0;
}
// quicly:streams_blocked_send
int trace_quicly__streams_blocked_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.streams_blocked_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_send.at);
  // uint64_t maximum
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_send.maximum);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__streams_blocked_send\n");

  return 0;
}
// quicly:streams_blocked_receive
int trace_quicly__streams_blocked_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAMS_BLOCKED_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.streams_blocked_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_receive.at);
  // uint64_t maximum
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_receive.maximum);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__streams_blocked_receive\n");

  return 0;
}
// quicly:new_connection_id_send
int trace_quicly__new_connection_id_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_connection_id_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_NEW_CONNECTION_ID_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.new_connection_id_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.retire_connection_id_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_RETIRE_CONNECTION_ID_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.retire_connection_id_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.data_blocked_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_DATA_BLOCKED_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.data_blocked_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_data_blocked_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_data_blocked_send.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_data_blocked_send.stream_id);
  // uint64_t maximum
  bpf_usdt_readarg(4, ctx, &event.stream_data_blocked_send.maximum);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_data_blocked_send\n");

  return 0;
}
// quicly:stream_data_blocked_receive
int trace_quicly__stream_data_blocked_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_DATA_BLOCKED_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_data_blocked_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_data_blocked_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_data_blocked_receive.stream_id);
  // uint64_t maximum
  bpf_usdt_readarg(4, ctx, &event.stream_data_blocked_receive.maximum);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_data_blocked_receive\n");

  return 0;
}
// quicly:datagram_send
int trace_quicly__datagram_send(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_DATAGRAM_SEND, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.datagram_send.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.datagram_send.at);
  // const void * payload (appdata)
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_DATAGRAM_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.datagram_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.datagram_receive.at);
  // const void * payload (appdata)
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_ACK_FREQUENCY_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.ack_frequency_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
// quicly:quictrace_send_stream
int trace_quicly__quictrace_send_stream(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_QUICTRACE_SEND_STREAM, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_send_stream.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_send_stream.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.quictrace_send_stream.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_QUICTRACE_RECV_STREAM, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_recv_stream.conn_master_id = get_st_quicly_conn_t__master_id(conn);
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
// quicly:quictrace_cc_ack
int trace_quicly__quictrace_cc_ack(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_ACK, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_cc_ack.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_ack.at);
  // struct quicly_rtt_t * rtt
  uint8_t rtt[sizeof_quicly_rtt_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof_quicly_rtt_t, buf);
  event.quictrace_cc_ack.rtt_minimum = get_quicly_rtt_t__minimum(rtt);
  event.quictrace_cc_ack.rtt_smoothed = get_quicly_rtt_t__smoothed(rtt);
  event.quictrace_cc_ack.rtt_variance = get_quicly_rtt_t__variance(rtt);
  event.quictrace_cc_ack.rtt_latest = get_quicly_rtt_t__latest(rtt);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_QUICTRACE_CC_LOST, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.quictrace_cc_lost.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_lost.at);
  // struct quicly_rtt_t * rtt
  uint8_t rtt[sizeof_quicly_rtt_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof_quicly_rtt_t, buf);
  event.quictrace_cc_lost.rtt_minimum = get_quicly_rtt_t__minimum(rtt);
  event.quictrace_cc_lost.rtt_smoothed = get_quicly_rtt_t__smoothed(rtt);
  event.quictrace_cc_lost.rtt_variance = get_quicly_rtt_t__variance(rtt);
  event.quictrace_cc_lost.rtt_latest = get_quicly_rtt_t__latest(rtt);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_OPEN, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_open.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_open.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_open.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_open\n");

  return 0;
}
// quicly:stream_on_destroy
int trace_quicly__stream_on_destroy(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_DESTROY, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_destroy.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_destroy.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_destroy.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
  // int err
  bpf_usdt_readarg(4, ctx, &event.stream_on_destroy.err);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_destroy\n");

  return 0;
}
// quicly:stream_on_send_shift
int trace_quicly__stream_on_send_shift(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_SHIFT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_send_shift.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_send_shift.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_send_shift.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
  // size_t delta
  bpf_usdt_readarg(4, ctx, &event.stream_on_send_shift.delta);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_send_shift\n");

  return 0;
}
// quicly:stream_on_send_emit
int trace_quicly__stream_on_send_emit(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_EMIT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_send_emit.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_send_emit.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_send_emit.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_SEND_STOP, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_send_stop.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_send_stop.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_send_stop.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
  // int err
  bpf_usdt_readarg(4, ctx, &event.stream_on_send_stop.err);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_send_stop\n");

  return 0;
}
// quicly:stream_on_receive
int trace_quicly__stream_on_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_receive.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_receive.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_receive.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
  // size_t off
  bpf_usdt_readarg(4, ctx, &event.stream_on_receive.off);
  // const void * src (appdata)
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_STREAM_ON_RECEIVE_RESET, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.stream_on_receive_reset.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_on_receive_reset.at);
  // struct st_quicly_stream_t * stream
  uint8_t stream[sizeof_st_quicly_stream_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof_st_quicly_stream_t, buf);
  event.stream_on_receive_reset.stream_stream_id = get_st_quicly_stream_t__stream_id(stream);
  // int err
  bpf_usdt_readarg(4, ctx, &event.stream_on_receive_reset.err);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__stream_on_receive_reset\n");

  return 0;
}
// quicly:conn_stats
int trace_quicly__conn_stats(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_QUICLY_CONN_STATS, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_quicly_conn_t * conn
  uint8_t conn[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof_st_quicly_conn_t, buf);
  event.conn_stats.conn_master_id = get_st_quicly_conn_t__master_id(conn);
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.conn_stats.at);
  // struct st_quicly_stats_t * stats
  bpf_usdt_readarg(3, ctx, &event.conn_stats.stats);
  // size_t size
  bpf_usdt_readarg(4, ctx, &event.conn_stats.size);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_quicly__conn_stats\n");

  return 0;
}

#if H2OLOG_SELECTIVE_TRACING
// h2o:_private_socket_lookup_flags
int trace_h2o___private_socket_lookup_flags(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // pid_t tid
  bpf_usdt_readarg(1, ctx, &event._private_socket_lookup_flags.tid);
  // uint64_t original_flags
  bpf_usdt_readarg(2, ctx, &event._private_socket_lookup_flags.original_flags);
  // struct st_h2o_ebpf_map_key_t * info
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event._private_socket_lookup_flags.info, sizeof_st_h2o_ebpf_map_key_t, buf);

  uint64_t flags = event._private_socket_lookup_flags.original_flags;
#ifdef H2OLOG_SAMPLING_RATE_U32
  if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) == 0) {
    if (bpf_get_prandom_u32() >= H2OLOG_SAMPLING_RATE_U32)
      flags |= H2O_EBPF_FLAGS_SKIP_TRACING_BIT;
  }
#endif
#ifdef H2OLOG_IS_SAMPLING_ADDRESS
  if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) == 0) {
    if (!H2OLOG_IS_SAMPLING_ADDRESS(event._private_socket_lookup_flags.info.family,
                                    event._private_socket_lookup_flags.info.remote.ip))
      flags |= H2O_EBPF_FLAGS_SKIP_TRACING_BIT;
  }
#endif
  int64_t ret = h2o_return.insert(&event._private_socket_lookup_flags.tid, &flags);
  if (ret != 0)
    bpf_trace_printk("failed to insert 0x%llx in trace_h2o___private_socket_lookup_flags with errno=%lld\n", flags, -ret);

  return 0;
}
#endif


#if H2OLOG_SELECTIVE_TRACING
// h2o:_private_socket_lookup_flags_sni
int trace_h2o___private_socket_lookup_flags_sni(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O__PRIVATE_SOCKET_LOOKUP_FLAGS_SNI, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // pid_t tid
  bpf_usdt_readarg(1, ctx, &event._private_socket_lookup_flags_sni.tid);
  // uint64_t original_flags
  bpf_usdt_readarg(2, ctx, &event._private_socket_lookup_flags_sni.original_flags);
  // const char * server_name
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event._private_socket_lookup_flags_sni.server_name, sizeof(event._private_socket_lookup_flags_sni.server_name), buf);
  // size_t server_name_len
  bpf_usdt_readarg(4, ctx, &event._private_socket_lookup_flags_sni.server_name_len);

  uint64_t flags  = event._private_socket_lookup_flags_sni.original_flags;
  if ((flags & H2O_EBPF_FLAGS_SKIP_TRACING_BIT) != 0) {
#ifdef H2OLOG_IS_SAMPLING_SNI
    size_t server_name_len = event._private_socket_lookup_flags_sni.server_name_len;
    if (server_name_len > sizeof(event._private_socket_lookup_flags_sni.server_name))
      server_name_len = sizeof(event._private_socket_lookup_flags_sni.server_name);
    if (H2OLOG_IS_SAMPLING_SNI(event._private_socket_lookup_flags_sni.server_name, server_name_len)
#ifdef H2OLOG_SAMPLING_RATE_U32
        && bpf_get_prandom_u32() < H2OLOG_SAMPLING_RATE_U32
#endif
      )
      flags &= ~H2O_EBPF_FLAGS_SKIP_TRACING_BIT;
#endif
  }
  int64_t ret = h2o_return.insert(&event._private_socket_lookup_flags_sni.tid, &flags);
  if (ret != 0)
    bpf_trace_printk("failed to insert 0x%lx in trace_h2o___private_socket_lookup_flags_sni with errno=%lld\n", flags, -ret);

  return 0;
}
#endif

// h2o:receive_request
int trace_h2o__receive_request(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_RECEIVE_REQUEST_HEADER, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.receive_request_header.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.receive_request_header.req_id);
  // const char * name (appdata)
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.receive_request_header.name, sizeof(event.receive_request_header.name), buf);
  // size_t name_len
  bpf_usdt_readarg(4, ctx, &event.receive_request_header.name_len);
  // const char * value (appdata)
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_SEND_RESPONSE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.send_response.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.send_response.req_id);
  // int status
  bpf_usdt_readarg(3, ctx, &event.send_response.status);
  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(4, ctx, &event.send_response.tunnel);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__send_response\n");

  return 0;
}
// h2o:send_response_header
int trace_h2o__send_response_header(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_SEND_RESPONSE_HEADER, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.send_response_header.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.send_response_header.req_id);
  // const char * name (appdata)
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.send_response_header.name, sizeof(event.send_response_header.name), buf);
  // size_t name_len
  bpf_usdt_readarg(4, ctx, &event.send_response_header.name_len);
  // const char * value (appdata)
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H1_ACCEPT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h1_accept.conn_id);
  // struct st_h2o_socket_t * sock
  bpf_usdt_readarg(2, ctx, &event.h1_accept.sock);
  // struct st_h2o_conn_t * conn
  bpf_usdt_readarg(3, ctx, &event.h1_accept.conn);
  // const char * conn_uuid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.h1_accept.conn_uuid, sizeof(event.h1_accept.conn_uuid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h1_accept\n");

  return 0;
}
// h2o:h1_close
int trace_h2o__h1_close(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H1_CLOSE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h1_close.conn_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h1_close\n");

  return 0;
}
// h2o:h2_unknown_frame_type
int trace_h2o__h2_unknown_frame_type(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H2_UNKNOWN_FRAME_TYPE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3S_ACCEPT, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3s_accept.conn_id);
  // struct st_h2o_conn_t * conn
  bpf_usdt_readarg(2, ctx, &event.h3s_accept.conn);
  // struct st_quicly_conn_t * quic
  uint8_t quic[sizeof_st_quicly_conn_t] = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&quic, sizeof_st_quicly_conn_t, buf);
  event.h3s_accept.quic_master_id = get_st_quicly_conn_t__master_id(quic);
  // const char * conn_uuid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.h3s_accept.conn_uuid, sizeof(event.h3s_accept.conn_uuid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3s_accept\n");

  return 0;
}
// h2o:h3s_destroy
int trace_h2o__h3s_destroy(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3S_DESTROY, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3s_destroy.conn_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3s_destroy\n");

  return 0;
}
// h2o:h3s_stream_set_state
int trace_h2o__h3s_stream_set_state(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3S_STREAM_SET_STATE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3_FRAME_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t frame_type
  bpf_usdt_readarg(1, ctx, &event.h3_frame_receive.frame_type);
  // const void * bytes (appdata)
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
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3_PACKET_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

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
  // const void * bytes
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.h3_packet_receive.bytes, sizeof(event.h3_packet_receive.bytes), buf);
  // size_t bytes_len
  bpf_usdt_readarg(4, ctx, &event.h3_packet_receive.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_packet_receive\n");

  return 0;
}
// h2o:h3_packet_forward
int trace_h2o__h3_packet_forward(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

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
// h2o:h3_packet_forward_to_node_ignore
int trace_h2o__h3_packet_forward_to_node_ignore(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_NODE_IGNORE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint64_t node_id
  bpf_usdt_readarg(1, ctx, &event.h3_packet_forward_to_node_ignore.node_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_packet_forward_to_node_ignore\n");

  return 0;
}
// h2o:h3_packet_forward_to_thread_ignore
int trace_h2o__h3_packet_forward_to_thread_ignore(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3_PACKET_FORWARD_TO_THREAD_IGNORE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // uint32_t thread_id
  bpf_usdt_readarg(1, ctx, &event.h3_packet_forward_to_thread_ignore.thread_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_packet_forward_to_thread_ignore\n");

  return 0;
}
// h2o:h3_forwarded_packet_receive
int trace_h2o__h3_forwarded_packet_receive(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3_FORWARDED_PACKET_RECEIVE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct sockaddr * dest
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&event.h3_forwarded_packet_receive.dest, sizeof_sockaddr, buf);
  if (get_sockaddr__sa_family(&event.h3_forwarded_packet_receive.dest) == AF_INET) {
    bpf_probe_read(&event.h3_forwarded_packet_receive.dest, sizeof_sockaddr_in, buf);
  } else if (get_sockaddr__sa_family(&event.h3_forwarded_packet_receive.dest) == AF_INET6) {
    bpf_probe_read(&event.h3_forwarded_packet_receive.dest, sizeof_sockaddr_in6, buf);
  }
  // struct sockaddr * src
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.h3_forwarded_packet_receive.src, sizeof_sockaddr, buf);
  if (get_sockaddr__sa_family(&event.h3_forwarded_packet_receive.src) == AF_INET) {
    bpf_probe_read(&event.h3_forwarded_packet_receive.src, sizeof_sockaddr_in, buf);
  } else if (get_sockaddr__sa_family(&event.h3_forwarded_packet_receive.src) == AF_INET6) {
    bpf_probe_read(&event.h3_forwarded_packet_receive.src, sizeof_sockaddr_in6, buf);
  }
  // size_t num_bytes
  bpf_usdt_readarg(3, ctx, &event.h3_forwarded_packet_receive.num_bytes);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3_forwarded_packet_receive\n");

  return 0;
}
// h2o:h3c_tunnel_create
int trace_h2o__h3c_tunnel_create(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_H3C_TUNNEL_CREATE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.h3c_tunnel_create.tunnel);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__h3c_tunnel_create\n");

  return 0;
}
// h2o:tunnel_on_destroy
int trace_h2o__tunnel_on_destroy(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_TUNNEL_ON_DESTROY, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.tunnel_on_destroy.tunnel);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__tunnel_on_destroy\n");

  return 0;
}
// h2o:tunnel_on_read
int trace_h2o__tunnel_on_read(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_TUNNEL_ON_READ, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.tunnel_on_read.tunnel);
  // const char * err
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.tunnel_on_read.err, sizeof(event.tunnel_on_read.err), buf);
  // const void * bytes (appdata)
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.tunnel_on_read.bytes, sizeof(event.tunnel_on_read.bytes), buf);
  // size_t bytes_len
  bpf_usdt_readarg(4, ctx, &event.tunnel_on_read.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__tunnel_on_read\n");

  return 0;
}
// h2o:tunnel_proceed_read
int trace_h2o__tunnel_proceed_read(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_TUNNEL_PROCEED_READ, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.tunnel_proceed_read.tunnel);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__tunnel_proceed_read\n");

  return 0;
}
// h2o:tunnel_write
int trace_h2o__tunnel_write(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_TUNNEL_WRITE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.tunnel_write.tunnel);
  // const void * bytes (appdata)
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.tunnel_write.bytes, sizeof(event.tunnel_write.bytes), buf);
  // size_t bytes_len
  bpf_usdt_readarg(3, ctx, &event.tunnel_write.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__tunnel_write\n");

  return 0;
}
// h2o:tunnel_on_write_complete
int trace_h2o__tunnel_on_write_complete(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_TUNNEL_ON_WRITE_COMPLETE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.tunnel_on_write_complete.tunnel);
  // const char * err
  bpf_usdt_readarg(2, ctx, &buf);
  bpf_probe_read(&event.tunnel_on_write_complete.err, sizeof(event.tunnel_on_write_complete.err), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__tunnel_on_write_complete\n");

  return 0;
}
// h2o:socket_tunnel_create
int trace_h2o__socket_tunnel_create(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_CREATE, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.socket_tunnel_create.tunnel);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__socket_tunnel_create\n");

  return 0;
}
// h2o:socket_tunnel_start
int trace_h2o__socket_tunnel_start(struct pt_regs *ctx) {
  const void *buf = NULL;
  struct h2olog_event_t event = { .id = H2OLOG_EVENT_ID_H2O_SOCKET_TUNNEL_START, .tid = (uint32_t)bpf_get_current_pid_tgid(), };

  // struct st_h2o_tunnel_t * tunnel
  bpf_usdt_readarg(1, ctx, &event.socket_tunnel_start.tunnel);
  // size_t bytes_to_consume
  bpf_usdt_readarg(2, ctx, &event.socket_tunnel_start.bytes_to_consume);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit in trace_h2o__socket_tunnel_start\n");

  return 0;
}

)";
}

