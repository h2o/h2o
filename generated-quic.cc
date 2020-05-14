// Generated code. Do not edit it here!

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include "h2olog.h"
#include "quic.h"
#include "json.h"

#define STR_LEN 64
#define STR_LIT(s) s, strlen(s)

// BPF modules written in C
const char *bpf_text = R"(

#include <linux/sched.h>

#define STR_LEN 64
/*
 * Copyright (c) 2019-2020 Fastly, Inc., Toru Maesaka, Goro Fuji
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

#ifndef H2OLOG_QUIC_H
#define H2OLOG_QUIC_H

/*
 * These structs mirror H2O's internal structs. As the name suggests, dummy
 * fields are paddings that are ignored.
 */
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

struct st_h2o_conn_t {
    int dummy;
};

#endif


struct quic_event_t {
  uint8_t id;

  union {
    struct { // quicly:connect
      uint32_t master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
    } accept;
    struct { // quicly:free
      uint32_t master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      uint32_t master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[STR_LEN];
      size_t num_bytes;
    } receive;
    struct { // quicly:version_switch
      uint32_t master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      uint32_t master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      uint32_t master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_decrypt
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      uint8_t decrypted[STR_LEN];
      size_t decrypted_len;
    } crypto_decrypt;
    struct { // quicly:crypto_handshake
      uint32_t master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      uint32_t master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
      char secret[STR_LEN];
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN];
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      uint32_t master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN];
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN];
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_prepare
      uint32_t master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_commit
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      int ack_only;
    } packet_commit;
    struct { // quicly:packet_acked
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      int newly_acked;
    } packet_acked;
    struct { // quicly:packet_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } packet_lost;
    struct { // quicly:pto
      uint32_t master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      uint32_t master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      uint32_t master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:transport_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:max_data_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_send;
    struct { // quicly:max_data_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_receive;
    struct { // quicly:max_streams_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      uint32_t master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      uint32_t master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      uint32_t master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:data_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_receive;
    struct { // quicly:quictrace_sent
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
    } quictrace_sent;
    struct { // quicly:quictrace_recv
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_recv;
    struct { // quicly:quictrace_send_stream
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_recv_ack
      uint32_t master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } quictrace_recv_ack;
    struct { // quicly:quictrace_recv_ack_delay
      uint32_t master_id;
      int64_t at;
      int64_t ack_delay;
    } quictrace_recv_ack_delay;
    struct { // quicly:quictrace_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_lost;
    struct { // quicly:quictrace_cc_ack
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t latest;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t latest;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // h2o:h3_accept
      uint64_t conn_id;
      uint32_t master_id;
    } h3_accept;
    struct { // h2o:h3_close
      uint64_t conn_id;
      uint32_t master_id;
    } h3_close;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
      uint32_t master_id;
    } send_response_header;

    };
  };
  
BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);

// tracepoint sched:sched_process_exit
int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  if (task->tgid != H2OLOG_H2O_PID) {
    return 0;
  }
  struct quic_event_t ev = { .id = 1 };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

// quicly:connect
int trace_quicly__connect(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 2 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.connect.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.connect.at);
  // uint32_t version
  bpf_usdt_readarg(3, ctx, &event.connect.version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:accept
int trace_quicly__accept(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 3 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.accept.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.accept.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.accept.dcid, sizeof(event.accept.dcid), buf);
  // struct st_quicly_address_token_plaintext_t * address_token
  struct st_quicly_address_token_plaintext_t  address_token = {};
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&address_token, sizeof(address_token), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:free
int trace_quicly__free(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 4 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.free.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.free.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:send
int trace_quicly__send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 5 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.send.at);
  // int state
  bpf_usdt_readarg(3, ctx, &event.send.state);
  // const char * dcid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.send.dcid, sizeof(event.send.dcid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:receive
int trace_quicly__receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 6 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.receive.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.receive.dcid, sizeof(event.receive.dcid), buf);
  // const void * bytes (ignored)
  // size_t num_bytes
  bpf_usdt_readarg(5, ctx, &event.receive.num_bytes);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:version_switch
int trace_quicly__version_switch(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 7 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.version_switch.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.version_switch.at);
  // uint32_t new_version
  bpf_usdt_readarg(3, ctx, &event.version_switch.new_version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:idle_timeout
int trace_quicly__idle_timeout(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 8 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.idle_timeout.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.idle_timeout.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stateless_reset_receive
int trace_quicly__stateless_reset_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 9 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stateless_reset_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stateless_reset_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_decrypt
int trace_quicly__crypto_decrypt(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 10 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_decrypt.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_decrypt.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.crypto_decrypt.pn);
  // const void * decrypted (ignored)
  // size_t decrypted_len
  bpf_usdt_readarg(5, ctx, &event.crypto_decrypt.decrypted_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_handshake
int trace_quicly__crypto_handshake(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 11 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_handshake.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_handshake.at);
  // int ret
  bpf_usdt_readarg(3, ctx, &event.crypto_handshake.ret);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_update_secret
int trace_quicly__crypto_update_secret(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 12 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_update_secret.master_id = conn.master_id; /* uint32_t */
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
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_send_key_update
int trace_quicly__crypto_send_key_update(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 13 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_send_key_update.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_send_key_update_confirmed
int trace_quicly__crypto_send_key_update_confirmed(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 14 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_send_key_update_confirmed.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update_confirmed.at);
  // uint64_t next_pn
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update_confirmed.next_pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_receive_key_update
int trace_quicly__crypto_receive_key_update(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 15 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_receive_key_update.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_receive_key_update_prepare
int trace_quicly__crypto_receive_key_update_prepare(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 16 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_receive_key_update_prepare.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update_prepare.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update_prepare.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_prepare
int trace_quicly__packet_prepare(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 17 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_prepare.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_prepare.at);
  // uint8_t first_octet
  bpf_usdt_readarg(3, ctx, &event.packet_prepare.first_octet);
  // const char * dcid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.packet_prepare.dcid, sizeof(event.packet_prepare.dcid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_commit
int trace_quicly__packet_commit(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 18 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_commit.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_commit.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_commit.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.packet_commit.len);
  // int ack_only
  bpf_usdt_readarg(5, ctx, &event.packet_commit.ack_only);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_acked
int trace_quicly__packet_acked(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 19 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_acked.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_acked.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_acked.pn);
  // int newly_acked
  bpf_usdt_readarg(4, ctx, &event.packet_acked.newly_acked);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_lost
int trace_quicly__packet_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 20 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_lost.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_lost.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:pto
int trace_quicly__pto(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 21 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.pto.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.pto.at);
  // size_t inflight
  bpf_usdt_readarg(3, ctx, &event.pto.inflight);
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.pto.cwnd);
  // int8_t pto_count
  bpf_usdt_readarg(5, ctx, &event.pto.pto_count);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:cc_ack_received
int trace_quicly__cc_ack_received(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 22 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.cc_ack_received.master_id = conn.master_id; /* uint32_t */
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
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:cc_congestion
int trace_quicly__cc_congestion(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 23 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.cc_congestion.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.cc_congestion.at);
  // uint64_t max_lost_pn
  bpf_usdt_readarg(3, ctx, &event.cc_congestion.max_lost_pn);
  // size_t inflight
  bpf_usdt_readarg(4, ctx, &event.cc_congestion.inflight);
  // uint32_t cwnd
  bpf_usdt_readarg(5, ctx, &event.cc_congestion.cwnd);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:transport_close_send
int trace_quicly__transport_close_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 24 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.transport_close_send.master_id = conn.master_id; /* uint32_t */
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
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:transport_close_receive
int trace_quicly__transport_close_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 25 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.transport_close_receive.master_id = conn.master_id; /* uint32_t */
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
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:application_close_send
int trace_quicly__application_close_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 26 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.application_close_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.application_close_send.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.application_close_send.error_code);
  // const char * reason_phrase
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.application_close_send.reason_phrase, sizeof(event.application_close_send.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:application_close_receive
int trace_quicly__application_close_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 27 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.application_close_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.application_close_receive.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.application_close_receive.error_code);
  // const char * reason_phrase
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.application_close_receive.reason_phrase, sizeof(event.application_close_receive.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_send
int trace_quicly__stream_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 28 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_send.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.stream_send.stream_id = stream.stream_id; /* int64_t */
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_send.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_send.len);
  // int is_fin
  bpf_usdt_readarg(6, ctx, &event.stream_send.is_fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_receive
int trace_quicly__stream_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 29 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_receive.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.stream_receive.stream_id = stream.stream_id; /* int64_t */
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_receive.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_receive.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_acked
int trace_quicly__stream_acked(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 30 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_acked.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_acked.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_acked.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_acked.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_acked.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_lost
int trace_quicly__stream_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 31 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_lost.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_lost.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_lost.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_lost.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_lost.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_data_send
int trace_quicly__max_data_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 32 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_data_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_data_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_data_receive
int trace_quicly__max_data_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 33 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_data_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_data_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_streams_send
int trace_quicly__max_streams_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 34 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_streams_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_streams_send.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_streams_receive
int trace_quicly__max_streams_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 35 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_streams_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_streams_receive.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_stream_data_send
int trace_quicly__max_stream_data_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 36 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_stream_data_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_send.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.max_stream_data_send.stream_id = stream.stream_id; /* int64_t */
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_stream_data_receive
int trace_quicly__max_stream_data_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 37 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_stream_data_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.max_stream_data_receive.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_token_send
int trace_quicly__new_token_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 38 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_token_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_send.at);
  // uint8_t * token
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.new_token_send.token, sizeof(event.new_token_send.token), buf);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.new_token_send.len);
  // uint64_t generation
  bpf_usdt_readarg(5, ctx, &event.new_token_send.generation);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_token_acked
int trace_quicly__new_token_acked(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 39 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_token_acked.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_acked.at);
  // uint64_t generation
  bpf_usdt_readarg(3, ctx, &event.new_token_acked.generation);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_token_receive
int trace_quicly__new_token_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 40 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_token_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_receive.at);
  // uint8_t * token
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.new_token_receive.token, sizeof(event.new_token_receive.token), buf);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.new_token_receive.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:handshake_done_send
int trace_quicly__handshake_done_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 41 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.handshake_done_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:handshake_done_receive
int trace_quicly__handshake_done_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 42 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.handshake_done_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:streams_blocked_send
int trace_quicly__streams_blocked_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 43 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.streams_blocked_send.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_send.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:streams_blocked_receive
int trace_quicly__streams_blocked_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 44 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.streams_blocked_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_receive.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:data_blocked_receive
int trace_quicly__data_blocked_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 45 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.data_blocked_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.data_blocked_receive.at);
  // uint64_t off
  bpf_usdt_readarg(3, ctx, &event.data_blocked_receive.off);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_data_blocked_receive
int trace_quicly__stream_data_blocked_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 46 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_data_blocked_receive.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_data_blocked_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_data_blocked_receive.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.stream_data_blocked_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_sent
int trace_quicly__quictrace_sent(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 47 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_sent.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_sent.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_sent.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.quictrace_sent.len);
  // uint8_t packet_type
  bpf_usdt_readarg(5, ctx, &event.quictrace_sent.packet_type);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv
int trace_quicly__quictrace_recv(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 48 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_send_stream
int trace_quicly__quictrace_send_stream(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 49 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_send_stream.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_send_stream.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.quictrace_send_stream.stream_id = stream.stream_id; /* int64_t */
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.quictrace_send_stream.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.quictrace_send_stream.len);
  // int fin
  bpf_usdt_readarg(6, ctx, &event.quictrace_send_stream.fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv_stream
int trace_quicly__quictrace_recv_stream(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 50 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv_stream.master_id = conn.master_id; /* uint32_t */
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
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv_ack
int trace_quicly__quictrace_recv_ack(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 51 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv_ack.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_ack.at);
  // uint64_t ack_block_begin
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_ack.ack_block_begin);
  // uint64_t ack_block_end
  bpf_usdt_readarg(4, ctx, &event.quictrace_recv_ack.ack_block_end);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv_ack_delay
int trace_quicly__quictrace_recv_ack_delay(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 52 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv_ack_delay.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_ack_delay.at);
  // int64_t ack_delay
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_ack_delay.ack_delay);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_lost
int trace_quicly__quictrace_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 53 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_lost.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_lost.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_cc_ack
int trace_quicly__quictrace_cc_ack(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 54 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_cc_ack.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_ack.at);
  // struct quicly_rtt_t * rtt
  struct quicly_rtt_t  rtt = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof(rtt), buf);
  event.quictrace_cc_ack.minimum = rtt.minimum; /* uint32_t */
  event.quictrace_cc_ack.latest = rtt.latest; /* uint32_t */
  event.quictrace_cc_ack.smoothed = rtt.smoothed; /* uint32_t */
  event.quictrace_cc_ack.variance = rtt.variance; /* uint32_t */
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.quictrace_cc_ack.cwnd);
  // size_t inflight
  bpf_usdt_readarg(5, ctx, &event.quictrace_cc_ack.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_cc_lost
int trace_quicly__quictrace_cc_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 55 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_cc_lost.master_id = conn.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_lost.at);
  // struct quicly_rtt_t * rtt
  struct quicly_rtt_t  rtt = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof(rtt), buf);
  event.quictrace_cc_lost.minimum = rtt.minimum; /* uint32_t */
  event.quictrace_cc_lost.latest = rtt.latest; /* uint32_t */
  event.quictrace_cc_lost.smoothed = rtt.smoothed; /* uint32_t */
  event.quictrace_cc_lost.variance = rtt.variance; /* uint32_t */
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.quictrace_cc_lost.cwnd);
  // size_t inflight
  bpf_usdt_readarg(5, ctx, &event.quictrace_cc_lost.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// h2o:h3_accept
int trace_h2o__h3_accept(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 60 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3_accept.conn_id);
  // struct st_h2o_conn_t * conn (ignored)
  // struct st_quicly_conn_t * quic
  struct st_quicly_conn_t  quic = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&quic, sizeof(quic), buf);
  event.h3_accept.master_id = quic.master_id; /* uint32_t */

  h2o_to_quicly_conn.update(&event.h3_accept.conn_id, &event.h3_accept.master_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// h2o:h3_close
int trace_h2o__h3_close(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 61 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3_close.conn_id);

  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.h3_close.conn_id);
  if (master_conn_id_ptr != NULL) {
    event.h3_close.master_id = *master_conn_id_ptr;
  } else {
    bpf_trace_printk("h2o's conn_id=%lu is not associated to master_conn_id\n", event.h3_close.conn_id);
  }
  h2o_to_quicly_conn.delete(&event.h3_close.conn_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// h2o:send_response_header
int trace_h2o__send_response_header(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 70 };

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

  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.send_response_header.conn_id);
  if (master_conn_id_ptr == NULL)
    return 0;
  event.send_response_header.master_id = *master_conn_id_ptr;

#ifdef CHECK_ALLOWED_RES_HEADER_NAME
  if (!CHECK_ALLOWED_RES_HEADER_NAME(event.send_response_header.name, event.send_response_header.name_len))
    return 0;
#endif

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}

)";

static uint64_t time_milliseconds()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}


static
std::vector<ebpf::USDT> quic_init_usdt_probes(pid_t pid) {
  const std::vector<ebpf::USDT> probes = {
    ebpf::USDT(pid, "quicly", "connect", "trace_quicly__connect"),
    ebpf::USDT(pid, "quicly", "accept", "trace_quicly__accept"),
    ebpf::USDT(pid, "quicly", "free", "trace_quicly__free"),
    ebpf::USDT(pid, "quicly", "send", "trace_quicly__send"),
    ebpf::USDT(pid, "quicly", "receive", "trace_quicly__receive"),
    ebpf::USDT(pid, "quicly", "version_switch", "trace_quicly__version_switch"),
    ebpf::USDT(pid, "quicly", "idle_timeout", "trace_quicly__idle_timeout"),
    ebpf::USDT(pid, "quicly", "stateless_reset_receive", "trace_quicly__stateless_reset_receive"),
    ebpf::USDT(pid, "quicly", "crypto_decrypt", "trace_quicly__crypto_decrypt"),
    ebpf::USDT(pid, "quicly", "crypto_handshake", "trace_quicly__crypto_handshake"),
    ebpf::USDT(pid, "quicly", "crypto_update_secret", "trace_quicly__crypto_update_secret"),
    ebpf::USDT(pid, "quicly", "crypto_send_key_update", "trace_quicly__crypto_send_key_update"),
    ebpf::USDT(pid, "quicly", "crypto_send_key_update_confirmed", "trace_quicly__crypto_send_key_update_confirmed"),
    ebpf::USDT(pid, "quicly", "crypto_receive_key_update", "trace_quicly__crypto_receive_key_update"),
    ebpf::USDT(pid, "quicly", "crypto_receive_key_update_prepare", "trace_quicly__crypto_receive_key_update_prepare"),
    ebpf::USDT(pid, "quicly", "packet_prepare", "trace_quicly__packet_prepare"),
    ebpf::USDT(pid, "quicly", "packet_commit", "trace_quicly__packet_commit"),
    ebpf::USDT(pid, "quicly", "packet_acked", "trace_quicly__packet_acked"),
    ebpf::USDT(pid, "quicly", "packet_lost", "trace_quicly__packet_lost"),
    ebpf::USDT(pid, "quicly", "pto", "trace_quicly__pto"),
    ebpf::USDT(pid, "quicly", "cc_ack_received", "trace_quicly__cc_ack_received"),
    ebpf::USDT(pid, "quicly", "cc_congestion", "trace_quicly__cc_congestion"),
    ebpf::USDT(pid, "quicly", "transport_close_send", "trace_quicly__transport_close_send"),
    ebpf::USDT(pid, "quicly", "transport_close_receive", "trace_quicly__transport_close_receive"),
    ebpf::USDT(pid, "quicly", "application_close_send", "trace_quicly__application_close_send"),
    ebpf::USDT(pid, "quicly", "application_close_receive", "trace_quicly__application_close_receive"),
    ebpf::USDT(pid, "quicly", "stream_send", "trace_quicly__stream_send"),
    ebpf::USDT(pid, "quicly", "stream_receive", "trace_quicly__stream_receive"),
    ebpf::USDT(pid, "quicly", "stream_acked", "trace_quicly__stream_acked"),
    ebpf::USDT(pid, "quicly", "stream_lost", "trace_quicly__stream_lost"),
    ebpf::USDT(pid, "quicly", "max_data_send", "trace_quicly__max_data_send"),
    ebpf::USDT(pid, "quicly", "max_data_receive", "trace_quicly__max_data_receive"),
    ebpf::USDT(pid, "quicly", "max_streams_send", "trace_quicly__max_streams_send"),
    ebpf::USDT(pid, "quicly", "max_streams_receive", "trace_quicly__max_streams_receive"),
    ebpf::USDT(pid, "quicly", "max_stream_data_send", "trace_quicly__max_stream_data_send"),
    ebpf::USDT(pid, "quicly", "max_stream_data_receive", "trace_quicly__max_stream_data_receive"),
    ebpf::USDT(pid, "quicly", "new_token_send", "trace_quicly__new_token_send"),
    ebpf::USDT(pid, "quicly", "new_token_acked", "trace_quicly__new_token_acked"),
    ebpf::USDT(pid, "quicly", "new_token_receive", "trace_quicly__new_token_receive"),
    ebpf::USDT(pid, "quicly", "handshake_done_send", "trace_quicly__handshake_done_send"),
    ebpf::USDT(pid, "quicly", "handshake_done_receive", "trace_quicly__handshake_done_receive"),
    ebpf::USDT(pid, "quicly", "streams_blocked_send", "trace_quicly__streams_blocked_send"),
    ebpf::USDT(pid, "quicly", "streams_blocked_receive", "trace_quicly__streams_blocked_receive"),
    ebpf::USDT(pid, "quicly", "data_blocked_receive", "trace_quicly__data_blocked_receive"),
    ebpf::USDT(pid, "quicly", "stream_data_blocked_receive", "trace_quicly__stream_data_blocked_receive"),
    ebpf::USDT(pid, "quicly", "quictrace_sent", "trace_quicly__quictrace_sent"),
    ebpf::USDT(pid, "quicly", "quictrace_recv", "trace_quicly__quictrace_recv"),
    ebpf::USDT(pid, "quicly", "quictrace_send_stream", "trace_quicly__quictrace_send_stream"),
    ebpf::USDT(pid, "quicly", "quictrace_recv_stream", "trace_quicly__quictrace_recv_stream"),
    ebpf::USDT(pid, "quicly", "quictrace_recv_ack", "trace_quicly__quictrace_recv_ack"),
    ebpf::USDT(pid, "quicly", "quictrace_recv_ack_delay", "trace_quicly__quictrace_recv_ack_delay"),
    ebpf::USDT(pid, "quicly", "quictrace_lost", "trace_quicly__quictrace_lost"),
    ebpf::USDT(pid, "quicly", "quictrace_cc_ack", "trace_quicly__quictrace_cc_ack"),
    ebpf::USDT(pid, "quicly", "quictrace_cc_lost", "trace_quicly__quictrace_cc_lost"),
    ebpf::USDT(pid, "h2o", "h3_accept", "trace_h2o__h3_accept"),
    ebpf::USDT(pid, "h2o", "h3_close", "trace_h2o__h3_close"),
    ebpf::USDT(pid, "h2o", "send_response_header", "trace_h2o__send_response_header"),

  };
  return probes;
}


struct quic_event_t {
  uint8_t id;

  union {
    struct { // quicly:connect
      uint32_t master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
    } accept;
    struct { // quicly:free
      uint32_t master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      uint32_t master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[STR_LEN];
      size_t num_bytes;
    } receive;
    struct { // quicly:version_switch
      uint32_t master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      uint32_t master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      uint32_t master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_decrypt
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      uint8_t decrypted[STR_LEN];
      size_t decrypted_len;
    } crypto_decrypt;
    struct { // quicly:crypto_handshake
      uint32_t master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      uint32_t master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
      char secret[STR_LEN];
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN];
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      uint32_t master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN];
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
      char secret[STR_LEN];
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_prepare
      uint32_t master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_commit
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      int ack_only;
    } packet_commit;
    struct { // quicly:packet_acked
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      int newly_acked;
    } packet_acked;
    struct { // quicly:packet_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } packet_lost;
    struct { // quicly:pto
      uint32_t master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      uint32_t master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      uint32_t master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:transport_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:max_data_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_send;
    struct { // quicly:max_data_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_receive;
    struct { // quicly:max_streams_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      uint32_t master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      uint32_t master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      uint32_t master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:data_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_receive;
    struct { // quicly:quictrace_sent
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
    } quictrace_sent;
    struct { // quicly:quictrace_recv
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_recv;
    struct { // quicly:quictrace_send_stream
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_recv_ack
      uint32_t master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } quictrace_recv_ack;
    struct { // quicly:quictrace_recv_ack_delay
      uint32_t master_id;
      int64_t at;
      int64_t ack_delay;
    } quictrace_recv_ack_delay;
    struct { // quicly:quictrace_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_lost;
    struct { // quicly:quictrace_cc_ack
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t latest;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t latest;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // h2o:h3_accept
      uint64_t conn_id;
      uint32_t master_id;
    } h3_accept;
    struct { // h2o:h3_close
      uint64_t conn_id;
      uint32_t master_id;
    } h3_close;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
      uint32_t master_id;
    } send_response_header;

    };
  };
  

static
void quic_handle_event(h2o_tracer_t *tracer, const void *data, int data_len) {
  FILE *out = tracer->out;

  const quic_event_t *event = static_cast<const quic_event_t*>(data);

  if (event->id == 1) { // sched:sched_process_exit
    exit(0);
  }

  // output JSON
  fprintf(out, "{");

  switch (event->id) {
  case 2: { // quicly:connect
    json_write_pair_n(out, STR_LIT("type"), "connect");
    json_write_pair_c(out, STR_LIT("conn"), event->connect.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->connect.at);
    json_write_pair_c(out, STR_LIT("version"), event->connect.version);
    break;
  }
  case 3: { // quicly:accept
    json_write_pair_n(out, STR_LIT("type"), "accept");
    json_write_pair_c(out, STR_LIT("conn"), event->accept.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->accept.at);
    json_write_pair_c(out, STR_LIT("dcid"), event->accept.dcid);
    break;
  }
  case 4: { // quicly:free
    json_write_pair_n(out, STR_LIT("type"), "free");
    json_write_pair_c(out, STR_LIT("conn"), event->free.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->free.at);
    break;
  }
  case 5: { // quicly:send
    json_write_pair_n(out, STR_LIT("type"), "send");
    json_write_pair_c(out, STR_LIT("conn"), event->send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->send.at);
    json_write_pair_c(out, STR_LIT("state"), event->send.state);
    json_write_pair_c(out, STR_LIT("dcid"), event->send.dcid);
    break;
  }
  case 6: { // quicly:receive
    json_write_pair_n(out, STR_LIT("type"), "receive");
    json_write_pair_c(out, STR_LIT("conn"), event->receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->receive.at);
    json_write_pair_c(out, STR_LIT("dcid"), event->receive.dcid);
    json_write_pair_c(out, STR_LIT("bytes-len"), event->receive.num_bytes);
    break;
  }
  case 7: { // quicly:version_switch
    json_write_pair_n(out, STR_LIT("type"), "version-switch");
    json_write_pair_c(out, STR_LIT("conn"), event->version_switch.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->version_switch.at);
    json_write_pair_c(out, STR_LIT("new-version"), event->version_switch.new_version);
    break;
  }
  case 8: { // quicly:idle_timeout
    json_write_pair_n(out, STR_LIT("type"), "idle-timeout");
    json_write_pair_c(out, STR_LIT("conn"), event->idle_timeout.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->idle_timeout.at);
    break;
  }
  case 9: { // quicly:stateless_reset_receive
    json_write_pair_n(out, STR_LIT("type"), "stateless-reset-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->stateless_reset_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stateless_reset_receive.at);
    break;
  }
  case 10: { // quicly:crypto_decrypt
    json_write_pair_n(out, STR_LIT("type"), "crypto-decrypt");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_decrypt.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_decrypt.at);
    json_write_pair_c(out, STR_LIT("pn"), event->crypto_decrypt.pn);
    json_write_pair_c(out, STR_LIT("decrypted-len"), event->crypto_decrypt.decrypted_len);
    break;
  }
  case 11: { // quicly:crypto_handshake
    json_write_pair_n(out, STR_LIT("type"), "crypto-handshake");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_handshake.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_handshake.at);
    json_write_pair_c(out, STR_LIT("ret"), event->crypto_handshake.ret);
    break;
  }
  case 12: { // quicly:crypto_update_secret
    json_write_pair_n(out, STR_LIT("type"), "crypto-update-secret");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_update_secret.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_update_secret.at);
    json_write_pair_c(out, STR_LIT("is-enc"), event->crypto_update_secret.is_enc);
    json_write_pair_c(out, STR_LIT("epoch"), event->crypto_update_secret.epoch);
    json_write_pair_c(out, STR_LIT("label"), event->crypto_update_secret.label);
    break;
  }
  case 13: { // quicly:crypto_send_key_update
    json_write_pair_n(out, STR_LIT("type"), "crypto-send-key-update");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_send_key_update.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_send_key_update.at);
    json_write_pair_c(out, STR_LIT("phase"), event->crypto_send_key_update.phase);
    break;
  }
  case 14: { // quicly:crypto_send_key_update_confirmed
    json_write_pair_n(out, STR_LIT("type"), "crypto-send-key-update-confirmed");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_send_key_update_confirmed.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_send_key_update_confirmed.at);
    json_write_pair_c(out, STR_LIT("next-pn"), event->crypto_send_key_update_confirmed.next_pn);
    break;
  }
  case 15: { // quicly:crypto_receive_key_update
    json_write_pair_n(out, STR_LIT("type"), "crypto-receive-key-update");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_receive_key_update.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_receive_key_update.at);
    json_write_pair_c(out, STR_LIT("phase"), event->crypto_receive_key_update.phase);
    break;
  }
  case 16: { // quicly:crypto_receive_key_update_prepare
    json_write_pair_n(out, STR_LIT("type"), "crypto-receive-key-update-prepare");
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_receive_key_update_prepare.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_receive_key_update_prepare.at);
    json_write_pair_c(out, STR_LIT("phase"), event->crypto_receive_key_update_prepare.phase);
    break;
  }
  case 17: { // quicly:packet_prepare
    json_write_pair_n(out, STR_LIT("type"), "packet-prepare");
    json_write_pair_c(out, STR_LIT("conn"), event->packet_prepare.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_prepare.at);
    json_write_pair_c(out, STR_LIT("first-octet"), event->packet_prepare.first_octet);
    json_write_pair_c(out, STR_LIT("dcid"), event->packet_prepare.dcid);
    break;
  }
  case 18: { // quicly:packet_commit
    json_write_pair_n(out, STR_LIT("type"), "packet-commit");
    json_write_pair_c(out, STR_LIT("conn"), event->packet_commit.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_commit.at);
    json_write_pair_c(out, STR_LIT("pn"), event->packet_commit.pn);
    json_write_pair_c(out, STR_LIT("len"), event->packet_commit.len);
    json_write_pair_c(out, STR_LIT("ack-only"), event->packet_commit.ack_only);
    break;
  }
  case 19: { // quicly:packet_acked
    json_write_pair_n(out, STR_LIT("type"), "packet-acked");
    json_write_pair_c(out, STR_LIT("conn"), event->packet_acked.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_acked.at);
    json_write_pair_c(out, STR_LIT("pn"), event->packet_acked.pn);
    json_write_pair_c(out, STR_LIT("newly-acked"), event->packet_acked.newly_acked);
    break;
  }
  case 20: { // quicly:packet_lost
    json_write_pair_n(out, STR_LIT("type"), "packet-lost");
    json_write_pair_c(out, STR_LIT("conn"), event->packet_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_lost.at);
    json_write_pair_c(out, STR_LIT("pn"), event->packet_lost.pn);
    break;
  }
  case 21: { // quicly:pto
    json_write_pair_n(out, STR_LIT("type"), "pto");
    json_write_pair_c(out, STR_LIT("conn"), event->pto.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->pto.at);
    json_write_pair_c(out, STR_LIT("inflight"), event->pto.inflight);
    json_write_pair_c(out, STR_LIT("cwnd"), event->pto.cwnd);
    json_write_pair_c(out, STR_LIT("pto-count"), event->pto.pto_count);
    break;
  }
  case 22: { // quicly:cc_ack_received
    json_write_pair_n(out, STR_LIT("type"), "cc-ack-received");
    json_write_pair_c(out, STR_LIT("conn"), event->cc_ack_received.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->cc_ack_received.at);
    json_write_pair_c(out, STR_LIT("largest-acked"), event->cc_ack_received.largest_acked);
    json_write_pair_c(out, STR_LIT("bytes-acked"), event->cc_ack_received.bytes_acked);
    json_write_pair_c(out, STR_LIT("cwnd"), event->cc_ack_received.cwnd);
    json_write_pair_c(out, STR_LIT("inflight"), event->cc_ack_received.inflight);
    break;
  }
  case 23: { // quicly:cc_congestion
    json_write_pair_n(out, STR_LIT("type"), "cc-congestion");
    json_write_pair_c(out, STR_LIT("conn"), event->cc_congestion.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->cc_congestion.at);
    json_write_pair_c(out, STR_LIT("max-lost-pn"), event->cc_congestion.max_lost_pn);
    json_write_pair_c(out, STR_LIT("inflight"), event->cc_congestion.inflight);
    json_write_pair_c(out, STR_LIT("cwnd"), event->cc_congestion.cwnd);
    break;
  }
  case 24: { // quicly:transport_close_send
    json_write_pair_n(out, STR_LIT("type"), "transport-close-send");
    json_write_pair_c(out, STR_LIT("conn"), event->transport_close_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->transport_close_send.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->transport_close_send.error_code);
    json_write_pair_c(out, STR_LIT("frame-type"), event->transport_close_send.frame_type);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->transport_close_send.reason_phrase);
    break;
  }
  case 25: { // quicly:transport_close_receive
    json_write_pair_n(out, STR_LIT("type"), "transport-close-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->transport_close_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->transport_close_receive.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->transport_close_receive.error_code);
    json_write_pair_c(out, STR_LIT("frame-type"), event->transport_close_receive.frame_type);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->transport_close_receive.reason_phrase);
    break;
  }
  case 26: { // quicly:application_close_send
    json_write_pair_n(out, STR_LIT("type"), "application-close-send");
    json_write_pair_c(out, STR_LIT("conn"), event->application_close_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->application_close_send.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->application_close_send.error_code);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->application_close_send.reason_phrase);
    break;
  }
  case 27: { // quicly:application_close_receive
    json_write_pair_n(out, STR_LIT("type"), "application-close-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->application_close_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->application_close_receive.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->application_close_receive.error_code);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->application_close_receive.reason_phrase);
    break;
  }
  case 28: { // quicly:stream_send
    json_write_pair_n(out, STR_LIT("type"), "stream-send");
    json_write_pair_c(out, STR_LIT("conn"), event->stream_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_send.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_send.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_send.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_send.len);
    json_write_pair_c(out, STR_LIT("is-fin"), event->stream_send.is_fin);
    break;
  }
  case 29: { // quicly:stream_receive
    json_write_pair_n(out, STR_LIT("type"), "stream-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->stream_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_receive.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_receive.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_receive.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_receive.len);
    break;
  }
  case 30: { // quicly:stream_acked
    json_write_pair_n(out, STR_LIT("type"), "stream-acked");
    json_write_pair_c(out, STR_LIT("conn"), event->stream_acked.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_acked.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_acked.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_acked.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_acked.len);
    break;
  }
  case 31: { // quicly:stream_lost
    json_write_pair_n(out, STR_LIT("type"), "stream-lost");
    json_write_pair_c(out, STR_LIT("conn"), event->stream_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_lost.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_lost.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_lost.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_lost.len);
    break;
  }
  case 32: { // quicly:max_data_send
    json_write_pair_n(out, STR_LIT("type"), "max-data-send");
    json_write_pair_c(out, STR_LIT("conn"), event->max_data_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_data_send.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_data_send.limit);
    break;
  }
  case 33: { // quicly:max_data_receive
    json_write_pair_n(out, STR_LIT("type"), "max-data-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->max_data_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_data_receive.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_data_receive.limit);
    break;
  }
  case 34: { // quicly:max_streams_send
    json_write_pair_n(out, STR_LIT("type"), "max-streams-send");
    json_write_pair_c(out, STR_LIT("conn"), event->max_streams_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_streams_send.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_streams_send.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->max_streams_send.is_unidirectional);
    break;
  }
  case 35: { // quicly:max_streams_receive
    json_write_pair_n(out, STR_LIT("type"), "max-streams-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->max_streams_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_streams_receive.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_streams_receive.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->max_streams_receive.is_unidirectional);
    break;
  }
  case 36: { // quicly:max_stream_data_send
    json_write_pair_n(out, STR_LIT("type"), "max-stream-data-send");
    json_write_pair_c(out, STR_LIT("conn"), event->max_stream_data_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_stream_data_send.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->max_stream_data_send.stream_id);
    json_write_pair_c(out, STR_LIT("limit"), event->max_stream_data_send.limit);
    break;
  }
  case 37: { // quicly:max_stream_data_receive
    json_write_pair_n(out, STR_LIT("type"), "max-stream-data-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->max_stream_data_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_stream_data_receive.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->max_stream_data_receive.stream_id);
    json_write_pair_c(out, STR_LIT("limit"), event->max_stream_data_receive.limit);
    break;
  }
  case 38: { // quicly:new_token_send
    json_write_pair_n(out, STR_LIT("type"), "new-token-send");
    json_write_pair_c(out, STR_LIT("conn"), event->new_token_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_token_send.at);
    json_write_pair_c(out, STR_LIT("token"), event->new_token_send.token, (event->new_token_send.len < STR_LEN ? event->new_token_send.len : STR_LEN));
    json_write_pair_c(out, STR_LIT("len"), event->new_token_send.len);
    json_write_pair_c(out, STR_LIT("generation"), event->new_token_send.generation);
    break;
  }
  case 39: { // quicly:new_token_acked
    json_write_pair_n(out, STR_LIT("type"), "new-token-acked");
    json_write_pair_c(out, STR_LIT("conn"), event->new_token_acked.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_token_acked.at);
    json_write_pair_c(out, STR_LIT("generation"), event->new_token_acked.generation);
    break;
  }
  case 40: { // quicly:new_token_receive
    json_write_pair_n(out, STR_LIT("type"), "new-token-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->new_token_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_token_receive.at);
    json_write_pair_c(out, STR_LIT("token"), event->new_token_receive.token, (event->new_token_receive.len < STR_LEN ? event->new_token_receive.len : STR_LEN));
    json_write_pair_c(out, STR_LIT("len"), event->new_token_receive.len);
    break;
  }
  case 41: { // quicly:handshake_done_send
    json_write_pair_n(out, STR_LIT("type"), "handshake-done-send");
    json_write_pair_c(out, STR_LIT("conn"), event->handshake_done_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->handshake_done_send.at);
    break;
  }
  case 42: { // quicly:handshake_done_receive
    json_write_pair_n(out, STR_LIT("type"), "handshake-done-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->handshake_done_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->handshake_done_receive.at);
    break;
  }
  case 43: { // quicly:streams_blocked_send
    json_write_pair_n(out, STR_LIT("type"), "streams-blocked-send");
    json_write_pair_c(out, STR_LIT("conn"), event->streams_blocked_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->streams_blocked_send.at);
    json_write_pair_c(out, STR_LIT("limit"), event->streams_blocked_send.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->streams_blocked_send.is_unidirectional);
    break;
  }
  case 44: { // quicly:streams_blocked_receive
    json_write_pair_n(out, STR_LIT("type"), "streams-blocked-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->streams_blocked_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->streams_blocked_receive.at);
    json_write_pair_c(out, STR_LIT("limit"), event->streams_blocked_receive.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->streams_blocked_receive.is_unidirectional);
    break;
  }
  case 45: { // quicly:data_blocked_receive
    json_write_pair_n(out, STR_LIT("type"), "data-blocked-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->data_blocked_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->data_blocked_receive.at);
    json_write_pair_c(out, STR_LIT("off"), event->data_blocked_receive.off);
    break;
  }
  case 46: { // quicly:stream_data_blocked_receive
    json_write_pair_n(out, STR_LIT("type"), "stream-data-blocked-receive");
    json_write_pair_c(out, STR_LIT("conn"), event->stream_data_blocked_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_data_blocked_receive.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_data_blocked_receive.stream_id);
    json_write_pair_c(out, STR_LIT("limit"), event->stream_data_blocked_receive.limit);
    break;
  }
  case 47: { // quicly:quictrace_sent
    json_write_pair_n(out, STR_LIT("type"), "quictrace-sent");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_sent.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_sent.at);
    json_write_pair_c(out, STR_LIT("pn"), event->quictrace_sent.pn);
    json_write_pair_c(out, STR_LIT("len"), event->quictrace_sent.len);
    json_write_pair_c(out, STR_LIT("packet-type"), event->quictrace_sent.packet_type);
    break;
  }
  case 48: { // quicly:quictrace_recv
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv.at);
    json_write_pair_c(out, STR_LIT("pn"), event->quictrace_recv.pn);
    break;
  }
  case 49: { // quicly:quictrace_send_stream
    json_write_pair_n(out, STR_LIT("type"), "quictrace-send-stream");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_send_stream.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_send_stream.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->quictrace_send_stream.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->quictrace_send_stream.off);
    json_write_pair_c(out, STR_LIT("len"), event->quictrace_send_stream.len);
    json_write_pair_c(out, STR_LIT("fin"), event->quictrace_send_stream.fin);
    break;
  }
  case 50: { // quicly:quictrace_recv_stream
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv-stream");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv_stream.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv_stream.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->quictrace_recv_stream.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->quictrace_recv_stream.off);
    json_write_pair_c(out, STR_LIT("len"), event->quictrace_recv_stream.len);
    json_write_pair_c(out, STR_LIT("fin"), event->quictrace_recv_stream.fin);
    break;
  }
  case 51: { // quicly:quictrace_recv_ack
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv-ack");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv_ack.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv_ack.at);
    json_write_pair_c(out, STR_LIT("ack-block-begin"), event->quictrace_recv_ack.ack_block_begin);
    json_write_pair_c(out, STR_LIT("ack-block-end"), event->quictrace_recv_ack.ack_block_end);
    break;
  }
  case 52: { // quicly:quictrace_recv_ack_delay
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv-ack-delay");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv_ack_delay.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv_ack_delay.at);
    json_write_pair_c(out, STR_LIT("ack-delay"), event->quictrace_recv_ack_delay.ack_delay);
    break;
  }
  case 53: { // quicly:quictrace_lost
    json_write_pair_n(out, STR_LIT("type"), "quictrace-lost");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_lost.at);
    json_write_pair_c(out, STR_LIT("pn"), event->quictrace_lost.pn);
    break;
  }
  case 54: { // quicly:quictrace_cc_ack
    json_write_pair_n(out, STR_LIT("type"), "quictrace-cc-ack");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_cc_ack.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_cc_ack.at);
    json_write_pair_c(out, STR_LIT("min-rtt"), event->quictrace_cc_ack.minimum);
    json_write_pair_c(out, STR_LIT("latest-rtt"), event->quictrace_cc_ack.latest);
    json_write_pair_c(out, STR_LIT("smoothed-rtt"), event->quictrace_cc_ack.smoothed);
    json_write_pair_c(out, STR_LIT("variance-rtt"), event->quictrace_cc_ack.variance);
    json_write_pair_c(out, STR_LIT("cwnd"), event->quictrace_cc_ack.cwnd);
    json_write_pair_c(out, STR_LIT("inflight"), event->quictrace_cc_ack.inflight);
    break;
  }
  case 55: { // quicly:quictrace_cc_lost
    json_write_pair_n(out, STR_LIT("type"), "quictrace-cc-lost");
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_cc_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_cc_lost.at);
    json_write_pair_c(out, STR_LIT("min-rtt"), event->quictrace_cc_lost.minimum);
    json_write_pair_c(out, STR_LIT("latest-rtt"), event->quictrace_cc_lost.latest);
    json_write_pair_c(out, STR_LIT("smoothed-rtt"), event->quictrace_cc_lost.smoothed);
    json_write_pair_c(out, STR_LIT("variance-rtt"), event->quictrace_cc_lost.variance);
    json_write_pair_c(out, STR_LIT("cwnd"), event->quictrace_cc_lost.cwnd);
    json_write_pair_c(out, STR_LIT("inflight"), event->quictrace_cc_lost.inflight);
    break;
  }
  case 60: { // h2o:h3_accept
    json_write_pair_n(out, STR_LIT("type"), "h3-accept");
    json_write_pair_c(out, STR_LIT("conn-id"), event->h3_accept.conn_id);
    json_write_pair_c(out, STR_LIT("conn"), event->h3_accept.master_id);
    json_write_pair_c(out, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 61: { // h2o:h3_close
    json_write_pair_n(out, STR_LIT("type"), "h3-close");
    json_write_pair_c(out, STR_LIT("conn-id"), event->h3_close.conn_id);
    json_write_pair_c(out, STR_LIT("conn"), event->h3_close.master_id);
    json_write_pair_c(out, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 70: { // h2o:send_response_header
    json_write_pair_n(out, STR_LIT("type"), "send-response-header");
    json_write_pair_c(out, STR_LIT("conn-id"), event->send_response_header.conn_id);
    json_write_pair_c(out, STR_LIT("req-id"), event->send_response_header.req_id);
    json_write_pair_c(out, STR_LIT("name"), event->send_response_header.name);
    json_write_pair_c(out, STR_LIT("name-len"), event->send_response_header.name_len);
    json_write_pair_c(out, STR_LIT("value"), event->send_response_header.value);
    json_write_pair_c(out, STR_LIT("value-len"), event->send_response_header.value_len);
    json_write_pair_c(out, STR_LIT("conn"), event->send_response_header.master_id);
    json_write_pair_c(out, STR_LIT("time"), time_milliseconds());
    break;
  }

  default:
    std::abort();
  }

  fprintf(out, "}\n");
}


static void quic_handle_lost(h2o_tracer_t *tracer, uint64_t lost) {
  fprintf(tracer->out, "{\"type\":\"h2olog-event-lost\",\"time\":%" PRIu64 ",\"lost\":%" PRIu64 "}\n", time_milliseconds(), lost);
}

static const char *quic_bpf_ext() {
  return bpf_text;
}

void init_quic_tracer(h2o_tracer_t * tracer) {
  tracer->handle_event = quic_handle_event;
  tracer->handle_lost = quic_handle_lost;
  tracer->init_usdt_probes = quic_init_usdt_probes;
  tracer->bpf_text = quic_bpf_ext;
}

