#!/usr/bin/env python
#
# h2olog - A BPF-backed request logging client for the H2O server.
#
# USAGE: $ sudo h2olog -p $(pgrep -o h2o)
#
# Copyright 2019 Fastly, Toru Maesaka

from bcc import BPF, USDT
from collections import OrderedDict
import binascii, getopt, json, sys, time

bpf = """
#define MAX_STR_LEN 128
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/*
 * "trace_line_t" is a general structure to store the data emitted by
 * USDT probes. This structure is pushed into the BPF ring buffer.
 */
struct trace_line_t {
    u64 conn_id;
    u64 req_id;
    u32 http_version;
    u32 http_status;
    u64 header_name_len;
    u64 header_value_len;
    char header_name[MAX_STR_LEN];
    char header_value[MAX_STR_LEN];
};

BPF_PERF_OUTPUT(rxbuf);
BPF_PERF_OUTPUT(txbuf);

int trace_receive_req(struct pt_regs *ctx) {
    struct trace_line_t line = {};

    bpf_usdt_readarg(1, ctx, &line.conn_id);
    bpf_usdt_readarg(2, ctx, &line.req_id);
    bpf_usdt_readarg(3, ctx, &line.http_version);

    if (rxbuf.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_receive_req_header(struct pt_regs *ctx) {
    struct trace_line_t line = {};
    void *pos = NULL;

    bpf_usdt_readarg(1, ctx, &line.conn_id);
    bpf_usdt_readarg(2, ctx, &line.req_id);

    // Extract the Header Name
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_usdt_readarg(4, ctx, &line.header_name_len);
    line.header_name_len = MIN(MAX_STR_LEN, line.header_name_len);
    bpf_probe_read(&line.header_name, line.header_name_len, pos);

    // Extract the Header Value
    bpf_usdt_readarg(5, ctx, &pos);
    bpf_usdt_readarg(6, ctx, &line.header_value_len);
    line.header_value_len = MIN(MAX_STR_LEN, line.header_value_len);
    bpf_probe_read(&line.header_value, line.header_value_len, pos);

    if (rxbuf.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_send_resp(struct pt_regs *ctx) {
    struct trace_line_t line = {};

    bpf_usdt_readarg(1, ctx, &line.conn_id);
    bpf_usdt_readarg(2, ctx, &line.req_id);
    bpf_usdt_readarg(3, ctx, &line.http_status);

    if (txbuf.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}
"""

quic_bpf = """
#define MAX_STR_LEN 32
#define TOKEN_PREVIEW_LEN 8

int sprintf(char * restrict str, const char * restrict format, ...);

struct st_quicly_conn_t {
    u32 dummy[4];
    u32 master_id;
};

struct quic_event_t {
    char type[MAX_STR_LEN];
    char dcid[MAX_STR_LEN];
    char token_preview[TOKEN_PREVIEW_LEN];
    u64 at;
    u32 master_conn_id;
    u64 stream_id;
    u64 error_code;
    u64 packet_num;
    u64 packet_len;
    u8 packet_type;
    u64 frame_type;
    u32 ack_only;
    u64 largest_acked;
    u64 bytes_acked;
    u64 ack_delay;
    u64 inflight;
    u64 max_lost_pn;
    u32 cwnd;
    u8 first_octet;
    u32 newly_acked;
    u32 new_version;
    u64 len;
    u64 token_generation;
    u64 limit;
    u64 off;
    u32 is_unidirectional;
    u32 ret;
};

BPF_PERF_OUTPUT(events);

int trace_accept(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "accept");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_probe_read(&event.dcid, MAX_STR_LEN, pos);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_probe_read(&event.dcid, MAX_STR_LEN, pos);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_version_switch(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "version_switch");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.new_version);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_idle_timeout(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "idle_timeout");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_stateless_reset_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "stateless_reset_receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_crypto_decrypt(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "crypto_decrypt");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.packet_num);
    bpf_usdt_readarg(4, ctx, &event.len);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_crypto_handshake(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "crypto_handshake");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.ret);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_prepare(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "packet_prepare");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.first_octet);
    bpf_usdt_readarg(4, ctx, &pos);
    bpf_probe_read(&event.dcid, MAX_STR_LEN, pos);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_commit(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "packet_commit");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.packet_num);
    bpf_usdt_readarg(4, ctx, &event.packet_len);
    bpf_usdt_readarg(5, ctx, &event.ack_only);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_acked(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "packet_acked");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.packet_num);
    bpf_usdt_readarg(4, ctx, &event.newly_acked);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_lost(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "packet_lost");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.packet_num);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_cc_ack_received(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "cc_ack_received");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.largest_acked);
    bpf_usdt_readarg(4, ctx, &event.bytes_acked);
    bpf_usdt_readarg(5, ctx, &event.cwnd);
    bpf_usdt_readarg(6, ctx, &event.inflight);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_cc_congestion(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "cc_congestion");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.max_lost_pn);
    bpf_usdt_readarg(4, ctx, &event.inflight);
    bpf_usdt_readarg(5, ctx, &event.cwnd);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_transport_close_send(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "transport_close_send");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.frame_type);

    return 0;
}

int trace_transport_close_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "transport_close_receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.error_code);
    bpf_usdt_readarg(4, ctx, &event.frame_type);

    return 0;
}

int trace_new_token_send(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "new_token_send");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_probe_read(&event.token_preview, TOKEN_PREVIEW_LEN, pos);
    bpf_usdt_readarg(4, ctx, &event.len);
    bpf_usdt_readarg(5, ctx, &event.token_generation);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_new_token_acked(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "new_token_acked");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.token_generation);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_new_token_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "new_token_receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_probe_read(&event.token_preview, TOKEN_PREVIEW_LEN, pos);
    bpf_usdt_readarg(4, ctx, &event.len);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_streams_blocked_send(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "streams_blocked_send");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.limit);
    bpf_usdt_readarg(4, ctx, &event.is_unidirectional);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_streams_blocked_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "streams_blocked_receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.limit);
    bpf_usdt_readarg(4, ctx, &event.is_unidirectional);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_data_blocked_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "data_blocked_receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.off);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_stream_data_blocked_receive(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "stream_data_blocked_receive");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.stream_id);
    bpf_usdt_readarg(4, ctx, &event.limit);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_quictrace_sent(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "quictrace_sent");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.packet_num);
    bpf_usdt_readarg(4, ctx, &event.packet_len);
    bpf_usdt_readarg(5, ctx, &event.packet_type);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_quictrace_recv(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "quictrace_recv");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.packet_num);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_quictrace_recv_ack_delay(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "quictrace_recv_ack_delay");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.ack_delay);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_quictrace_lost(struct pt_regs *ctx) {
    void *pos = NULL;
    struct quic_event_t event = {};
    struct st_quicly_conn_t conn = {};
    sprintf(event.type, "quictrace_lost");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    event.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &event.at);
    bpf_usdt_readarg(3, ctx, &event.packet_num);

    if (events.perf_submit(ctx, &event, sizeof(event)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}
"""

def handle_req_line(cpu, data, size):
    line = b["rxbuf"].event(data)
    if line.http_version:
        v = "HTTP/%d.%d" % (line.http_version / 256, line.http_version % 256)
        print("%u %u RxProtocol %s" % (line.conn_id, line.req_id, v))
    else:
        print("%u %u RxHeader   %s %s" % (line.conn_id, line.req_id, line.header_name, line.header_value))

def handle_resp_line(cpu, data, size):
    line = b["txbuf"].event(data)
    print("%u %u TxStatus   %d" % (line.conn_id, line.req_id, line.http_status))

def load_common_fields(hsh, line):
    for k in ['at', 'type', 'master_conn_id']:
        v = getattr(line, k)
        if v == 0 and k == 'at':
            # TODO: This is a synthetic hack
            v = int(time.time() * 1000)
        hsh[k] = v

def build_quic_trace_result(res, event, fields):
    for k in fields:
        res[k] = getattr(event, k)
        if k == "token_preview":
            res[k] = binascii.hexlify(res[k])
    return res

def handle_quic_event(cpu, data, size):
    ev = b["events"].event(data)
    if allowed_quic_event and ev.type != allowed_quic_event:
        return

    res = OrderedDict()
    load_common_fields(res, ev)

    if ev.type == "accept":
        build_quic_trace_result(res, ev, ["dcid"])
    elif ev.type == "receive":
        build_quic_trace_result(res, ev, ["dcid"])
    elif ev.type == "version_switch":
        build_quic_trace_result(res, ev, ["new_version"])
    elif ev.type == "crypto_decrypt":
        build_quic_trace_result(res, ev, ["packet_num", "len"])
    elif ev.type == "crypto_handshake":
        build_quic_trace_result(res, ev, ["ret"])
    elif ev.type == "packet_prepare":
        build_quic_trace_result(res, ev, ["first_octet", "dcid"])
    elif ev.type == "packet_commit":
        build_quic_trace_result(res, ev, ["packet_num", "packet_len", "ack_only"])
    elif ev.type == "packet_acked":
        build_quic_trace_result(res, ev, ["packet_num", "newly_acked"])
    elif ev.type == "packet_lost":
        build_quic_trace_result(res, ev, ["packet_num"])
    elif ev.type == "cc_ack_received":
        build_quic_trace_result(res, ev, ["largest_acked", "bytes_acked", "cwnd", "inflight"])
    elif ev.type == "cc_congestion":
        build_quic_trace_result(res, ev, ["max_lost_pn", "inflight", "cwnd"])
    elif ev.type == "transport_close_send":
        build_quic_trace_result(res, ev, ["frame_type"])
    elif ev.type == "transport_close_receive":
        build_quic_trace_result(res, ev, ["error_code", "frame_type"])
    elif ev.type == "new_token_send":
        build_quic_trace_result(res, ev, ["token_preview", "len", "token_generation"])
    elif ev.type == "new_token_acked":
        build_quic_trace_result(res, ev, ["token_generation"])
    elif ev.type == "streams_blocked_send":
        build_quic_trace_result(res, ev, ["limit", "is_unidirectional"])
    elif ev.type == "streams_blocked_receive":
        build_quic_trace_result(res, ev, ["limit", "is_unidirectional"])
    elif ev.type == "data_blocked_receive":
        build_quic_trace_result(res, ev, ["off"])
    elif ev.type == "stream_data_blocked_receive":
        build_quic_trace_result(res, ev, ["stream_id", "limit"])
    elif ev.type == "quictrace_sent":
        build_quic_trace_result(res, ev, ["packet_num", "packet_len", "packet_type"])
    elif ev.type == "quictrace_recv":
        build_quic_trace_result(res, ev, ["packet_num"])
    elif ev.type == "quictrace_recv_ack_delay":
        build_quic_trace_result(res, ev, ["ack_delay"])
    elif ev.type == "quictrace_lost":
        build_quic_trace_result(res, ev, ["packet_num"])

    print(json.dumps(res))

def usage():
    print ("USAGE: h2olog -p PID")
    print ("       h2olog quic -p PID")
    print ("       h2olog quic -t event_type -p PID")
    exit()

def trace_http():
    b["rxbuf"].open_perf_buffer(handle_req_line)
    b["txbuf"].open_perf_buffer(handle_resp_line)

    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

def trace_quic():
    b["events"].open_perf_buffer(handle_quic_event)
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if len(sys.argv) < 1:
    usage()

tracer_func = trace_http
optidx = 1
if sys.argv[1] == "quic":
    tracer_func = trace_quic
    optidx = 2

try:
    h2o_pid = 0
    allowed_quic_event = None
    opts, args = getopt.getopt(sys.argv[optidx:], 'p:t:')
    for opt, arg in opts:
        if opt == "-p":
            h2o_pid = arg
        if opt == "-t":
            allowed_quic_event = arg
except getopt.error as msg:
    print(msg)
    sys.exit(2)

if h2o_pid == 0:
    usage()

u = USDT(pid=int(h2o_pid))
if sys.argv[1] == "quic":
    u.enable_probe(probe="accept", fn_name="trace_accept")
    u.enable_probe(probe="receive", fn_name="trace_receive")
    u.enable_probe(probe="version_switch", fn_name="trace_version_switch")
    u.enable_probe(probe="idle_timeout", fn_name="trace_idle_timeout")
    u.enable_probe(probe="stateless_reset_receive", fn_name="trace_stateless_reset_receive")
    u.enable_probe(probe="crypto_decrypt", fn_name="trace_crypto_decrypt")
    u.enable_probe(probe="crypto_handshake", fn_name="trace_crypto_handshake")
    u.enable_probe(probe="packet_prepare", fn_name="trace_packet_prepare")
    u.enable_probe(probe="packet_commit", fn_name="trace_packet_commit")
    u.enable_probe(probe="packet_acked", fn_name="trace_packet_acked")
    u.enable_probe(probe="packet_lost", fn_name="trace_packet_lost")
    u.enable_probe(probe="cc_ack_received", fn_name="trace_cc_ack_received")
    u.enable_probe(probe="cc_congestion", fn_name="trace_cc_congestion")
    u.enable_probe(probe="transport_close_send", fn_name="trace_transport_close_send")
    u.enable_probe(probe="transport_close_receive", fn_name="trace_transport_close_receive")
    u.enable_probe(probe="new_token_send", fn_name="trace_new_token_send")
    u.enable_probe(probe="new_token_acked", fn_name="trace_new_token_acked")
    u.enable_probe(probe="new_token_receive", fn_name="trace_new_token_receive")
    u.enable_probe(probe="streams_blocked_send", fn_name="trace_streams_blocked_send")
    u.enable_probe(probe="streams_blocked_receive", fn_name="trace_streams_blocked_receive")
    u.enable_probe(probe="data_blocked_receive", fn_name="trace_data_blocked_receive")
    u.enable_probe(probe="stream_data_blocked_receive", fn_name="trace_stream_data_blocked_receive")
    u.enable_probe(probe="quictrace_sent", fn_name="trace_quictrace_sent")
    u.enable_probe(probe="quictrace_recv", fn_name="trace_quictrace_recv")
    u.enable_probe(probe="quictrace_recv_ack_delay", fn_name="trace_quictrace_recv_ack_delay")
    u.enable_probe(probe="quictrace_lost", fn_name="trace_quictrace_lost")
    b = BPF(text=quic_bpf, usdt_contexts=[u])
else:
    u.enable_probe(probe="receive_request", fn_name="trace_receive_req")
    u.enable_probe(probe="receive_request_header", fn_name="trace_receive_req_header")
    u.enable_probe(probe="send_response", fn_name="trace_send_resp")
    b = BPF(text=bpf, usdt_contexts=[u])

tracer_func()
