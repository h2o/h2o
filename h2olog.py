#!/usr/bin/env python
#
# h2olog - A BPF-backed request logging client for the H2O server.
#
# USAGE: $ sudo h2olog -p $(pgrep -o h2o)
#
# Copyright 2019 Fastly, Toru Maesaka

from bcc import BPF, USDT
from collections import OrderedDict
import binascii, getopt, json, sys

bpf = """
#include <stdio.h>

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
    u64 packet_num;
    u64 packet_len;
    u8 packet_type;
    u32 ack_only;
    u64 largest_acked;
    u64 bytes_acked;
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
        hsh[k] = getattr(line, k)

def handle_quic_event(cpu, data, size):
    line = b["events"].event(data)
    if allowed_quic_event and line.type != allowed_quic_event:
        return

    rv = OrderedDict()
    load_common_fields(rv, line)

    if line.type == "accept":
        rv["dcid"] = getattr(line, "dcid")
    elif line.type == "receive":
        rv["dcid"] = getattr(line, "dcid")
    elif line.type == "version_switch":
        rv["new_version"] = getattr(line, "new_version")
    elif line.type == "packet_prepare":
        for k in ["first_octet", "dcid"]:
            rv[k] = getattr(line, k)
    elif line.type == "packet_commit":
        for k in ["packet_num", "packet_len", "ack_only"]:
            rv[k] = getattr(line, k)
    elif line.type == "packet_acked":
        for k in ["packet_num", "newly_acked"]:
            rv[k] = getattr(line, k)
    elif line.type == "packet_lost":
        for k in ["packet_num"]:
            rv[k] = getattr(line, k)
    elif line.type == "cc_ack_received":
        for k in ["largest_acked", "bytes_acked", "cwnd", "inflight"]:
            rv[k] = getattr(line, k)
    elif line.type == "cc_congestion":
        for k in ["max_lost_pn", "inflight", "cwnd"]:
            rv[k] = getattr(line, k)
    elif line.type == "new_token_send":
        for k in ["token_preview", "len", "token_generation"]:
            rv[k] = getattr(line, k)
        rv["token_preview"] = binascii.hexlify(rv["token_preview"])
    elif line.type == "new_token_acked":
        rv["token_generation"] = getattr(line, "token_generation")
    elif line.type == "streams_blocked_send":
        for k in ["limit", "is_unidirectional"]:
            rv[k] = getattr(line, k)
    elif line.type == "streams_blocked_receive":
        for k in ["limit", "is_unidirectional"]:
            rv[k] = getattr(line, k)
    elif line.type == "data_blocked_receive":
        rv["off"] = getattr(line, "off")
    elif line.type == "stream_data_blocked_receive":
        for k in ["stream_id", "limit"]:
            rv[k] = getattr(line, k)
    elif line.type == "quictrace_sent":
        for k in ["packet_num", "packet_len", "packet_type"]:
            rv[k] = getattr(line, k)
    elif line.type == "quictrace_recv":
        for k in ["packet_num"]:
            rv[k] = getattr(line, k)
    elif line.type == "quictrace_lost":
        for k in ["packet_num"]:
            rv[k] = getattr(line, k)

    print(json.dumps(rv))

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
    u.enable_probe(probe="packet_prepare", fn_name="trace_packet_prepare")
    u.enable_probe(probe="packet_commit", fn_name="trace_packet_commit")
    u.enable_probe(probe="packet_acked", fn_name="trace_packet_acked")
    u.enable_probe(probe="packet_lost", fn_name="trace_packet_lost")
    u.enable_probe(probe="cc_ack_received", fn_name="trace_cc_ack_received")
    u.enable_probe(probe="cc_congestion", fn_name="trace_cc_congestion")
    u.enable_probe(probe="new_token_send", fn_name="trace_new_token_send")
    u.enable_probe(probe="new_token_acked", fn_name="trace_new_token_acked")
    u.enable_probe(probe="new_token_receive", fn_name="trace_new_token_receive")
    u.enable_probe(probe="streams_blocked_send", fn_name="trace_streams_blocked_send")
    u.enable_probe(probe="streams_blocked_receive", fn_name="trace_streams_blocked_receive")
    u.enable_probe(probe="data_blocked_receive", fn_name="trace_data_blocked_receive")
    u.enable_probe(probe="stream_data_blocked_receive", fn_name="trace_stream_data_blocked_receive")
    u.enable_probe(probe="quictrace_sent", fn_name="trace_quictrace_sent")
    u.enable_probe(probe="quictrace_recv", fn_name="trace_quictrace_recv")
    u.enable_probe(probe="quictrace_lost", fn_name="trace_quictrace_lost")
    b = BPF(text=quic_bpf, usdt_contexts=[u])
else:
    u.enable_probe(probe="receive_request", fn_name="trace_receive_req")
    u.enable_probe(probe="receive_request_header", fn_name="trace_receive_req_header")
    u.enable_probe(probe="send_response", fn_name="trace_send_resp")
    b = BPF(text=bpf, usdt_contexts=[u])

tracer_func()
