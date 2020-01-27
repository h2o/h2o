#!/usr/bin/env python
#
# h2olog - A BPF-backed request logging client for the H2O server.
#
# USAGE: $ sudo h2olog -p $(pgrep -o h2o)
#
# Copyright 2019 Fastly, Toru Maesaka

from bcc import BPF, USDT
from collections import OrderedDict
import getopt, json, sys

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

struct st_quicly_conn_t {
    u32 dummy[4];
    u32 master_id;
};

struct quic_line_t {
    char type[MAX_STR_LEN];
    char dcid[MAX_STR_LEN];
    u64 at;
    u64 packet_num;
    u64 packet_len;
    u32 ack_only;
    u32 master_conn_id;
    u8 first_octet;
    u32 newly_acked;
};

BPF_PERF_OUTPUT(events);

int trace_accept(struct pt_regs *ctx) {
    struct quic_line_t line = {};
    struct st_quicly_conn_t conn = {};
    void *pos = NULL;
    sprintf(line.type, "accept");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    line.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &line.at);
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_probe_read(&line.dcid, MAX_STR_LEN, pos);

    if (events.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_prepare(struct pt_regs *ctx) {
    struct quic_line_t line = {};
    struct st_quicly_conn_t conn = {};
    void *pos = NULL;
    sprintf(line.type, "packet_prepare");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    line.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &line.at);
    bpf_usdt_readarg(3, ctx, &line.first_octet);
    bpf_usdt_readarg(4, ctx, &pos);
    bpf_probe_read(&line.dcid, MAX_STR_LEN, pos);

    if (events.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_commit(struct pt_regs *ctx) {
    struct quic_line_t line = {};
    struct st_quicly_conn_t conn = {};
    void *pos = NULL;
    sprintf(line.type, "packet_commit");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    line.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &line.at);
    bpf_usdt_readarg(3, ctx, &line.packet_num);
    bpf_usdt_readarg(4, ctx, &line.packet_len);
    bpf_usdt_readarg(5, ctx, &line.ack_only);

    if (events.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_acked(struct pt_regs *ctx) {
    struct quic_line_t line = {};
    struct st_quicly_conn_t conn = {};
    void *pos = NULL;
    sprintf(line.type, "packet_acked");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    line.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &line.at);
    bpf_usdt_readarg(3, ctx, &line.packet_num);
    bpf_usdt_readarg(4, ctx, &line.newly_acked);

    if (events.perf_submit(ctx, &line, sizeof(line)) < 0)
        bpf_trace_printk("failed to perf_submit\\n");

    return 0;
}

int trace_packet_lost(struct pt_regs *ctx) {
    struct quic_line_t line = {};
    struct st_quicly_conn_t conn = {};
    void *pos = NULL;
    sprintf(line.type, "packet_lost");

    bpf_usdt_readarg(1, ctx, &pos);
    bpf_probe_read(&conn, sizeof(conn), pos);
    line.master_conn_id = conn.master_id;
    bpf_usdt_readarg(2, ctx, &line.at);
    bpf_usdt_readarg(3, ctx, &line.packet_num);

    if (events.perf_submit(ctx, &line, sizeof(line)) < 0)
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

def handle_quic_line(cpu, data, size):
    line = b["events"].event(data)
    rv = OrderedDict()
    if line.type == "accept":
        for k in ['type', 'at', 'master_conn_id', 'dcid']:
            rv[k] = getattr(line, k)
    elif line.type == "packet_prepare":
        for k in ['type', 'at', 'master_conn_id', 'first_octet', 'dcid']:
            rv[k] = getattr(line, k)
    elif line.type == "packet_commit":
        for k in ['type', 'at', 'master_conn_id', 'packet_num', 'packet_len', 'ack_only']:
            rv[k] = getattr(line, k)
    elif line.type == "packet_acked":
        for k in ['type', 'at', 'master_conn_id', 'packet_num', 'newly_acked']:
            rv[k] = getattr(line, k)
    elif line.type == "packet_lost":
        for k in ['type', 'at', 'master_conn_id', 'packet_num']:
            rv[k] = getattr(line, k)

    print(json.dumps(rv))

def usage():
    print ("USAGE: h2olog -p PID")
    print ("       h2olog quic -p PID")
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
    b["events"].open_perf_buffer(handle_quic_line)
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
    opts, args = getopt.getopt(sys.argv[optidx:], 'p:')
    for opt, arg in opts:
        if opt == "-p":
            h2o_pid = arg
except getopt.error as msg:
    print(msg)
    sys.exit(2)

if h2o_pid == 0:
    usage()

u = USDT(pid=int(h2o_pid))
if sys.argv[1] == "quic":
    u.enable_probe(probe="accept", fn_name="trace_accept")
    u.enable_probe(probe="packet_prepare", fn_name="trace_packet_prepare")
    u.enable_probe(probe="packet_commit", fn_name="trace_packet_commit")
    u.enable_probe(probe="packet_acked", fn_name="trace_packet_acked")
    u.enable_probe(probe="packet_lost", fn_name="trace_packet_lost")
    b = BPF(text=quic_bpf, usdt_contexts=[u])
else:
    u.enable_probe(probe="receive_request", fn_name="trace_receive_req")
    u.enable_probe(probe="receive_request_header", fn_name="trace_receive_req_header")
    u.enable_probe(probe="send_response", fn_name="trace_send_resp")
    b = BPF(text=bpf, usdt_contexts=[u])

tracer_func()
