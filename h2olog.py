#!/usr/bin/env python
#
# h2olog - A BPF-backed request logging client for the H2O server.
#
# USAGE: $ sudo h2olog -p $(pgrep -o h2o)
#
# Copyright 2019 Fastly, Toru Maesaka

from bcc import BPF, USDT
import getopt, sys

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
    size_t n_len, v_len;
    void *pos = NULL;

    bpf_usdt_readarg(1, ctx, &line.conn_id);
    bpf_usdt_readarg(2, ctx, &line.req_id);

    // Extract the Header Name
    bpf_usdt_readarg(3, ctx, &pos);
    bpf_usdt_readarg(4, ctx, &n_len);
    line.header_name_len = MIN(MAX_STR_LEN, n_len);
    bpf_probe_read(&line.header_name, line.header_name_len, pos);

    // Extract the Header Value
    bpf_usdt_readarg(5, ctx, &pos);
    bpf_usdt_readarg(6, ctx, &v_len);
    line.header_value_len = MIN(MAX_STR_LEN, v_len);
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

try:
    h2o_pid = 0
    opts, args = getopt.getopt(sys.argv[1:], 'p:')
    for opt, arg in opts:
        if opt == "-p":
            h2o_pid = arg
except getopt.error as msg:
    print(msg)
    sys.exit(2)

if h2o_pid == 0:
    sys.exit("USAGE: h2olog -p PID")

u = USDT(pid=int(h2o_pid))
u.enable_probe(probe="receive_request", fn_name="trace_receive_req")
u.enable_probe(probe="receive_request_header", fn_name="trace_receive_req_header")
u.enable_probe(probe="send_response", fn_name="trace_send_resp")

b = BPF(text=bpf, usdt_contexts=[u])
b["rxbuf"].open_perf_buffer(handle_req_line)
b["txbuf"].open_perf_buffer(handle_resp_line)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
