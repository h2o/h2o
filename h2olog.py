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

/*
 * "req_line_t" represents an individual log line for a given request.
 * This structure is pushed into the BPF ring buffer for later collection
 * by the user-space script (Python part of this script).
 */
struct req_line_t {
    u64 conn_id;
    u64 req_id;
    u32 http_version;
    u64 header_name_len;
    u64 header_value_len;
    char header_name[MAX_STR_LEN];
    char header_value[MAX_STR_LEN];
};

int trace_receive_req(void *ctx) {
    return 0;
}

int trace_receive_req_header(void *ctx) {
    return 0;
}
"""

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

b = BPF(text=bpf, usdt_contexts=[u])
