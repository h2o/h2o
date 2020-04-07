/*
 * Copyright (c) 2019-2020 Fastly, Inc., Toru Maesaka
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

#include "h2olog.h"

const char *HTTP_BPF = R"(
enum {
  HTTP_EVENT_RECEIVE_REQ
};

struct event_t {
  uint8_t type;
  uint64_t conn_id;
  uint64_t req_id;
  union {
    uint32_t http_version;
  };
};

BPF_PERF_OUTPUT(events);

int trace_receive_request(struct pt_regs *ctx) {
  struct event_t ev = {};
  ev.type = HTTP_EVENT_RECEIVE_REQ;
  bpf_usdt_readarg(1, ctx, &ev.conn_id);
  bpf_usdt_readarg(2, ctx, &ev.req_id);
  bpf_usdt_readarg(3, ctx, &ev.http_version);
  if (events.perf_submit(ctx, &ev, sizeof(ev)) < 0)
    bpf_trace_printk("failed to perf_submit\\n");
  return 0;
}
)";

enum {
  HTTP_EVENT_RECEIVE_REQ
};

struct http_event_t {
    uint8_t type;
    uint64_t conn_id;
    uint64_t req_id;

    union {
      uint32_t http_version;
    };
};

static void handle_event(void *cpu, void *data, int len)
{
    struct http_event_t *ev = (http_event_t *)data;
    if (ev->type == HTTP_EVENT_RECEIVE_REQ) {
      printf("%" PRIu64 " %" PRIu64 " RxProtocol HTTP/%" PRIu32 ".%" PRIu32 "\n",
             ev->conn_id, ev->req_id, ev->http_version / 256, ev->http_version % 256);
    }
}

static std::vector<ebpf::USDT> init_usdt_probes(pid_t h2o_pid)
{
    std::vector<ebpf::USDT> vec;
    vec.push_back(ebpf::USDT(h2o_pid, "h2o", "receive_request", "trace_receive_request"));
    return vec;
}

static const char *bpf_text(void)
{
    return HTTP_BPF;
}

h2o_tracer_t *create_http_tracer(void)
{
    h2o_tracer_t *tracer = (h2o_tracer_t *)malloc(sizeof(tracer));
    tracer->handle_event = handle_event;
    tracer->init_usdt_probes = init_usdt_probes;
    tracer->bpf_text = bpf_text;
    return tracer;
}
