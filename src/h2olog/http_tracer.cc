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
#include <linux/sched.h>

#define MAX_HDR_LEN 128

enum {
  HTTP_EVENT_RECEIVE_REQ,
  HTTP_EVENT_RECEIVE_REQ_HDR,
  HTTP_EVENT_SEND_RESP,
  HTTP_EVENT_SEND_RESP_HDR,
  SCHED_PROCESS_EXIT,
};

typedef struct  st_http_event_t {
  uint8_t type;
  uint64_t conn_id;
  uint64_t req_id;
  union {
    uint32_t http_version;
    uint32_t http_status;
    struct {
      uint64_t name_len;
      uint64_t value_len;
      char name[MAX_HDR_LEN];
      char value[MAX_HDR_LEN];
    } header;
  };
} http_event_t;

BPF_PERF_OUTPUT(events);

int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  pid_t h2o_pid = task->tgid;
  pid_t h2o_tid = task->pid;
  if (!(h2o_pid == H2OLOG_H2O_PID && h2o_tid == H2OLOG_H2O_PID)) {
    return 0;
  }
  http_event_t ev = { .type = SCHED_PROCESS_EXIT };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

int trace_receive_request(struct pt_regs *ctx) {
  http_event_t ev = { .type = HTTP_EVENT_RECEIVE_REQ };
  bpf_usdt_readarg(1, ctx, &ev.conn_id);
  bpf_usdt_readarg(2, ctx, &ev.req_id);
  bpf_usdt_readarg(3, ctx, &ev.http_version);
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

int trace_receive_request_header(struct pt_regs *ctx) {
  http_event_t ev = { .type = HTTP_EVENT_RECEIVE_REQ_HDR };
  void *pos = NULL;
  bpf_usdt_readarg(1, ctx, &ev.conn_id);
  bpf_usdt_readarg(2, ctx, &ev.req_id);
  bpf_usdt_readarg(3, ctx, &pos);
  bpf_usdt_readarg(4, ctx, &ev.header.name_len);
  bpf_probe_read(&ev.header.name, sizeof(ev.header.name), pos);
  bpf_usdt_readarg(5, ctx, &pos);
  bpf_usdt_readarg(6, ctx, &ev.header.value_len);
  bpf_probe_read(&ev.header.value, sizeof(ev.header.value), pos);
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

int trace_send_response(struct pt_regs *ctx) {
  http_event_t ev = { .type = HTTP_EVENT_SEND_RESP };
  bpf_usdt_readarg(1, ctx, &ev.conn_id);
  bpf_usdt_readarg(2, ctx, &ev.req_id);
  bpf_usdt_readarg(3, ctx, &ev.http_status);
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

int trace_send_response_header(struct pt_regs *ctx) {
  http_event_t ev = { .type = HTTP_EVENT_SEND_RESP_HDR };
  void *pos = NULL;
  bpf_usdt_readarg(1, ctx, &ev.conn_id);
  bpf_usdt_readarg(2, ctx, &ev.req_id);
  bpf_usdt_readarg(3, ctx, &pos);
  bpf_usdt_readarg(4, ctx, &ev.header.name_len);
  bpf_probe_read(&ev.header.name, sizeof(ev.header.name), pos);
  bpf_usdt_readarg(5, ctx, &pos);
  bpf_usdt_readarg(6, ctx, &ev.header.value_len);
  bpf_probe_read(&ev.header.value, sizeof(ev.header.value), pos);
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}
)";

#define MAX_HDR_LEN 128
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

enum {
    HTTP_EVENT_RECEIVE_REQ,
    HTTP_EVENT_RECEIVE_REQ_HDR,
    HTTP_EVENT_SEND_RESP,
    HTTP_EVENT_SEND_RESP_HDR,
    SCHED_PROCESS_EXIT,
};

typedef struct st_http_event_t {
    uint8_t type;
    uint64_t conn_id;
    uint64_t req_id;
    union {
        uint32_t http_version;
        uint32_t http_status;
        struct {
            uint64_t name_len;
            uint64_t value_len;
            char name[MAX_HDR_LEN];
            char value[MAX_HDR_LEN];
        } header;
    };
} http_event_t;

class h2o_http_tracer : public h2o_tracer
{
  protected:
    virtual void do_handle_event(const void *data, int len)
    {
        const http_event_t *ev = (const http_event_t *)data;

        switch (ev->type) {
        case HTTP_EVENT_RECEIVE_REQ:
            fprintf(out_, "%" PRIu64 " %" PRIu64 " RxProtocol HTTP/%" PRIu32 ".%" PRIu32 "\n", ev->conn_id, ev->req_id,
                    ev->http_version / 256, ev->http_version % 256);
            break;
        case HTTP_EVENT_SEND_RESP:
            fprintf(out_, "%" PRIu64 " %" PRIu64 " TxStatus   %" PRIu32 "\n", ev->conn_id, ev->req_id, ev->http_status);
            break;
        case HTTP_EVENT_RECEIVE_REQ_HDR:
        case HTTP_EVENT_SEND_RESP_HDR: {
            int n_len = MIN(ev->header.name_len, MAX_HDR_LEN);
            int v_len = MIN(ev->header.value_len, MAX_HDR_LEN);
            const char *label = (ev->type == HTTP_EVENT_RECEIVE_REQ_HDR) ? "RxHeader" : "TxHeader";
            fprintf(out_, "%" PRIu64 " %" PRIu64 " %s   %.*s %.*s\n", ev->conn_id, ev->req_id, label, n_len, ev->header.name, v_len,
                    ev->header.value);
        } break;
        case SCHED_PROCESS_EXIT: {
            exit(0);
        } break;
        default:
            fprintf(out_, "unknown event: %u\n", ev->type);
        }
    }
    virtual void do_handle_lost(uint64_t lost)
    {
        fprintf(stderr, "Possibly lost %" PRIu64 " events\n", lost);
    }

  public:
    virtual std::string select_usdts(const char *_pattern) {
      return "-t is not supported by the HTTP tracer (-H)";
    }

    virtual const std::vector<h2o_tracer::usdt> &usdt_probes()
    {
        static const std::vector<h2o_tracer::usdt> vec{
            h2o_tracer::usdt("h2o", "receive_request", "trace_receive_request"),
            h2o_tracer::usdt("h2o", "receive_request_header", "trace_receive_request_header"),
            h2o_tracer::usdt("h2o", "send_response", "trace_send_response"),
            h2o_tracer::usdt("h2o", "send_response_header", "trace_send_response_header"),
        };
        return vec;
    }
    virtual std::string bpf_text()
    {
        return HTTP_BPF;
    }
};

h2o_tracer *create_http_tracer()
{
    return new h2o_http_tracer();
}
