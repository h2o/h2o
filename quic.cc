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

#include "h2olog.h"

const char *QUIC_BPF = R"(
struct event_t {
  uint64_t at;
};

BPF_PERF_OUTPUT(events);

int trace_quicly__accept(struct pt_regs *ctx) {
  struct event_t event = {};
  bpf_usdt_readarg(2, ctx, &event.at);
  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

int trace_quicly__crypto_handshake(struct pt_regs *ctx) {
  struct event_t event = {};
  bpf_usdt_readarg(2, ctx, &event.at);
  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}
)";

struct quic_event_t {
  uint64_t at;
};

static void handle_event(void *cpu, void *data, int len) {
  struct quic_event_t *ev = (quic_event_t*)data;
  printf("time: %" PRIu64 "\n", ev->at);
}

static std::vector<ebpf::USDT> init_usdt_probes(pid_t h2o_pid) {
  std::vector<ebpf::USDT> vec;
  vec.push_back(ebpf::USDT(h2o_pid, "quicly", "accept", "trace_quicly__accept"));
  vec.push_back(ebpf::USDT(h2o_pid, "quicly", "crypto_handshake", "trace_quicly__crypto_handshake"));
  return vec;
}

h2o_tracer_t *create_quic_tracer(void) {
  h2o_tracer_t *tracer = (h2o_tracer_t*)malloc(sizeof(tracer));
  tracer->handle_event = handle_event;
  tracer->init_usdt_probes = init_usdt_probes;
  return tracer;
}
