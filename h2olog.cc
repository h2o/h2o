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

#include <inttypes.h>
#include <bcc/BPF.h>
#include <iostream>

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
)";

#define VERSION "0.1.0"
#define POLL_TIMEOUT 100

struct event_t {
  uint64_t at;
};

typedef void (*bpf_cb)(void *cpu, void *data, int len);

static void usage(void) {
  printf("h2olog (%s)\n", VERSION);
  printf("-p PID of the H2O server\n");
  printf("-h Print this help and exit\n");
  return;
}

void handle_http_event(void *cpu, void *data, int len) {
  printf("unimplemented\n");
}

void handle_quic_event(void *cpu, void *data, int len) {
  struct event_t *ev = (event_t*)data;
  printf("time: %" PRIu64 "\n", ev->at);
}

int main(int argc, char **argv) {
  pid_t h2o_pid = -1;
  bpf_cb cb = handle_http_event;

  if (argc > 1 && strcmp(argv[1], "quic") == 0) {
    cb = handle_quic_event;
    --argc;
    ++argv;
  }

  int c;
  while ((c = getopt(argc, argv, "hvp:t:s:dP:")) != -1) {
    switch(c) {
    case 'p':
      h2o_pid = atoi(optarg);
      break;
    case 'h':
      usage();
      exit(EXIT_SUCCESS);
    }
  }

  if (h2o_pid == -1) {
    fprintf(stderr, "Error: -p option is missing\n");
    exit(EXIT_FAILURE);
  }

  ebpf::BPF *bpf = new ebpf::BPF();
  ebpf::USDT u("", h2o_pid, "quicly", "accept", "trace_quicly__accept");
  ebpf::StatusTuple ret = bpf->init(QUIC_BPF, {}, {u});
  if (ret.code() != 0) {
    std::cerr << ret.msg() << std::endl;
    return 1;
  }

  ret = bpf->attach_usdt(u);
  if (ret.code() != 0) {
    std::cerr << ret.msg() << std::endl;
    return 1;
  }

  ret = bpf->open_perf_buffer("events", cb);
  if (ret.code() != 0) {
    std::cerr << ret.msg() << std::endl;
    return 1;
  }

  ebpf::BPFPerfBuffer *perf_buffer = bpf->get_perf_buffer("events");
  if (perf_buffer)
    while (true)
      perf_buffer->poll(POLL_TIMEOUT);

  return 0;
}
