/*
 * Demonstration of how we might port the Python h2olog to C++.
 * Compile with: "g++ -o h2olog -I/usr/include/bcc/compat h2olog.cc -lbcc"
 */

#include <bcc/BPF.h>
#include <iostream>

const std::string QUIC_BPF = R"(
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

#define POLL_TIMEOUT 100

struct event_t {
  uint64_t at;
};

void handle_quic_event(void *cpu, void *data, int len) {
  struct event_t *ev = (event_t*)data;
  std::cout << "time: " << ev->at << std::endl;
}

int main(int argc, char **argv) {
  // Simplified for demonstration purpose.
  pid_t pid = -1;
  if (argc < 2) {
    std::cerr << "h2olog <pid>" << std::endl;
    return 1;
  }
  pid = std::atoi(argv[1]);

  ebpf::BPF *bpf = new ebpf::BPF();
  ebpf::USDT u("", pid, "quicly", "accept", "trace_quicly__accept");
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

  ret = bpf->open_perf_buffer("events", &handle_quic_event);
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
