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

#include <vector>

#include "h2olog.h"

using namespace std;

#define VERSION "0.1.0"
#define POLL_TIMEOUT 100

static void usage(void)
{
    printf("h2olog (%s)\n", VERSION);
    printf("-p PID of the H2O server\n");
    printf("-h Print this help and exit\n");
    return;
}

int main(int argc, char **argv)
{
    h2o_tracer_t *tracer;
    if (argc > 1 && strcmp(argv[1], "quic") == 0) {
        tracer = create_quic_tracer();
        --argc;
        ++argv;
    } else {
        tracer = create_http_tracer();
    }

    int c;
    pid_t h2o_pid = -1;
    while ((c = getopt(argc, argv, "hvp:t:s:dP:")) != -1) {
        switch (c) {
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

    if (geteuid() != 0) {
        fprintf(stderr, "Error: root privilege is required\n");
        exit(EXIT_FAILURE);
    }

    ebpf::BPF *bpf = new ebpf::BPF();
    std::vector<ebpf::USDT> probes = tracer->init_usdt_probes(h2o_pid);

    ebpf::StatusTuple ret = bpf->init(tracer->bpf_text(), {}, probes);
    if (ret.code() != 0) {
        fprintf(stderr, "init: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    for (auto &probe : probes) {
        ret = bpf->attach_usdt(probe);
        if (ret.code() != 0) {
            fprintf(stderr, "attach_usdt: %s\n", ret.msg().c_str());
            return EXIT_FAILURE;
        }
    }

    ret = bpf->open_perf_buffer("events", tracer->handle_event);
    if (ret.code() != 0) {
        fprintf(stderr, "open_perf_buffer: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    ebpf::BPFPerfBuffer *perf_buffer = bpf->get_perf_buffer("events");
    if (perf_buffer) {
        while (true) {
            perf_buffer->poll(POLL_TIMEOUT);
            fflush(stdout);
        }
    }

    return 0;
}
