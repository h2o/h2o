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
#include <unistd.h>

#include "h2olog.h"

using namespace std;

#define VERSION "0.1.0"
#define POLL_TIMEOUT (1000)

static void usage(void)
{
    printf("h2olog (%s)\n", VERSION);
    printf("-p PID of the H2O server\n");
    printf("-h Print this help and exit\n");
    return;
}

static void show_event_per_sec(h2o_tracer_t *tracer, time_t *t0)
{
    time_t t1 = time(NULL);
    int64_t d = t1 - *t0;
    if (d > 10) {
        uint64_t c = tracer->count / d;
        if (c > 0) {
            struct tm t;
            localtime_r(&t1, &t);
            char s[100];
            const char *iso8601format = "%FT%TZ";
            strftime(s, sizeof(s), iso8601format, &t);

            fprintf(stderr, "%s %20lu events/s\n", s, c);
            tracer->count = 0;
        }
        *t0 = t1;
    }
}

static void show_process(pid_t pid)
{
    char cmdline[256];
    char proc_file[256];
    snprintf(proc_file, sizeof(proc_file), "/proc/%d/cmdline", pid);
    FILE *f = fopen(proc_file, "r");
    if (f == nullptr) {
        fprintf(stderr, "Failed to open %s: %s\n", proc_file, strerror(errno));
        exit(EXIT_FAILURE);
    }
    size_t nread = fread(cmdline, 1, sizeof(cmdline), f);
    fclose(f);
    for (size_t i = 0; i < nread; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    fprintf(stderr, "Attaching pid=%d (%s)\n", pid, cmdline);
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

    bool debug = false;
    const char *out_file = nullptr;
    int c;
    pid_t h2o_pid = -1;
    while ((c = getopt(argc, argv, "hvp:t:s:dP:o:")) != -1) {
        switch (c) {
        case 'p':
            h2o_pid = atoi(optarg);
            break;
        case 'o':
            out_file = optarg;
            break;
        case 'd':
            debug = true;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        default:
            usage();
            exit(EXIT_FAILURE);
        }
    }

    if (argc > optind) {
        fprintf(stderr, "Error: too many aruments\n");
        usage();
        exit(EXIT_FAILURE);
    }

    if (h2o_pid == -1) {
        fprintf(stderr, "Error: -p option is missing\n");
        usage();
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Error: root privilege is required\n");
        exit(EXIT_FAILURE);
    }

    if (out_file != nullptr) {
        FILE *out = fopen(out_file, "w");
        if (out == nullptr) {
            fprintf(stderr, "Error: failed to open %s: %s", out_file, strerror(errno));
            exit(EXIT_FAILURE);
        }
        tracer->out = out;
    } else {
        tracer->out = stdout;
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

    ret = bpf->open_perf_buffer("events", tracer->handle_event, nullptr, tracer, 64);
    if (ret.code() != 0) {
        fprintf(stderr, "open_perf_buffer: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    if (debug) {
        show_process(h2o_pid);
    }

    ebpf::BPFPerfBuffer *perf_buffer = bpf->get_perf_buffer("events");
    if (perf_buffer) {
        time_t t0 = time(NULL);

        while (true) {
            perf_buffer->poll(POLL_TIMEOUT);
            fflush(tracer->out);

            if (debug) {
                show_event_per_sec(tracer, &t0);
            }
        }
    }

    fprintf(stderr, "Error: failed to get_perf_buffer()\n");
    return EXIT_FAILURE;
}
