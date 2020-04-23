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
#include <stdarg.h>

#include "h2olog.h"

#define VERSION "0.1.0"
#define POLL_TIMEOUT (1000)

static void usage(void)
{
    printf(R"(h2olog (v%s)
Usage: h2olog -p PID
       h2olog quic -p PID
       h2olog quic -t event_type -p PID
       h2olog quic -v -s response_header_name -p PID
Other options:
    -h Shows this help and exit.
    -d Shows debugging information.
    -w <file> Write output to <file> instead of stdout.
)",
           VERSION);
    return;
}

static void make_timestamp(char *buf, size_t buf_len)
{
    time_t t = time(NULL);
    struct tm tms;
    localtime_r(&t, &tms);
    const char *iso8601format = "%FT%TZ";
    strftime(buf, buf_len, iso8601format, &tms);
}

static void infof(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void infof(const char *fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    char timestamp[128];
    make_timestamp(timestamp, sizeof(timestamp));

    fprintf(stderr, "%s %s\n", timestamp, buf);
}

static void show_event_per_sec(h2o_tracer_t *tracer, time_t *t0)
{
    time_t t1 = time(NULL);
    int64_t d = t1 - *t0;
    if (d > 10) {
        uint64_t c = tracer->count / d;
        if (c > 0) {
            if (tracer->lost_count > 0) {
                infof("%20" PRIu64 " events/s (possibly lost %" PRIu64 " events)", c, tracer->lost_count);
                tracer->lost_count = 0;
            } else {
                infof("%20" PRIu64 " events/s", c);
            }
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
        fprintf(stderr, "Error: failed to open %s: %s\n", proc_file, strerror(errno));
        exit(EXIT_FAILURE);
    }
    size_t nread = fread(cmdline, 1, sizeof(cmdline), f);
    fclose(f);
    for (size_t i = 0; i < nread; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    infof("Attaching pid=%d (%s)", pid, cmdline);
}

static std::string join_str(const std::string &sep, const std::vector<std::string> &strs)
{
    std::string s;
    for (auto iter = strs.cbegin(); iter != strs.cend(); ++iter) {
        if (iter != strs.cbegin()) {
            s += sep;
        }
        s += *iter;
    }
    return s;
}

static std::string generate_header_filter_cflag(const std::vector<std::string> &tokens)
{
    std::vector<std::string> conditions;

    for (auto &token : tokens) {
        char buf[256];
        snprintf(buf, sizeof(buf), "/* %s */ (slen) == %zu", token.c_str(), token.size());
        std::vector<std::string> exprs = {buf};

        for (size_t i = 0; i < token.size(); ++i) {
            snprintf(buf, sizeof(buf), "(s)[%zu] == '%c'", i, token[i]);
            exprs.push_back(buf);
        }
        conditions.push_back("(" + join_str(" && ", exprs) + ")");
    }

    std::string cflag("-DCHECK_ALLOWED_RES_HEADER_NAME(s,slen)=(");
    cflag += join_str(" || ", conditions);
    cflag += ")";
    return cflag;
}

static void event_cb(void *context, void *data, int len)
{
    h2o_tracer_t *tracer = (h2o_tracer_t *)context;
    tracer->count++;

    tracer->handle_event(tracer, data, len);
}

static void lost_cb(void *context, uint64_t lost)
{
    h2o_tracer_t *tracer = (h2o_tracer_t *)context;
    tracer->lost_count += lost;

    tracer->handle_lost(tracer, lost);
}

int main(int argc, char **argv)
{
    h2o_tracer_t tracer = {};
    if (argc > 1 && strcmp(argv[1], "quic") == 0) {
        init_quic_tracer(&tracer);
        --argc;
        ++argv;
    } else {
        init_http_tracer(&tracer);
    }

    bool debug = false;
    const char *out_file = nullptr;
    std::vector<std::string> event_type_filters;
    std::vector<std::string> response_header_filters;
    int c;
    pid_t h2o_pid = -1;
    while ((c = getopt(argc, argv, "hdp:t:s:w:")) != -1) {
        switch (c) {
        case 'p':
            h2o_pid = atoi(optarg);
            break;
        case 't':
            event_type_filters.push_back(optarg);
            break;
        case 's':
            response_header_filters.push_back(optarg);
            break;
        case 'w':
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
        tracer.out = out;
    } else {
        tracer.out = stdout;
    }

    std::vector<std::string> cflags;

    if (!response_header_filters.empty()) {
        cflags.push_back(generate_header_filter_cflag(response_header_filters));
    }

    ebpf::BPF *bpf = new ebpf::BPF();
    std::vector<ebpf::USDT> probes = tracer.init_usdt_probes(h2o_pid);

    ebpf::StatusTuple ret = bpf->init(tracer.bpf_text(), cflags, probes);
    if (ret.code() != 0) {
        fprintf(stderr, "Error: init: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    for (auto &probe : probes) {
        ret = bpf->attach_usdt(probe);
        if (ret.code() != 0) {
            fprintf(stderr, "Error: attach_usdt: %s\n", ret.msg().c_str());
            return EXIT_FAILURE;
        }
    }

    ret = bpf->open_perf_buffer("events", event_cb, lost_cb, &tracer, 64);
    if (ret.code() != 0) {
        fprintf(stderr, "Error: open_perf_buffer: %s\n", ret.msg().c_str());
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
            fflush(tracer.out);

            if (debug) {
                show_event_per_sec(&tracer, &t0);
            }
        }
    }

    fprintf(stderr, "Error: failed to get_perf_buffer()\n");
    return EXIT_FAILURE;
}
