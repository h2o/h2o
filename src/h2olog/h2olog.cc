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

#include <memory>
#include <vector>
#include <algorithm>
#include <bcc/BPF.h>
extern "C" {
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include "h2o/memory.h"
#include "h2o/version.h"
}
#include "h2olog.h"

#define POLL_TIMEOUT (1000)
#define PERF_BUFFER_PAGE_COUNT 256

static void usage(void)
{
    printf(R"(h2olog (h2o v%s)
Usage: h2olog -p PID
Optional arguments:
    -d Print debugging information (-dd shows more)
    -h Print this help and exit
    -l Print the list of available tracepoints and exit
    -H Trace HTTP requests and responses in varnishlog-like format
    -s RESPONSE_HEADER_NAME A response header name to show, e.g. "content-type"
    -t TRACEPOINT A tracepoint, or fully-qualified probe name, to show,
                  including a glob pattern, e.g. "quicly:accept", "h2o:*"
    -r Run without dropping root privilege
    -w Path to write the output (default: stdout)

Examples:
    h2olog -p -H $(pgrep -o h2o)
    h2olog -p $(pgrep -o h2o) -t quicly:accept -t quicly:free
    h2olog -p $(pgrep -o h2o) -t h2o:send_response_header -t h2o:h3s_accept -t h2o:h3s_destroy -s alt-svc
)",
           H2O_VERSION);
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

uint64_t h2o_tracer::time_milliseconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void h2o_tracer::show_event_per_sec(time_t *t0)
{
    time_t t1 = time(NULL);
    int64_t d = t1 - *t0;
    if (d > 10) {
        uint64_t c = stats_.num_events / d;
        if (c > 0) {
            if (stats_.num_lost > 0) {
                infof("%20" PRIu64 " events/s (possibly lost %" PRIu64 " events)", c, stats_.num_lost);
                stats_.num_lost = 0;
            } else {
                infof("%20" PRIu64 " events/s", c);
            }
            stats_.num_events = 0;
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
    if (nread == 0) {
        fprintf(stderr, "Error: failed to read from %s: %s\n", proc_file, strerror(errno));
        exit(EXIT_FAILURE);
    }
    nread--; // skip trailing nul
    for (size_t i = 0; i < nread; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    infof("Attaching pid=%d (%s)", pid, cmdline);
}

static void drop_root_privilege(void)
{
    if (getuid() == 0) {
        const char *sudo_gid = getenv("SUDO_GID");
        if (sudo_gid == NULL) {
            fprintf(stderr, "Error: the SUDO_GID environment variable is not set\n");
            exit(EXIT_FAILURE);
        }
        errno = 0;
        gid_t gid = (gid_t)strtol(sudo_gid, NULL, 10);
        if (errno != 0) {
            fprintf(stderr, "Error: failed to parse SUDO_GID\n");
            exit(EXIT_FAILURE);
        }
        if (setgid(gid) != 0) {
            perror("Error: setgid(2) failed");
            exit(EXIT_FAILURE);
        }
        const char *sudo_uid = getenv("SUDO_UID");
        if (sudo_uid == NULL) {
            fprintf(stderr, "Error: the SUDO_UID environment variable is not set\n");
            exit(EXIT_FAILURE);
        }
        errno = 0;
        uid_t uid = (uid_t)strtol(sudo_uid, NULL, 10);
        if (errno != 0) {
            fprintf(stderr, "Error: failed to parse SUDO_UID\n");
            exit(EXIT_FAILURE);
        }
        if (setuid(uid) != 0) {
            perror("Error: setuid(2) failed");
            exit(EXIT_FAILURE);
        }
    }
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

static std::string make_pid_cflag(const char *macro_name, pid_t pid)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "-D%s=%d", macro_name, pid);
    return std::string(buf);
}

static void event_cb(void *context, void *data, int len)
{
    h2o_tracer *tracer = (h2o_tracer *)context;
    tracer->handle_event(data, len);
}

static void lost_cb(void *context, uint64_t lost)
{
    h2o_tracer *tracer = (h2o_tracer *)context;
    tracer->handle_lost(lost);
}

int main(int argc, char **argv)
{
    std::unique_ptr<h2o_tracer> tracer(create_raw_tracer());

    int debug = 0;
    bool preserve_root = false;
    bool list_usdts = false;
    FILE *outfp = stdout;
    std::vector<std::string> response_header_filters;
    int c;
    pid_t h2o_pid = -1;
    while ((c = getopt(argc, argv, "hHdrlp:t:s:w:")) != -1) {
        switch (c) {
        case 'H':
            tracer.reset(create_http_tracer());
            break;
        case 'p':
            h2o_pid = atoi(optarg);
            break;
        case 't': {
            std::string err = tracer->select_usdts(optarg);
            if (!err.empty()) {
                fprintf(stderr, "%s\n", err.c_str());
                exit(EXIT_FAILURE);
            }
            break;
        }
        case 's':
            response_header_filters.push_back(optarg);
            break;
        case 'w':
            if ((outfp = fopen(optarg, "w")) == nullptr) {
                fprintf(stderr, "Error: failed to open %s: %s", optarg, strerror(errno));
                exit(EXIT_FAILURE);
            }
            break;
        case 'd':
            debug++;
            break;
        case 'l':
            list_usdts = true;
            break;
        case 'r':
            preserve_root = true;
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

    if (list_usdts) {
        for (const auto &usdt : tracer->usdt_probes()) {
            printf("%s\n", usdt.fully_qualified_name().c_str());
        }
        exit(EXIT_SUCCESS);
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

    tracer->init(outfp);

    std::vector<std::string> cflags({
        make_pid_cflag("H2OLOG_H2O_PID", h2o_pid),
    });

    if (!response_header_filters.empty()) {
        cflags.push_back(generate_header_filter_cflag(response_header_filters));
    }

    if (debug >= 2) {
        fprintf(stderr, "usdts=");
        const auto &usdts = tracer->usdt_probes();
        for (auto iter = usdts.cbegin(); iter != usdts.cend(); iter++) {
            if (iter != usdts.cbegin()) {
                fprintf(stderr, ",");
            }
            fprintf(stderr, "%s", iter->fully_qualified_name().c_str());
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "cflags=");
        for (size_t i = 0; i < cflags.size(); i++) {
            if (i > 0) {
                fprintf(stderr, " ");
            }
            fprintf(stderr, "%s", cflags[i].c_str());
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "<BPF>\n%s\n</BPF>\n", tracer->bpf_text().c_str());
    }

    ebpf::BPF *bpf = new ebpf::BPF();
    std::vector<ebpf::USDT> probes;

    for (const auto &usdt : tracer->usdt_probes()) {
        probes.push_back(ebpf::USDT(h2o_pid, usdt.provider, usdt.name, usdt.probe_func));
    }

    ebpf::StatusTuple ret = bpf->init(tracer->bpf_text(), cflags, probes);
    if (ret.code() != 0) {
        fprintf(stderr, "Error: init: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    bpf->attach_tracepoint("sched:sched_process_exit", "trace_sched_process_exit");

    for (auto &probe : probes) {
        ret = bpf->attach_usdt(probe);
        if (ret.code() != 0) {
            fprintf(stderr, "Error: attach_usdt: %s\n", ret.msg().c_str());
            return EXIT_FAILURE;
        }
    }

    ret = bpf->open_perf_buffer("events", event_cb, lost_cb, tracer.get(), PERF_BUFFER_PAGE_COUNT);
    if (ret.code() != 0) {
        fprintf(stderr, "Error: open_perf_buffer: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    if (debug) {
        show_process(h2o_pid);
    }
    if (!preserve_root) {
        drop_root_privilege();
    }

    ebpf::BPFPerfBuffer *perf_buffer = bpf->get_perf_buffer("events");
    if (perf_buffer) {
        time_t t0 = time(NULL);

        while (true) {
            perf_buffer->poll(POLL_TIMEOUT);
            tracer->flush();

            if (debug) {
                tracer->show_event_per_sec(&t0);
            }
        }
    }

    fprintf(stderr, "Error: failed to get_perf_buffer()\n");
    return EXIT_FAILURE;
}
