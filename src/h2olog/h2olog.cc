/*
 * Copyright (c) 2019-2021 Fastly, Inc., Toru Maesaka, Goro Fuji, Kazuho Oku
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
#include <bcc/libbpf.h>

extern "C" {
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "h2o/memory.h"
#include "h2o/version.h"
#include "h2o/ebpf.h"
}
#include "h2olog.h"

#define POLL_TIMEOUT (1000)
#define PERF_BUFFER_PAGE_COUNT 256

static void usage(void)
{
    printf(R"(h2olog (h2o v%s)
Usage: h2olog -p PID
Optional arguments:
  -d                Print debugging information (-dd shows more).
  -h                Print this help and exit.
  -l                Print the list of available tracepoints and exit.
  -H                Trace HTTP requests and responses in varnishlog-like format.
  -s <header-name>  A response header name to show, e.g. "content-type".
  -t <tracepoint>   A tracepoint, or fully-qualified probe name to trace. Glob
                    patterns can be used; e.g., "quicly:accept", "h2o:*".
  -S <rate>         Enable random sampling per connection (0.0-1.0). Requires
                    use of `usdt-selective-tracing`.
  -A <ip-address>   Limit connections being traced to those coming from the
                    specified address. Requries use of `usdt-selective-tracing`.
  -N <server-name>  Limit connections being traced to those carrying the
                    specified name in the TLS SNI extension. Requires use of
                    `usdt-selective-tracing: ON`.
  -a                Include application data which are omitted by default.
  -r                Run without dropping root privilege.
  -w <path>         Path to write the output (default: stdout).

Examples:
  h2olog -p $(pgrep -o h2o) -H
  h2olog -p $(pgrep -o h2o) -t quicly:accept -t quicly:free
  h2olog -p $(pgrep -o h2o) -t h2o:send_response_header -t h2o:h3s_accept \
         -t h2o:h3s_destroy -s alt-svc
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

/**
 * Builds a `-D$name=$expr` style cc macro.
 */
static std::string build_cc_macro_expr(const char *name, const std::string &expr)
{
    return std::string("-D") + std::string(name) + "=" + expr;
}

template <typename T> static std::string build_cc_macro_expr(const char *name, const T &expr)
{
    return build_cc_macro_expr(name, std::to_string(expr));
}

/**
 * Builds a `-D$name="$str"` style cc macro.
 */
static std::string build_cc_macro_str(const char *name, const std::string &str)
{
    return build_cc_macro_expr(name, "\"" + str + "\"");
}

#define CC_MACRO_EXPR(name) build_cc_macro_expr(#name, name)
#define CC_MACRO_STR(name) build_cc_macro_str(#name, name)

int main(int argc, char **argv)
{
    std::unique_ptr<h2o_tracer> tracer(create_raw_tracer());

    int debug = 0;
    bool preserve_root = false;
    bool list_usdts = false;
    bool include_appdata = false;
    FILE *outfp = stdout;
    std::vector<std::string> response_header_filters;
    int c;
    pid_t h2o_pid = -1;
    double sampling_rate = 1.0;
    std::vector<std::pair<std::vector<uint8_t> /* address */, unsigned /* netmask */>> sampling_addresses;
    std::vector<std::string> sampling_snis;
    while ((c = getopt(argc, argv, "hHdrlap:t:s:w:S:A:N:")) != -1) {
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
        case 'S': // can take 0.0 ... 1.0
            sampling_rate = atof(optarg);
            if (!(sampling_rate >= 0.0 && sampling_rate <= 1.0)) {
                fprintf(stderr, "Error: the argument of -S must be in the range of 0.0 to 1.0\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'A': {
            const char *slash = std::find(optarg, optarg + strlen(optarg), '/');
            std::string addr(optarg, slash - optarg);
            in_addr v4;
            in6_addr v6;
            if (inet_pton(AF_INET, addr.c_str(), (sockaddr *)&v4) == 1) {
                const uint8_t *src = reinterpret_cast<const uint8_t *>(&v4);
                sampling_addresses.emplace_back(std::vector<uint8_t>(src, src + 4), 32);
            } else if (inet_pton(AF_INET6, addr.c_str(), (sockaddr *)&v6) == 1) {
                const uint8_t *src = reinterpret_cast<const uint8_t *>(&v6);
                sampling_addresses.emplace_back(std::vector<uint8_t>(src, src + 16), 128);
            } else {
                fprintf(stderr, "Error: invalid address supplied to -A: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            if (*slash != '\0') {
                if (sscanf(slash + 1, "%u", &sampling_addresses.back().second) != 1) {
                    fprintf(stderr, "Error: invalid address mask supplied to -A: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
            }
        } break;
        case 'N':
            sampling_snis.emplace_back(optarg);
            break;
        case 'a':
            include_appdata = true;
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

    tracer->init(outfp, include_appdata);

    const char *h2o_root = getenv("H2O_ROOT");
    if (h2o_root == NULL)
        h2o_root = H2O_TO_STR(H2O_ROOT);
    // BCC does not resolve a relative path, so h2olog does resolve it as an absolute path.
    char h2o_root_resolved[PATH_MAX];
    if (realpath(h2o_root, h2o_root_resolved) == NULL) {
        h2o_perror("Error: realpath failed for H2O_ROOT");
        exit(EXIT_FAILURE);
    }
    std::vector<std::string> cflags({
        std::string("-I") + std::string(h2o_root_resolved) + "/include",
        build_cc_macro_expr("H2OLOG_H2O_PID", h2o_pid),
        CC_MACRO_EXPR(H2O_EBPF_RETURN_MAP_SIZE),
    });

    if (!response_header_filters.empty()) {
        cflags.push_back(generate_header_filter_cflag(response_header_filters));
    }

    ebpf::BPF *bpf = new ebpf::BPF();
    std::vector<ebpf::USDT> probes;

    bool selective_tracing = false;
    if (sampling_rate < 1.0) {
        /* eBPF bytecode cannot handle floating point numbers see man bpf(2). We use uint32_t which maps to 0 <= value < 1. */
        cflags.push_back(
            build_cc_macro_expr("H2OLOG_SAMPLING_RATE_U32", static_cast<uint32_t>(sampling_rate * (UINT64_C(1) << 32))));
        selective_tracing = true;
    }
    if (!sampling_addresses.empty()) {
        std::string expr;
        for (const auto &addrmask : sampling_addresses) {
            if (!expr.empty())
                expr += " || ";
            expr += "((family) == ";
            expr += addrmask.first.size() == 4 ? '4' : '6';
            size_t off;
            for (off = 0; off < addrmask.second / 8 * 8; off += 8) {
                expr += " && (addr)[";
                expr += std::to_string(off / 8);
                expr += "] == ";
                expr += std::to_string(addrmask.first[off / 8]);
            }
            if (addrmask.second % 8 != 0) {
                expr += " && ((addr)[";
                expr += std::to_string(off / 8);
                expr += "] & ";
                expr += std::to_string((uint8_t)(0xff << (8 - addrmask.second % 8)));
                expr += ") == ";
                expr += std::to_string(addrmask.first[off / 8]);
            }
            expr += ')';
        }
        cflags.push_back(build_cc_macro_expr("H2OLOG_IS_SAMPLING_ADDRESS(family, addr)", std::string("(") + expr + ")"));
        selective_tracing = true;
    }
    if (!sampling_snis.empty()) {
        /* if both address- and sni-based sampling are used, the output will be the union of both */
        if (sampling_addresses.empty())
            cflags.push_back(build_cc_macro_expr("H2OLOG_IS_SAMPLING_ADDRESS(family, addr)", 0));
        std::string expr;
        for (const auto &name : sampling_snis) {
            if (!expr.empty())
                expr += " || ";
            expr += "((name_len) == ";
            expr += std::to_string(name.size());
            /* as string constants cannot be used in eBPF, do hand-written memcmp */
            for (size_t i = 0; i < name.size(); i += 8) {
                uint64_t u8 = 0, mask = 0;
                memcpy(&u8, name.c_str() + i, std::min((size_t)8, name.size() - i));
                expr += " && (*(uint64_t *)((name) + ";
                expr += std::to_string(i);
                expr += ")";
                if (name.size() - i < 8) {
                    static const uint8_t mask_bytes[14] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; /* 7x 0xff, 7x 0x00 */
                    memcpy(&mask, mask_bytes + 7 - (name.size() - i), 8);
                    expr += " & ";
                    expr += std::to_string(mask);
                }
                expr += ") == ";
                expr += std::to_string(u8);
            }
            expr += ")";
        }
        cflags.push_back(build_cc_macro_expr("H2OLOG_IS_SAMPLING_SNI(name, name_len)", std::string("(") + expr + ")"));
        selective_tracing = true;
    }

    if (selective_tracing) {
        cflags.push_back(build_cc_macro_expr("H2OLOG_SELECTIVE_TRACING", 1));
        probes.push_back(ebpf::USDT(h2o_pid, "h2o", "_private_socket_lookup_flags", "trace_h2o___private_socket_lookup_flags"));
        probes.push_back(
            ebpf::USDT(h2o_pid, "h2o", "_private_socket_lookup_flags_sni", "trace_h2o___private_socket_lookup_flags_sni"));
    }

    for (const auto &usdt : tracer->usdt_probes()) {
        probes.push_back(ebpf::USDT(h2o_pid, usdt.provider, usdt.name, usdt.probe_func));
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
