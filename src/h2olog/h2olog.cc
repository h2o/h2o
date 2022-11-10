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
#include <bcc/bpf_module.h>

extern "C" {
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "h2o.h"
#include "h2o/version.h"
}
#include "h2olog.h"

#define PICOJSON_USE_INT64 1
#include "picojson.h"

#define POLL_TIMEOUT (1000)
#define PERF_BUFFER_PAGE_COUNT 256

static void usage(void)
{
    printf(R"(h2olog (h2o v%s)
Usage: h2olog -u <h2olog-socket-path>
       where <h2olog-socket-path> is specified in the h2o configuration file.

Optional arguments:
  -d                Print debugging information (-dd shows more).
  -h                Print this help and exit.
  -H                Trace HTTP requests and responses in varnishlog-like format.
  -s <header-name>  A response header name to show, e.g. "content-type".
  -t <tracepoint>   A tracepoint, or fully-qualified probe name to trace. Glob
                    patterns can be used; e.g., "quicly:accept", "h2o:*".
  -S <rate>         Enable random sampling per connection in 0 < N <= UINT32_MAX.
  -A <ip-address>   Limit connections being traced to those coming from the
                    specified address. <ip-address> can have a netmask.
  -N <server-name>  Limit connections being traced to those carrying the
                    specified name in the TLS SNI extension.
  -a                Include application data which are omitted by default.
  -r                Run without dropping root privilege.
  -w <path>         Path to write the output (default: stdout).
  -u <unix-socket>  Path to the unix socket to connect to. Experimental.

Examples:
  h2olog -u $H2OLOG_SOCK -H
  h2olog -u $H2OLOG_SOCK -t quicly:accept -t quicly:free
  h2olog -u $H2OLOG_SOCK -t h2o:send_response_header -t h2o:h3s_accept \
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

static bool is_json_whitespace(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static void http_tracer_transform_logs(FILE *outfp, const char *buf, size_t len)
{
    // ptlslog could write only a part of a JSON line, but won't retry to write the rest. In that case, this function does not parse
    // a broken JSON line.

    auto cur = buf;
    auto end = buf + len;
    while (cur != end) {
        picojson::value ev;
        std::string err;

        cur = picojson::parse(ev, cur, end, &err);

        if (err.empty()) {
            if (ev.get("module") == picojson::value("h2o")) {
                if (ev.get("type") == picojson::value("receive_request")) {
                    fprintf(outfp, "%" PRIu64 " %" PRIu64 " RxProtocol HTTP/%" PRIu64 ".%" PRIu64 "\n",
                            ev.get("conn_id").get<int64_t>(), ev.get("req_id").get<int64_t>(),
                            ev.get("http_version").get<int64_t>() / 256, ev.get("http_version").get<int64_t>() % 256);
                } else if (ev.get("type") == picojson::value("receive_request_header")) {
                    if (ev.get("name").is<picojson::null>()) {
                        infof("Error: no appdata is provided in the log (%s). Turns on it by `h2olog: appdata` in the h2o "
                              "configuration file.",
                              ev.serialize().c_str());
                        exit(1);
                    }

                    fprintf(outfp, "%" PRIu64 " %" PRIu64 " RxHeader   %s %s\n", ev.get("conn_id").get<int64_t>(),
                            ev.get("req_id").get<int64_t>(), ev.get("name").get<std::string>().c_str(),
                            ev.get("value").get<std::string>().c_str());
                } else if (ev.get("type") == picojson::value("send_response")) {
                    fprintf(outfp, "%" PRIu64 " %" PRIu64 " TxStatus   %" PRIu64 "\n", ev.get("conn_id").get<int64_t>(),
                            ev.get("req_id").get<int64_t>(), ev.get("status").get<int64_t>());
                } else if (ev.get("type") == picojson::value("send_response_header")) {
                    fprintf(outfp, "%" PRIu64 " %" PRIu64 " TxHeader   %s %s\n", ev.get("conn_id").get<int64_t>(),
                            ev.get("req_id").get<int64_t>(), ev.get("name").get<std::string>().c_str(),
                            ev.get("value").get<std::string>().c_str());
                }
            }
        } else {
            infof("Warn: failed to parse JSON: %s", err.c_str());
        }

        while (is_json_whitespace(*cur))
            cur++;
    }
}

static void do_write(FILE *outfp, const char *buf, size_t len, bool trace_http)
{
    if (trace_http) {
        http_tracer_transform_logs(outfp, buf, len);
    } else {
        fwrite(buf, 1, len, outfp);
    }
}

struct sampling_address_t {
    std::string input;
    std::vector<uint8_t> address;
    unsigned netmask;
};

static int read_from_unix_socket(const char *unix_socket_path, FILE *outfp, bool debug, bool preserve_root, bool trace_http,
                                 uint32_t sampling_rate, std::vector<sampling_address_t> sampling_addresses,
                                 std::vector<std::string> sampling_snis)
{
    struct sockaddr_un sa = {
        .sun_family = AF_UNIX,
    };
    if (strlen(unix_socket_path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "'%s' is too long as the name of a unix domain socket.\n", unix_socket_path);
        return EXIT_FAILURE;
    }
    strcpy(sa.sun_path, unix_socket_path);

    int fd;
    int ret = EXIT_FAILURE;
    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("failed to create a socket");
        goto Exit;
    }
    if (connect(fd, (const struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("failed to connect to the socket");
        goto Exit;
    }

    setvbuf(outfp, NULL, _IOLBF, 0);

    if (!preserve_root)
        drop_root_privilege();

    {

        std::string req = "GET " H2O_LOG_ENDPOINT "?";

        if (sampling_rate != 0)
            req += "sampling_rate=" + std::to_string(sampling_rate);

        if (!sampling_addresses.empty()) {
            for (const auto &item : sampling_addresses) {
                if (req[req.size() - 1] != '?')
                    req += "&";

                req += "sampling_address=" + item.input;
            }
        }

        if (!sampling_snis.empty()) {
            for (const auto &item : sampling_snis) {
                if (req[req.size() - 1] != '?')
                    req += "&";

                req += "sampling_sni=" + item;
            }
        }

        req += " HTTP/1.0\r\n"
               "h2olog: 1\r\n"
               "\r\n";
        (void)write(fd, req.c_str(), req.size());
    }

    if (debug)
        infof("Attaching %s", unix_socket_path);

    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        bool headers_done = false;
        while (select(fd + 1, &fds, NULL, NULL, NULL) > 0) {
            char buf[4096];
            ssize_t ret = read(fd, buf, sizeof(buf));
            if (ret == -1) {
                if (ret != EINTR)
                    break;
            } else if (ret > 0) {
                if (!headers_done) {
                    // h2olog is not interested in the response headers.
                    static const h2o_iovec_t h_sep = h2o_iovec_init(H2O_STRLIT("\r\n\r\n"));
                    size_t headers_done_at;
                    if (((headers_done_at = h2o_strstr(buf, ret, h_sep.base, h_sep.len)) != SIZE_MAX)) {
                        headers_done = true;

                        const char *content = buf + headers_done_at + h_sep.len;
                        size_t len = ret - headers_done_at - h_sep.len;
                        if (len > 0)
                            do_write(outfp, content, len, trace_http);
                    }
                    continue;
                }
                do_write(outfp, buf, ret, trace_http);
            } else {
                if (debug)
                    infof("Connection closed\n");
                // disconnected
                break;
            }
        }
    }

    ret = EXIT_SUCCESS;
Exit:
    if (fd != -1)
        close(fd);

    return ret;
}

#define CC_MACRO_EXPR(name) build_cc_macro_expr(#name, name)
#define CC_MACRO_STR(name) build_cc_macro_str(#name, name)

int main(int argc, char **argv)
{
    std::unique_ptr<h2o_tracer> tracer(create_raw_tracer());

    int debug = 0;
    unsigned int bcc_flags = 0;
    bool preserve_root = false;
    bool list_usdts = false;
    bool include_appdata = false;
    bool trace_http = false;
    FILE *outfp = stdout;
    std::vector<std::string> response_header_filters;
    int c;
    pid_t h2o_pid = -1;
    uint32_t sampling_rate = 0; // e.g. 1 for no-sampling, 100 for 1/100.
    std::vector<sampling_address_t> sampling_addresses;
    std::vector<std::string> sampling_snis;
    const char *unix_socket_path = NULL; // h2olog.path in h2o conf file
    while ((c = getopt(argc, argv, "hHdrlap:t:s:w:S:A:N:f:u:")) != -1) {
        switch (c) {
        case 'H':
            trace_http = true;
            break;
        case 'p':
            h2o_pid = atoi(optarg);
            fprintf(stderr, "-p <pid> is obsolete. Use -u <socket-path> instead.\n");
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
        case 'S': { // positive integer
            char *end;
            unsigned long v = strtoul(optarg, &end, 10);
            if ((optarg + strlen(optarg) != end) && !(0 < v && v <= UINT32_MAX)) {
                fprintf(stderr, "Error: the argument of -S must be a positive integer in the range of 0 < N <= UINT32_MAX\n");
                exit(EXIT_FAILURE);
            }
            sampling_rate = static_cast<uint32_t>(v);
            break;
        }
        case 'A': { // IPv4 or IPv6 with an optional netmask
            const char *slash = std::find(optarg, optarg + strlen(optarg), '/');
            std::string addr(optarg, slash - optarg);
            in_addr v4;
            in6_addr v6;
            if (inet_pton(AF_INET, addr.c_str(), (sockaddr *)&v4) == 1) {
                const uint8_t *src = reinterpret_cast<const uint8_t *>(&v4);
                sampling_addresses.emplace_back((sampling_address_t){
                    .input = optarg,
                    .address = std::vector<uint8_t>(src, src + 4),
                    .netmask = 32,
                });
            } else if (inet_pton(AF_INET6, addr.c_str(), (sockaddr *)&v6) == 1) {
                const uint8_t *src = reinterpret_cast<const uint8_t *>(&v6);
                sampling_addresses.emplace_back((sampling_address_t){
                    .input = optarg,
                    .address = std::vector<uint8_t>(src, src + 16),
                    .netmask = 128,
                });
            } else {
                fprintf(stderr, "Error: invalid address supplied to -A: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
            if (*slash != '\0') {
                if (sscanf(slash + 1, "%u", &sampling_addresses.back().netmask) != 1) {
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
            fprintf(stderr, "-a is not yet implemented. Set `h2olog: appdata` in the h2o config file instead.\n");
            break;
        case 'd':
            debug++;
            break;
        case 'f':
#define BCC_FLAG(var, flag)                                                                                                        \
    if (strcmp(optarg, #flag) == 0) {                                                                                              \
        var |= ebpf::flag;                                                                                                         \
    } else
            BCC_FLAG(bcc_flags, DEBUG_LLVM_IR)
            BCC_FLAG(bcc_flags, DEBUG_BPF)
            BCC_FLAG(bcc_flags, DEBUG_PREPROCESSOR)
            BCC_FLAG(bcc_flags, DEBUG_SOURCE)
            BCC_FLAG(bcc_flags, DEBUG_BPF_REGISTER_STATE)
            BCC_FLAG(bcc_flags, DEBUG_BTF)
            // else
            {
                fprintf(stderr, "Error: unknown name for -f: %s\n", optarg);
                exit(EXIT_FAILURE);
            }
#undef BCC_FLAG
            break;
        case 'l':
            list_usdts = true;
            break;
        case 'r':
            preserve_root = true;
            break;
        case 'u':
            unix_socket_path = optarg;
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

    if (unix_socket_path != NULL) {
        // TODO: the path might not be "/"
        return read_from_unix_socket(unix_socket_path, outfp, debug, preserve_root, trace_http, sampling_rate, sampling_addresses,
                                     sampling_snis);
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

    if (trace_http)
        tracer.reset(create_http_tracer());

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

    ebpf::BPF bpf(bcc_flags);
    std::vector<ebpf::USDT> probes;

    bool selective_tracing = false;
    if (sampling_rate != 0) {
        cflags.push_back(build_cc_macro_expr("H2OLOG_SAMPLING_RATE_U32", sampling_rate));
        selective_tracing = true;
    }
    if (!sampling_addresses.empty()) {
        std::string expr;
        for (const auto &addrmask : sampling_addresses) {
            if (!expr.empty())
                expr += " || ";
            expr += "((family) == ";
            expr += addrmask.address.size() == 4 ? '4' : '6';
            size_t off;
            for (off = 0; off < addrmask.netmask / 8 * 8; off += 8) {
                expr += " && (addr)[";
                expr += std::to_string(off / 8);
                expr += "] == ";
                expr += std::to_string(addrmask.address[off / 8]);
            }
            if (addrmask.netmask % 8 != 0) {
                expr += " && ((addr)[";
                expr += std::to_string(off / 8);
                expr += "] & ";
                expr += std::to_string((uint8_t)(0xff << (8 - addrmask.netmask % 8)));
                expr += ") == ";
                expr += std::to_string(addrmask.address[off / 8]);
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

    ebpf::StatusTuple ret = bpf.init(tracer->bpf_text(), cflags, probes);
    if (ret.code() != 0) {
        fprintf(stderr, "Error: init: %s\n", ret.msg().c_str());
        return EXIT_FAILURE;
    }

    bpf.attach_tracepoint("sched:sched_process_exit", "trace_sched_process_exit");

    for (auto &probe : probes) {
        ret = bpf.attach_usdt(probe);
        if (ret.code() != 0) {
            fprintf(stderr, "Error: attach_usdt: %s\n", ret.msg().c_str());
            return EXIT_FAILURE;
        }
    }

    ret = bpf.open_perf_buffer("events", event_cb, lost_cb, tracer.get(), PERF_BUFFER_PAGE_COUNT);
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

    ebpf::BPFPerfBuffer *perf_buffer = bpf.get_perf_buffer("events");
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
