#include "h2olog.h"
#include "json.h"

#include <cstdio>
#include <cstring>
#include <cinttypes>

extern "C" {
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "h2o/socket.h"
}

using namespace std;

#define FPUTS_LIT(s, out) fwrite(s, 1, strlen(s), out)

static bool json_need_escape(char c)
{
    return static_cast<unsigned char>(c) < 0x20 || c == 0x7f;
}

static void json_write_str_value(FILE *out, const char *str, size_t str_len)
{
    fputc('"', out);
    for (size_t i = 0; i < str_len; i++) {
        switch (str[i]) {
        case '\"':
            FPUTS_LIT("\\\"", out);
            break;
        case '\\':
            FPUTS_LIT("\\\\", out);
            break;
        case '\b':
            FPUTS_LIT("\\b", out);
            break;
        case '\f':
            FPUTS_LIT("\\f", out);
            break;
        case '\n':
            FPUTS_LIT("\\n", out);
            break;
        case '\r':
            FPUTS_LIT("\\r", out);
            break;
        case '\t':
            FPUTS_LIT("\\t", out);
            break;
        default:
            if (!json_need_escape(str[i])) {
                fputc(str[i], out);
            } else {
                auto u8 = static_cast<uint8_t>(str[i]);
                fprintf(out, "\\u%04x", u8);
            }
            break;
        }
    }
    fputc('"', out);
}

static void json_write_name_value(FILE *out, const char *name, size_t name_len)
{
    fputc('"', out);
    fwrite(name, 1, name_len, out);
    fputc('"', out);
    fputc(':', out);
}

void json_write_pair_n(FILE *out, const char *name, size_t name_len, const char *value, size_t value_len)
{
    json_write_name_value(out, name, name_len);
    json_write_str_value(out, value, value_len);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, const char *value, size_t value_len)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    json_write_str_value(out, value, value_len);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, const void *value, size_t len)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fputc('"', out);
    const uint8_t *bin = static_cast<const uint8_t *>(value);
    for (size_t i = 0; i < len; i++) {
        fputc("0123456789abcdef"[bin[i] >> 4], out);
        fputc("0123456789abcdef"[bin[i] & 0xf], out);
    }
    fputc('"', out);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, int32_t value)
{
    json_write_pair_c(out, name, name_len, static_cast<int64_t>(value));
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, uint32_t value)
{
    json_write_pair_c(out, name, name_len, static_cast<uint64_t>(value));
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, int64_t value)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fprintf(out, "%" PRId64, value);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, uint64_t value)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fprintf(out, "%" PRIu64, value);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, const quicly_address_t &value)
{
    const sockaddr *sa = &value.sa;
    fputc(',', out);

    json_write_name_value(out, name, name_len);

    char addr[NI_MAXHOST];
    size_t addr_len = h2o_socket_getnumerichost(sa, sizeof(quicly_address_t), addr);
    if (addr_len == SIZE_MAX) {
        fprintf(out, "null");
        return;
    }
    int32_t port = h2o_socket_getport(sa);

    fputc('"', out);

    if (sa->sa_family == AF_INET) {
        // e.g. "1.2.3.4:12345"
        fwrite(addr, 1, addr_len, out);
    } else if (sa->sa_family == AF_INET6) {
        // e.g. "[2001:0db8:85a3::8a2e:0370:7334]:12345"
        fputc('[', out);
        fwrite(addr, 1, addr_len, out);
        fputc(']', out);
    }
    fputc(':', out);
    fprintf(out, "%" PRId32, port);

    fputc('"', out);
}

void json_write_pair_c(FILE *out, const char *name, size_t name_len, const void *value)
{
    fputc(',', out);
    json_write_name_value(out, name, name_len);
    fprintf(out, "%" PRIu64, (uint64_t)value);
}
